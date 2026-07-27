package main

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// session_store_concurrency_test.go — CONC-HIGH-1.
//
// The defect: sessionStore used one plain Mutex and held it across the ENTIRE
// durable write (marshal + os.WriteFile/os.Rename, or with STORE_BACKEND=postgres
// a DELETE + N INSERTs bounded only by a 15 s context). IsActive — which withAuth
// calls on EVERY authenticated request — took that same exclusive lock. So a
// single logout on a slow disk or against a stalled Postgres froze the whole API,
// for every tenant, for as long as the write took.
//
// Every happy-path session test stayed green through that defect, because none of
// them ever had a write in flight while a read was attempted. These do.
//
// The backend is a process-wide var, so nothing in this file may run in parallel.

// blockingKV is a kvBackend whose Save can be held open for as long as the test
// wants — the fault-injection shape a "slow disk / stalled Postgres" needs, as
// opposed to faultyKV (settings_persist_failure_test.go), which models a write
// that FAILS rather than one that HANGS.
type blockingKV struct {
	mu      sync.Mutex
	blobs   map[string][]byte
	saves   int
	written [][]byte      // every payload, in the order it landed
	gate    chan struct{} // nil = writes pass straight through
	entered chan struct{} // one token per Save that has begun
	delay   time.Duration // artificial write latency, to widen interleavings
}

func newBlockingKV() *blockingKV {
	return &blockingKV{blobs: map[string][]byte{}, entered: make(chan struct{}, 256)}
}

func (k *blockingKV) Load(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.blobs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (k *blockingKV) Save(key string, data []byte) error {
	select {
	case k.entered <- struct{}{}:
	default: // the test is not watching; never block the writer on bookkeeping
	}
	k.mu.Lock()
	gate, delay := k.gate, k.delay
	k.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.saves++
	blob := append([]byte(nil), data...)
	k.blobs[key] = blob
	k.written = append(k.written, blob)
	return nil
}

// block holds every subsequent Save open until unblock.
func (k *blockingKV) block() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.gate == nil {
		k.gate = make(chan struct{})
	}
}

// unblock releases a held Save. Idempotent, so it is safe as a t.Cleanup: a test
// that fails while a write is parked must not leave the binary deadlocked.
func (k *blockingKV) unblock() {
	k.mu.Lock()
	g := k.gate
	k.gate = nil
	k.mu.Unlock()
	if g != nil {
		close(g)
	}
}

func (k *blockingKV) saveCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.saves
}

func (k *blockingKV) payloads() [][]byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([][]byte(nil), k.written...)
}

// drainEntered discards Save-entry tokens from earlier setup writes.
func (k *blockingKV) drainEntered() {
	for {
		select {
		case <-k.entered:
		default:
			return
		}
	}
}

// waitEntered blocks until a Save has begun, or fails the test.
func (k *blockingKV) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-k.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no durable write ever started — the test is not exercising the persist path")
	}
}

// newKVSessionStore builds a session store over the given backend.
func newKVSessionStore(t *testing.T, b kvBackend) *sessionStore {
	t.Helper()
	withBackend(t, b)
	st, err := newSessionStore("kv://sessions")
	if err != nil {
		t.Fatalf("newSessionStore: %v", err)
	}
	return st
}

// rewindSession backdates a session's timestamps to simulate elapsed time
// (white-box, same package — server time only, no client clock involved).
func rewindSession(st *sessionStore, id string, lastActivity, created time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	x := st.byID[id]
	if !lastActivity.IsZero() {
		x.LastActivityAt = lastActivity
	}
	if !created.IsZero() {
		x.CreatedAt = created
	}
	st.byID[id] = x
}

// storeSeq reads the mutation counter (white-box) — used to wait deterministically
// for a set of in-memory mutations to have landed.
func storeSeq(st *sessionStore) uint64 {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.seq
}

func decodeSessions(t *testing.T, b []byte) []Session {
	t.Helper()
	var list []Session
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("persisted blob is not a session list: %v", err)
	}
	return list
}

func countRevoked(list []Session) int {
	n := 0
	for _, x := range list {
		if x.Status == sessionRevoked {
			n++
		}
	}
	return n
}

// TestIsActiveIsNotBlockedByASlowPersist is THE regression test for CONC-HIGH-1:
// with a durable write parked in the backend, the per-request read path must
// still answer immediately. Before the fix this blocked for the full duration of
// the write (up to 15 s against Postgres) and took the entire API down with it.
func TestIsActiveIsNotBlockedByASlowPersist(t *testing.T) {
	kv := newBlockingKV()
	st := newKVSessionStore(t, kv)
	t.Cleanup(kv.unblock)

	victim, _, err := st.Create("alice", "10.0.0.1", "ua", time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	bystander, _, err := st.Create("bob", "10.0.0.2", "ua", time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	kv.drainEntered()

	// Park the next durable write, then revoke.
	kv.block()
	revoked := make(chan error, 1)
	go func() {
		_, e := st.Revoke(victim.ID)
		revoked <- e
	}()
	kv.waitEntered(t) // the write is now in flight; the in-memory flip has happened

	// Every read surface must answer promptly while that write is stuck.
	type readResult struct {
		victimActive    bool
		bystanderActive bool
		gotBystander    bool
		listed          int
	}
	res := make(chan readResult, 1)
	go func() {
		var r readResult
		r.victimActive = st.IsActive(victim.ID)
		r.bystanderActive = st.IsActive(bystander.ID)
		_, r.gotBystander = st.Get(bystander.ID)
		r.listed = len(st.List())
		res <- r
	}()

	var got readResult
	select {
	case got = <-res:
	case <-time.After(3 * time.Second):
		kv.unblock()
		t.Fatal("CONC-HIGH-1: the read path blocked behind an in-flight durable write — " +
			"withAuth calls IsActive on every authenticated request, so this is a process-wide API freeze")
	}

	// ...and the answers must be correct, not merely prompt. Revocation is still
	// instant: the in-memory flip is visible before the write lands (auth.go
	// re-checks per request and relies on exactly this).
	if got.victimActive {
		t.Error("revoked session still reported active — revocation must be instant, not write-gated")
	}
	if !got.bystanderActive || !got.gotBystander {
		t.Error("an unrelated session became invisible while another session's write was in flight")
	}
	if got.listed != 2 {
		t.Errorf("List() returned %d sessions during an in-flight write, want 2", got.listed)
	}

	kv.unblock()
	select {
	case err := <-revoked:
		if err != nil {
			t.Fatalf("Revoke: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Revoke never completed after the backend was released")
	}

	// The revocation is durable once Revoke returned nil (the F-70 contract).
	blob, err := kv.Load("kv://sessions")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, x := range decodeSessions(t, blob) {
		if x.ID == victim.ID && x.Status != sessionRevoked {
			t.Errorf("Revoke returned nil but the persisted status is %q", x.Status)
		}
	}
}

// TestConcurrentSessionMutationsNeverPersistStaleState proves the ordering
// argument: concurrent flushes may not write out-of-order state, and no mutation
// may be lost. Revocation is monotonic, so the count of revoked sessions in each
// successive payload the backend receives must never decrease — a stale snapshot
// landing after a newer one would show up as a drop.
func TestConcurrentSessionMutationsNeverPersistStaleState(t *testing.T) {
	kv := newBlockingKV()
	kv.delay = 300 * time.Microsecond // widen the window for interleaving
	st := newKVSessionStore(t, kv)

	const n = 40
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		// Distinct users, so the per-user concurrent cap never evicts anything.
		sess, _, err := st.Create("user-"+string(rune('a'+i%26))+string(rune('0'+i/26)), "10.0.0.1", "ua",
			time.Hour, 12*time.Hour)
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		ids = append(ids, sess.ID)
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			if _, err := st.Revoke(id); err != nil {
				errs <- err
			}
		}(id)
	}
	// Hammer the read path throughout, so a lock inversion or a read-under-write
	// deadlock shows up here (and, under -race, so does any unsynchronized access).
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					for _, id := range ids {
						st.IsActive(id)
					}
					st.List()
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(stop)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Revoke: %v", err)
	}

	// 1. No lost update: every revocation is in memory AND in the final blob.
	for _, id := range ids {
		if st.IsActive(id) {
			t.Fatalf("session %s is still active in memory after Revoke returned", id)
		}
	}
	blob, err := kv.Load("kv://sessions")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	final := decodeSessions(t, blob)
	if len(final) != n {
		t.Fatalf("persisted %d sessions, want %d", len(final), n)
	}
	if got := countRevoked(final); got != n {
		t.Fatalf("lost update: %d of %d revocations reached the store", got, n)
	}

	// 2. No out-of-order write: revoked-count is monotonic in the true state, so
	//    it must be monotonic in the order payloads landed.
	prev := 0
	for i, p := range kv.payloads() {
		got := countRevoked(decodeSessions(t, p))
		if got < prev {
			t.Fatalf("write %d persisted STALE state: %d revoked after a snapshot with %d — "+
				"a later mutation's snapshot was overtaken by an earlier one", i, got, prev)
		}
		prev = got
	}
}

// TestConcurrentPersistsCoalesce documents the write-amplification answer to
// "does Touch need to flush every time": mutations that pile up behind one slow
// write collapse into a single extra write, with no loss window (each caller
// still returns only once its own state is durable).
func TestConcurrentPersistsCoalesce(t *testing.T) {
	kv := newBlockingKV()
	st := newKVSessionStore(t, kv)
	t.Cleanup(kv.unblock)

	const n = 20
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		sess, _, err := st.Create("u"+string(rune('a'+i)), "10.0.0.1", "ua", time.Hour, 12*time.Hour)
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		ids = append(ids, sess.ID)
	}
	kv.drainEntered()
	base := kv.saveCount()
	baseSeq := storeSeq(st)

	kv.block()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			st.Touch(id)
		}(id)
	}
	kv.waitEntered(t)
	// Deterministic barrier: wait until every in-memory mutation has landed, so
	// all n goroutines are inside persist or queued on flushMu.
	deadline := time.Now().Add(5 * time.Second)
	for storeSeq(st) < baseSeq+n {
		if time.Now().After(deadline) {
			kv.unblock()
			t.Fatal("touches never completed their in-memory phase")
		}
		time.Sleep(time.Millisecond)
	}
	kv.unblock()
	wg.Wait()

	if got := kv.saveCount() - base; got > 2 {
		t.Errorf("%d durable writes for %d coalescible touches, want <= 2", got, n)
	}
	// And nothing was lost: the last write carries every touch.
	blob, err := kv.Load("kv://sessions")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, x := range decodeSessions(t, blob) {
		if x.LastRefreshAt.Equal(x.CreatedAt) {
			t.Errorf("session %s persisted without its touch — coalescing must not drop state", x.ID)
		}
	}
}

// TestSessionMutatorsStillReportPersistFailure is the F-70 regression guard:
// moving the flush out of the lock must not turn a reported error into a
// fire-and-forget. Create must additionally roll back.
func TestSessionMutatorsStillReportPersistFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := newSessionStore(dir + "/sessions.json")
	if err != nil {
		t.Fatalf("newSessionStore: %v", err)
	}
	live, _, err := st.Create("alice", "10.0.0.1", "ua", time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	other, _, err := st.Create("carol", "10.0.0.3", "ua", time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	f := withFailingKV(t)

	// Create: reports the failure AND rolls the session back out of memory, so
	// the process never serves a session the store does not have.
	before := f.attempts()
	ghost, _, err := st.Create("bob", "10.0.0.2", "ua", time.Hour, 12*time.Hour)
	if err == nil {
		t.Fatal("Create reported success while the store was broken (F-70 regression)")
	}
	if f.attempts() == before {
		t.Fatal("Create never attempted a save — the test is not exercising the persist path")
	}
	if ghost.ID != "" {
		t.Errorf("Create returned a session %+v alongside its error", ghost)
	}
	for _, x := range st.List() {
		if x.UserID == "bob" {
			t.Error("failed Create left the session applied in memory — no rollback")
		}
	}

	// Revoke: reported (revoked=true, err!=nil) — the status flipped in memory but
	// did not reach the store, which is exactly what the caller must be told.
	killed, err := st.Revoke(live.ID)
	if !killed {
		t.Error("Revoke did not report killing an active session")
	}
	if err == nil {
		t.Fatal("Revoke reported success while the store was broken (F-70 regression)")
	}

	// RevokeAllForUser: same contract.
	n, err := st.RevokeAllForUser("carol")
	if n != 1 {
		t.Errorf("RevokeAllForUser revoked %d, want 1", n)
	}
	if err == nil {
		t.Fatal("RevokeAllForUser reported success while the store was broken")
	}
	if st.IsActive(other.ID) {
		t.Error("RevokeAllForUser reported n=1 but the session is still active in memory")
	}

	// Idempotent no-op stays a benign (false, nil): a broken store must not turn
	// "already dead" into an error.
	if killed, err := st.Revoke(live.ID); killed || err != nil {
		t.Errorf("second Revoke = (%v, %v), want (false, nil)", killed, err)
	}
	if killed, err := st.Revoke("no-such-session"); killed || err != nil {
		t.Errorf("Revoke(unknown) = (%v, %v), want (false, nil)", killed, err)
	}
}

// TestSessionExpirySemanticsUnchanged pins the externally visible lifecycle
// behaviour across the locking change: idle and absolute windows, the enforce
// flags, absolute taking precedence, and terminal statuses being sticky.
func TestSessionExpirySemanticsUnchanged(t *testing.T) {
	kv := newBlockingKV()
	st := newKVSessionStore(t, kv)

	mk := func(user string) Session {
		t.Helper()
		s, _, err := st.Create(user, "10.0.0.1", "ua", 30*time.Minute, 12*time.Hour)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return s
	}

	// Fresh session: valid.
	fresh := mk("fresh")
	if _, err := st.Validate(fresh.ID, true, true); err != nil {
		t.Errorf("fresh session: %v, want nil", err)
	}

	// Idle: last activity beyond the window.
	idle := mk("idle")
	rewindSession(st, idle.ID, time.Now().UTC().Add(-31*time.Minute), time.Time{})
	if _, err := st.Validate(idle.ID, true, true); !errors.Is(err, errSessionIdle) {
		t.Errorf("idle session: %v, want errSessionIdle", err)
	}
	if sessionErrorCode(errSessionIdle) != "SESSION_IDLE_TIMEOUT" {
		t.Error("idle error code changed")
	}
	// The flip is sticky and now terminal.
	if _, err := st.Validate(idle.ID, true, true); !errors.Is(err, errSessionIdle) {
		t.Errorf("idle re-validate: %v, want errSessionIdle", err)
	}
	if st.IsActive(idle.ID) {
		t.Error("idle-expired session still reports active")
	}

	// Absolute: created beyond the cap, and it wins over idle when both apply.
	abs := mk("abs")
	rewindSession(st, abs.ID, time.Now().UTC().Add(-31*time.Minute), time.Now().UTC().Add(-13*time.Hour))
	if _, err := st.Validate(abs.ID, true, true); !errors.Is(err, errSessionAbsolute) {
		t.Errorf("absolute session: %v, want errSessionAbsolute (absolute is checked first)", err)
	}

	// The enforce flags still gate each window independently.
	off := mk("off")
	rewindSession(st, off.ID, time.Now().UTC().Add(-31*time.Minute), time.Now().UTC().Add(-13*time.Hour))
	if _, err := st.Validate(off.ID, false, false); err != nil {
		t.Errorf("both windows disabled: %v, want nil", err)
	}
	if _, err := st.Validate(off.ID, true, false); !errors.Is(err, errSessionIdle) {
		t.Errorf("idle-only enforcement: %v, want errSessionIdle", err)
	}

	// Unknown and revoked ids keep their typed errors.
	if _, err := st.Validate("nope", true, true); !errors.Is(err, errSessionNotFound) {
		t.Errorf("unknown session: %v, want errSessionNotFound", err)
	}
	rev := mk("rev")
	if _, err := st.Revoke(rev.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := st.Validate(rev.ID, true, true); !errors.Is(err, errSessionRevoked) {
		t.Errorf("revoked session: %v, want errSessionRevoked", err)
	}

	// An expiry that DID persist survives a reload.
	st2, err := newSessionStore("kv://sessions")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if st2.IsActive(idle.ID) {
		t.Error("idle expiry did not survive a reload")
	}
}

// TestSessionExpiryIsBestEffortButNeverSilent: when the store is broken, an
// expiry still flips in memory and still returns its typed error. It is not
// reported as an error because the verdict is DERIVED from durable timestamps —
// a restart recomputes it identically — unlike a revocation, which exists
// nowhere else and therefore must be reported (F-70).
func TestSessionExpiryIsBestEffortButNeverSilent(t *testing.T) {
	dir := t.TempDir()
	st, err := newSessionStore(dir + "/sessions.json")
	if err != nil {
		t.Fatalf("newSessionStore: %v", err)
	}
	sess, _, err := st.Create("alice", "10.0.0.1", "ua", 30*time.Minute, 12*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rewindSession(st, sess.ID, time.Now().UTC().Add(-31*time.Minute), time.Time{})
	// Make the backdated timestamps DURABLE (any successful write flushes the
	// whole set) — the recomputation argument rests on them being on disk.
	if _, _, err := st.Create("bystander", "10.0.0.9", "ua", 30*time.Minute, 12*time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}

	f := withFailingKV(t)
	before := f.attempts()
	if _, err := st.Validate(sess.ID, true, true); !errors.Is(err, errSessionIdle) {
		t.Fatalf("Validate with a broken store: %v, want errSessionIdle", err)
	}
	if f.attempts() == before {
		t.Fatal("expiry never attempted a save")
	}
	if st.IsActive(sess.ID) {
		t.Error("expiry did not take effect in memory when the store was broken")
	}
	// Touch is best-effort for the same reason and must not panic or block.
	st.Touch(sess.ID)

	// The recomputation argument: reload from the last DURABLE state (the write
	// never landed, so the session is active again there) and confirm the very
	// next Validate reaches the identical verdict from the timestamps alone.
	withBackend(t, fileKV{})
	st2, err := newSessionStore(dir + "/sessions.json")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	reloaded, ok := st2.Get(sess.ID)
	if !ok {
		t.Fatal("session missing after reload")
	}
	if reloaded.Status != sessionActive {
		t.Fatalf("precondition: the failed expiry write should NOT be on disk, got %q", reloaded.Status)
	}
	if _, err := st2.Validate(sess.ID, true, true); !errors.Is(err, errSessionIdle) {
		t.Errorf("reloaded session: %v, want errSessionIdle — expiry must be recomputable", err)
	}
}
