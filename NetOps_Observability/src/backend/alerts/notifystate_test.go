package alerts

// notifystate_test.go — the RESTART defect (2026-09-03).
//
// Live evidence this is written against: the api restarted twice inside an hour
// (deploys) and each restart produced a burst of pages — CollectorDown ×6,
// CollectorAllTargetsUnreachable ×6, DeviceUnreachable ×2 — for conditions that
// had already been paged. The engine's "already notified" record was in memory
// only, so every restart made every still-firing alert look brand new.
//
// The contract asserted here, end to end:
//
//	fire → notified once → restart (a NEW engine over the SAME store) → still
//	firing → NO second notification → clears → resolve delivered exactly once.

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// notifyRig is one engine over a given store path, wired to a real Dispatcher
// so the notification decision is observed where it actually happens.
type notifyRig struct {
	e     *Engine
	ch    *fakeResolveChannel
	d     *notify.Dispatcher
	clock *fakeClock
	store *NotifyStateStore
}

func (r *notifyRig) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.ch.mu.Lock()
		ok := cond()
		r.ch.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	t.Fatalf("timed out waiting for %s (sent=%v resolved=%v)", what, r.ch.sent, r.ch.resolved)
}

// quiet asserts nothing further is delivered. It has to WAIT: "no notification"
// is only meaningful once the async delivery pool has had time to produce one.
func (r *notifyRig) quiet(t *testing.T, sent, resolved int) {
	t.Helper()
	time.Sleep(75 * time.Millisecond)
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	if len(r.ch.sent) != sent || len(r.ch.resolved) != resolved {
		t.Fatalf("want sent=%d resolved=%d, got sent=%v resolved=%v", sent, resolved, r.ch.sent, r.ch.resolved)
	}
}

// newNotifyRig starts an engine over the store at path, exactly as a fresh
// process would: load the file, seed the engine, evaluate.
func newNotifyRig(t *testing.T, path string, at time.Time, eval func(Rule) ([]Sample, error)) (*notifyRig, int) {
	t.Helper()
	st, err := NewNotifyStateStore(path)
	if err != nil {
		t.Fatalf("NewNotifyStateStore: %v", err)
	}
	clock := &fakeClock{t: at}
	st.SetNowForTest(clock.now)
	ch := &fakeResolveChannel{}
	d := notify.NewDispatcher()
	d.Register(ch)
	e := NewEngine("", d)
	e.now = clock.now
	e.evalFn = eval
	restored := e.SetNotifyState(st)
	return &notifyRig{e: e, ch: ch, d: d, clock: clock, store: st}, restored
}

// THE DEFECT, end to end.
func TestRestartDoesNotRenotifyAStillFiringAlert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_notify_state.json")
	t0 := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
	firing := true
	eval := func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"collector": "snmpv2c"}, Value: 0}}, nil
	}
	rule := Rule{Name: "CollectorAllTargetsUnreachable", Expr: "x == 0", For: 5 * time.Minute, Severity: "critical"}

	// ── process #1: the alert fires and is notified exactly once ────────────
	r1, restored := newNotifyRig(t, path, t0, eval)
	defer r1.d.Close()
	if restored != 0 {
		t.Fatalf("a first boot restored %d records from an empty store", restored)
	}
	r1.e.AddRule(rule)
	r1.e.evaluateAll() // pending — `for` has not elapsed
	r1.clock.advance(5 * time.Minute)
	r1.e.evaluateAll() // fires
	r1.waitFor(t, "the first notification", func() bool { return len(r1.ch.sent) == 1 })
	r1.e.evaluateAll() // steady — no re-send within one process (pre-existing)
	r1.quiet(t, 1, 0)

	// ── process #2: a NEW engine over the SAME store, still firing ──────────
	r2, restored := newNotifyRig(t, path, t0.Add(10*time.Minute), eval)
	defer r2.d.Close()
	if restored != 1 {
		t.Fatalf("restored %d records across the restart, want 1", restored)
	}
	r2.e.AddRule(rule)
	r2.e.evaluateAll()
	// THE ASSERTION: no second page, and no spurious resolve either — the
	// restored `for` clock must not drop the alert out of the active set.
	r2.quiet(t, 0, 0)
	if n := len(r2.e.Active()); n != 1 {
		t.Fatalf("active after restart = %d, want 1 — the alert is still firing", n)
	}

	// ── it clears: the resolve still goes out, exactly once ─────────────────
	firing = false
	r2.clock.advance(time.Minute)
	r2.e.evaluateAll()
	r2.waitFor(t, "the resolve after the restart", func() bool { return len(r2.ch.resolved) == 1 })
	r2.e.evaluateAll()
	r2.quiet(t, 0, 1)
	if got := r2.store.List(""); len(got) != 0 {
		t.Fatalf("the resolved alert was not forgotten: %+v", got)
	}

	// ── process #3: it fires AGAIN, and that is a genuinely new page ────────
	firing = true
	r3, restored := newNotifyRig(t, path, t0.Add(30*time.Minute), eval)
	defer r3.d.Close()
	if restored != 0 {
		t.Fatalf("restored %d records after the alert resolved, want 0", restored)
	}
	r3.e.AddRule(rule)
	r3.e.evaluateAll()
	r3.clock.advance(5 * time.Minute)
	r3.e.evaluateAll()
	r3.waitFor(t, "the re-fire to notify", func() bool { return len(r3.ch.sent) == 1 })
}

// An alert that CLEARED while the process was down must still produce its
// resolution — a restart may not swallow "it is over" any more than it may
// duplicate "it started".
func TestAlertThatClearedWhileDownResolvesOnceAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	t0 := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
	firing := true
	eval := func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "spine1"}, Value: 1}}, nil
	}
	rule := Rule{Name: "DeviceUnreachable", Expr: "x > 0", Severity: "critical"}

	r1, _ := newNotifyRig(t, path, t0, eval)
	defer r1.d.Close()
	r1.e.AddRule(rule)
	r1.e.evaluateAll()
	r1.waitFor(t, "the first notification", func() bool { return len(r1.ch.sent) == 1 })

	firing = false // it cleared while we were down
	r2, restored := newNotifyRig(t, path, t0.Add(time.Hour), eval)
	defer r2.d.Close()
	if restored != 1 {
		t.Fatalf("restored %d, want 1", restored)
	}
	r2.e.AddRule(rule)
	r2.e.evaluateAll()
	r2.waitFor(t, "the resolve", func() bool { return len(r2.ch.resolved) == 1 })
	r2.quiet(t, 0, 1)
}

// A SUPPRESSED firing (muted/snoozed episode, maintenance window) sent nothing,
// so it must record nothing — otherwise the first notification after the mute
// is lifted would be suppressed by a restart instead.
func TestSuppressedFiringIsNotRecordedAsNotified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	t0 := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
	eval := func(Rule) ([]Sample, error) {
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 1}}, nil
	}
	r, _ := newNotifyRig(t, path, t0, eval)
	defer r.d.Close()
	r.e.SuppressNotify = func(models.Alert) bool { return true }
	r.e.AddRule(Rule{Name: "LinkDown", Expr: "x > 0", Severity: "critical"})
	r.e.evaluateAll()
	r.quiet(t, 0, 0)
	if got := r.store.List(""); len(got) != 0 {
		t.Fatalf("a suppressed firing was recorded as notified: %+v", got)
	}
}

// The store is BOUNDED (§9): per-tenant cap, and an age-out so a rule deleted
// while firing cannot suppress its own name forever.
func TestNotifyStateIsBoundedAndAgesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	clock := &fakeClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	st, err := NewNotifyStateStore(path)
	if err != nil {
		t.Fatalf("NewNotifyStateStore: %v", err)
	}
	st.SetNowForTest(clock.now)

	for i := 0; i < notifyStateMaxPerTenant+50; i++ {
		clock.advance(time.Second)
		st.MarkNotified("acme", models.Alert{ID: "R|n=" + strconv.Itoa(i), Rule: "R"})
	}
	if got := len(st.List("acme")); got != notifyStateMaxPerTenant {
		t.Fatalf("per-tenant records = %d, want the cap %d", got, notifyStateMaxPerTenant)
	}
	// Oldest-first eviction: the earliest ids are the ones that went.
	if _, ok := st.Notified("acme", "R|n=0"); ok {
		t.Fatal("eviction did not drop the oldest record first")
	}
	if _, ok := st.Notified("acme", "R|n="+strconv.Itoa(notifyStateMaxPerTenant+49)); !ok {
		t.Fatal("eviction dropped the newest record")
	}

	// Age-out, through the flush sweep.
	st.SetMaxAgeForTest(time.Minute)
	clock.advance(2 * time.Minute)
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := len(st.List("acme")); got != 0 {
		t.Fatalf("records after the age-out = %d, want 0", got)
	}
}

// A still-firing alert is refreshed at most once per notifyStateRefreshEvery,
// so a chronic alert neither ages out nor rewrites the blob twice a minute.
func TestTouchIsRateLimitedButKeepsAChronicAlertAlive(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	st, err := NewNotifyStateStore("") // path "" = memory only, no writes
	if err != nil {
		t.Fatalf("NewNotifyStateStore: %v", err)
	}
	st.SetNowForTest(clock.now)
	st.MarkNotified("", models.Alert{ID: "a1", Rule: "Chronic"})
	first, _ := st.Notified("", "a1")

	clock.advance(30 * time.Second)
	st.Touch("", "a1")
	if got, _ := st.Notified("", "a1"); !got.LastSeen.Equal(first.LastSeen) {
		t.Fatal("Touch rewrote the record inside the refresh window")
	}
	clock.advance(notifyStateRefreshEvery)
	st.Touch("", "a1")
	got, _ := st.Notified("", "a1")
	if !got.LastSeen.After(first.LastSeen) {
		t.Fatal("Touch did not refresh the record past the window — a chronic alert would age out and re-page")
	}
	// Touching an id this tenant does not own is a no-op, not an insert.
	st.Touch("", "nope")
	if _, ok := st.Notified("", "nope"); ok {
		t.Fatal("Touch created a record for an unknown id")
	}
}

// A persist failure must never stop the alert loop; it is reported, and the
// dirty state is KEPT so the next flush retries rather than pretending the
// write happened.
func TestFlushFailureKeepsTheStateDirty(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	st, err := NewNotifyStateStore(filepath.Join(blocker, "state.json"))
	if err != nil {
		t.Fatalf("NewNotifyStateStore: %v", err) // absent = empty, not a fault
	}
	// Now make the record's PARENT a file, so the atomic write cannot create it.
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	st.MarkNotified("", models.Alert{ID: "a1", Rule: "R"})
	if err := st.Flush(); err == nil {
		t.Fatal("a write into a non-directory must fail loudly")
	}
	st.mu.Lock()
	dirty := st.dirty
	st.mu.Unlock()
	if !dirty {
		t.Fatal("a failed flush marked the state clean — the record would be lost silently")
	}
	// The engine keeps running: the record is still readable in memory.
	if _, ok := st.Notified("", "a1"); !ok {
		t.Fatal("a failed flush dropped the in-memory record")
	}
}
