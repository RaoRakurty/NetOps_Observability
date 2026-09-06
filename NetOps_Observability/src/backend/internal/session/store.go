// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package session

// session_store.go — server-side sessions: the source of truth for a login's
// LIFECYCLE (idle timeout, absolute timeout, revocation), separate from the two
// tokens (FAANG-style separation of concerns):
//
//   - access JWT  → stateless authorization proof (short-lived; carries `sid`)
//   - refresh tok → rotation + proof of possession (opaque, hashed; maps to sid)
//   - Session     → authoritative lifecycle state (THIS file)
//
// Idle/absolute are enforced ONLY at /api/auth/refresh, against this record — the
// refresh boundary is the activity signal; we deliberately do NOT stamp every API
// call (avoids write amplification). Server time only (no client clock trust).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

// Session lifecycle states.
const (
	StatusActive          = "active"
	StatusRevoked         = "revoked"
	StatusExpiredIdle     = "expired_idle"
	StatusExpiredAbsolute = "expired_absolute"

	MaxSessionsPerUser = 5 // enterprise-safe concurrent cap; oldest evicted past it
)

// Typed validation errors → mapped to machine-readable codes for the SPA.
var (
	ErrNotFound = errors.New("session not found")
	ErrRevoked  = errors.New("session revoked")
	ErrIdle     = errors.New("session idle timeout")
	ErrAbsolute = errors.New("session absolute timeout")
)

// Session is one login's authoritative lifecycle record.
type Session struct {
	ID                 string    `json:"id"`
	UserID             string    `json:"user_id"`
	CreatedAt          time.Time `json:"created_at"`
	LastActivityAt     time.Time `json:"last_activity_at"`
	LastRefreshAt      time.Time `json:"last_refresh_at"`
	IssuedIP           string    `json:"issued_ip,omitempty"`
	UserAgentHash      string    `json:"user_agent_hash,omitempty"`
	Status             string    `json:"status"`
	IdleTimeoutSec     int       `json:"idle_timeout_sec"`
	AbsoluteTimeoutSec int       `json:"absolute_timeout_sec"`
}

// KV abstracts where the store persists its JSON blob. The integrator supplies
// the platform kv layer (file or postgres); the package deliberately does not
// know which. A missing key must return an os.ErrNotExist-wrapped error.
type KV interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// Errorf is the structured error-log sink the store reports persistence
// failures through (no silent failures; the package does not pick a logger).
type Errorf func(component, msg string, fields map[string]any)

// Store holds the live session set in memory and mirrors it to the kv
// backend. Two locks, deliberately:
//
//   - mu (RWMutex) guards byID + seq and is NEVER held across IO. The hot path
//     is IsActive, which withAuth calls on EVERY authenticated request; it takes
//     a read lock, so per-request checks do not serialize against each other.
//   - flushMu makes persistence single-writer. Snapshot AND kv.Save happen inside
//     it, so durable writes land in flushMu order (see persist for the ordering
//     argument).
//
// CONC-HIGH-1: mu used to be a plain Mutex held across the whole flush —
// marshal + os.WriteFile/os.Rename, or with STORE_BACKEND=postgres a
// DELETE + N INSERTs bounded only by a 15 s context. One slow disk or a stalled
// Postgres therefore froze IsActive, and with it every authenticated request of
// every tenant, for up to 15 s. Durable writes now happen outside mu entirely.
type Store struct {
	mu   sync.RWMutex
	path string
	kv   KV
	errf Errorf
	byID map[string]Session
	// seq is a monotonic mutation counter, bumped under mu.Lock together with
	// the mutation itself. A snapshot taken at version V provably contains every
	// mutation numbered <= V; that is what makes out-of-order writes detectable
	// and the coalescing fast path in persist safe.
	seq uint64

	flushMu sync.Mutex
	// flushedSeq is the highest version already durably written. Guarded by
	// flushMu (only ever read/written inside persist's critical section).
	flushedSeq uint64
}

func NewStore(path string, kv KV, errf Errorf) (*Store, error) {
	if path == "" {
		path = "/data/sessions.json"
	}
	if kv == nil || errf == nil {
		return nil, errors.New("session.NewStore: kv and errf are required")
	}
	s := &Store{path: path, kv: kv, errf: errf, byID: map[string]Session{}}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := s.kv.Load(s.path)
	if err != nil {
		return err
	}
	var list []Session
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, x := range list {
		s.byID[x.ID] = x
	}
	return nil
}

// bumpLocked stamps a mutation with the next version. Caller holds mu for write.
func (s *Store) bumpLocked() uint64 {
	s.seq++
	return s.seq
}

// persist durably writes the current session set. Callers MUST have released mu
// first: the whole point is that no reader (IsActive) and no other mutator waits
// on the backend's IO.
//
// `want` is the version the caller needs to see on disk. Ordering argument —
// why two concurrent persists cannot write stale state:
//
//  1. Every mutation bumps seq under mu.Lock, atomically with the mutation, so a
//     snapshot read under mu.RLock at version V contains exactly the mutations
//     numbered <= V. Versions are monotonic and never reused.
//  2. flushMu serializes snapshot AND kv.Save as ONE critical section. A writer's
//     snapshot is therefore taken after every previously-completed write has
//     already returned, so the version handed to kv.Save is non-decreasing in
//     write order. An older snapshot can never overtake a newer one — the
//     out-of-order hazard is structurally impossible, not merely unlikely.
//  3. A caller's own mutation is always <= the version its persist snapshots
//     (the snapshot happens after the caller released mu), so a nil return
//     truthfully means "your change reached the store" — the F-70 contract.
//  4. `want <= flushedSeq` is consequently safe, and it COALESCES: when N
//     mutations pile up behind one slow write, the first waiter to acquire
//     flushMu snapshots all of them at once and the remaining waiters return
//     without writing. A burst costs 2 writes instead of N — the same win a
//     timer-based debounce would buy, but with a zero loss window, since no
//     caller returns before its own state is durable.
//  5. A failed write does NOT advance flushedSeq, so the next mutation's persist
//     retries the whole set (the write is a full-collection rewrite, so a later
//     success subsumes every earlier failure).
func (s *Store) persist(want uint64) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	if want != 0 && want <= s.flushedSeq {
		return nil // already durable, inside a snapshot at least as new
	}
	s.mu.RLock()
	ver := s.seq
	list := make([]Session, 0, len(s.byID))
	for _, x := range s.byID {
		list = append(list, x)
	}
	s.mu.RUnlock()
	// Session is all value fields, so the copy above is a complete snapshot and
	// the O(N) sort + marshal below run entirely outside mu.
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := s.kv.Save(s.path, b); err != nil {
		return err
	}
	s.flushedSeq = ver
	return nil
}

// gcLocked drops terminal sessions whose last activity is well in the past.
func (s *Store) gcLocked(now time.Time) {
	for id, x := range s.byID {
		if x.Status != StatusActive && now.Sub(x.LastActivityAt) > 7*24*time.Hour {
			delete(s.byID, id)
		}
	}
}

func uaHash(ua string) string {
	if ua == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:8])
}

// Create opens a new active session, enforcing the per-user concurrent cap by
// revoking the oldest active session(s) past the limit. Returns the session and
// the ids it evicted (for observability).
func (s *Store) Create(userID, ip, ua string, idle, absolute time.Duration) (Session, []string, error) {
	now := time.Now().UTC()
	sess := Session{
		ID: randHex(16), UserID: userID, CreatedAt: now, LastActivityAt: now, LastRefreshAt: now,
		IssuedIP: ip, UserAgentHash: uaHash(ua), Status: StatusActive,
		IdleTimeoutSec: int(idle.Seconds()), AbsoluteTimeoutSec: int(absolute.Seconds()),
	}
	s.mu.Lock()
	s.gcLocked(now)
	evicted := s.enforceCapLocked(userID)
	s.byID[sess.ID] = sess
	ver := s.bumpLocked()
	s.mu.Unlock()

	if err := s.persist(ver); err != nil {
		// F-70: a create that did not reach the store must not report success.
		// Roll the new session back out of memory, exactly as before.
		s.mu.Lock()
		delete(s.byID, sess.ID)
		rollbackVer := s.bumpLocked()
		s.mu.Unlock()
		// The rollback needs its own write attempt, which the old
		// lock-held-across-IO version did not: a CONCURRENT persist may have
		// snapshotted and durably written this session between the mutation and
		// the failure above, so dropping it from memory alone could leave it on
		// disk. Best-effort by construction (the backend is already known
		// broken and the caller is being told the create failed either way), but
		// never silent — §10.
		if rerr := s.persist(rollbackVer); rerr != nil {
			s.errf("session", "create rollback did not persist", map[string]any{
				"session": sess.ID, "err": rerr.Error(),
			})
		}
		return Session{}, nil, err
	}
	return sess, evicted, nil
}

// enforceCapLocked revokes the oldest-active sessions so that, after adding one
// more, the user holds at most MaxSessionsPerUser active sessions.
func (s *Store) enforceCapLocked(userID string) []string {
	var active []Session
	for _, x := range s.byID {
		if x.UserID == userID && x.Status == StatusActive {
			active = append(active, x)
		}
	}
	if len(active) < MaxSessionsPerUser {
		return nil
	}
	sort.Slice(active, func(i, j int) bool { return active[i].LastActivityAt.Before(active[j].LastActivityAt) })
	var evicted []string
	for i := 0; i <= len(active)-MaxSessionsPerUser; i++ {
		x := active[i]
		x.Status = StatusRevoked
		s.byID[x.ID] = x
		evicted = append(evicted, x.ID)
	}
	return evicted
}

// Validate checks a session at the refresh boundary: it must exist, be active and
// be within the idle + absolute windows (server time only). On expiry it flips
// and persists the status and returns the typed error. The enforce* flags gate
// each window (policy toggles).
func (s *Store) Validate(id string, enforceIdle, enforceAbsolute bool) (Session, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	x, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return Session{}, ErrNotFound
	}
	if x.Status != StatusActive {
		s.mu.Unlock()
		switch x.Status {
		case StatusExpiredIdle:
			return x, ErrIdle
		case StatusExpiredAbsolute:
			return x, ErrAbsolute
		default:
			return x, ErrRevoked
		}
	}
	var ver uint64
	var verr error
	switch {
	case enforceAbsolute && x.AbsoluteTimeoutSec > 0 &&
		now.Sub(x.CreatedAt) > time.Duration(x.AbsoluteTimeoutSec)*time.Second:
		x.Status = StatusExpiredAbsolute
		s.byID[id] = x
		ver, verr = s.bumpLocked(), ErrAbsolute
	case enforceIdle && x.IdleTimeoutSec > 0 &&
		now.Sub(x.LastActivityAt) > time.Duration(x.IdleTimeoutSec)*time.Second:
		x.Status = StatusExpiredIdle
		s.byID[id] = x
		ver, verr = s.bumpLocked(), ErrIdle
	}
	s.mu.Unlock()
	if verr == nil {
		return x, nil
	}
	// Persisting an EXPIRY stays best-effort — deliberately, and unlike Revoke.
	// An expired status is not a fact that exists only here: it is DERIVED from
	// CreatedAt / LastActivityAt, which are themselves durable. If this write is
	// lost, a restart reloads the session as active with the same old timestamps
	// and the very next Validate recomputes the identical verdict, so the
	// externally visible behaviour (refresh refused with the same code) is
	// unchanged. Revocation has no such fallback — nothing recomputes "an admin
	// killed this" — which is why F-70 reports it and this does not. Reporting it
	// here would also mean overloading Validate's error, whose sole meaning to
	// auth.go is the SPA-facing session code. Logged, never swallowed (§10).
	if err := s.persist(ver); err != nil {
		s.errf("session", "session expiry did not persist", map[string]any{
			"session": id, "status": x.Status, "err": err.Error(),
		})
	}
	return x, verr
}

// Touch records activity at the refresh boundary (last_activity + last_refresh).
//
// Flush policy: Touch still writes, but it no longer holds the store lock while
// doing so, and concurrent touches COALESCE inside persist (a burst behind one
// slow write collapses to a single extra write). A time-based debounce was
// considered and rejected: Touch fires only at /api/auth/refresh — once per
// access-token TTL per session, not per request (see the file header) — so the
// write amplification a debounce would remove is already small, while it would
// buy a real loss window and a background timer to own. Coalescing gives the
// same burst behaviour with a zero loss window.
//
// The persist error stays UNREPORTED (Touch has no error return, and auth.go's
// refresh has already succeeded by this point). Losing it only moves
// LastActivityAt backwards to its last durable value, which can only SHORTEN the
// idle window on a restart — it fails closed, never open. Logged, not swallowed.
func (s *Store) Touch(id string) {
	now := time.Now().UTC()
	s.mu.Lock()
	x, ok := s.byID[id]
	if !ok || x.Status != StatusActive {
		s.mu.Unlock()
		return
	}
	x.LastActivityAt = now
	x.LastRefreshAt = now
	s.byID[id] = x
	ver := s.bumpLocked()
	s.mu.Unlock()
	if err := s.persist(ver); err != nil {
		s.errf("session", "session activity did not persist", map[string]any{
			"session": id, "err": err.Error(),
		})
	}
}

// Revoke kills one session (logout / admin action). Idempotent.
//
// Returns (revoked, err): `revoked` reports whether an ACTIVE session was found
// and killed — false means the id was unknown or already dead, which is a
// legitimate idempotent outcome, not a failure. `err` is a PERSIST failure: the
// in-memory status flipped but the change did not reach disk, so a restart
// resurrects the session.
//
// F-70: this used to return nothing and swallow the flush error, so a logout
// that failed to persist reported success and the session came back on the next
// restart — while an audit record asserted it had been killed.
func (s *Store) Revoke(id string) (bool, error) {
	s.mu.Lock()
	x, ok := s.byID[id]
	if !ok || x.Status != StatusActive {
		s.mu.Unlock()
		return false, nil
	}
	x.Status = StatusRevoked
	s.byID[id] = x
	ver := s.bumpLocked()
	s.mu.Unlock()
	// Reported, not best-effort: persist(ver) returns nil only once a snapshot
	// containing this revocation is on disk (persist §3).
	if err := s.persist(ver); err != nil {
		return true, err
	}
	return true, nil
}

// RevokeAllForUser revokes every active session for a user (e.g. on password
// change). Returns the number revoked and any PERSIST failure — see Revoke.
//
// A non-nil error with n>0 means the sessions are dead in memory but will
// return on restart. auth.go's promise that a password change "revokes ALL
// sessions so a stolen session can't survive a credential reset" depends
// entirely on this error being surfaced.
func (s *Store) RevokeAllForUser(userID string) (int, error) {
	s.mu.Lock()
	n := 0
	for id, x := range s.byID {
		if x.UserID == userID && x.Status == StatusActive {
			x.Status = StatusRevoked
			s.byID[id] = x
			n++
		}
	}
	var ver uint64
	if n > 0 {
		ver = s.bumpLocked()
	}
	s.mu.Unlock()
	if n > 0 {
		if err := s.persist(ver); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Get returns a session by id.
func (s *Store) Get(id string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	x, ok := s.byID[id]
	return x, ok
}

// IsActive reports whether a session is currently active — the cheap per-request
// check withAuth uses for instant revocation (admin kill / logout / pw-change).
//
// CONC-HIGH-1: this runs on EVERY authenticated request. It takes a READ lock and
// touches nothing but the map, so concurrent requests do not serialize against
// each other and — critically — never wait on a durable write.
func (s *Store) IsActive(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	x, ok := s.byID[id]
	return ok && x.Status == StatusActive
}

// List returns all sessions, most-recently-active first (admin/device UI).
func (s *Store) List() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, 0, len(s.byID))
	for _, x := range s.byID {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastActivityAt.After(out[j].LastActivityAt) })
	return out
}

// ListForUser returns a user's sessions, newest first (for the admin/device UI).
func (s *Store) ListForUser(userID string) []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Session
	for _, x := range s.byID {
		if x.UserID == userID {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ErrorCode maps a validation error to the SPA-facing machine code.
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrIdle):
		return "SESSION_IDLE_TIMEOUT"
	case errors.Is(err, ErrAbsolute):
		return "SESSION_ABSOLUTE_TIMEOUT"
	case errors.Is(err, ErrRevoked):
		return "SESSION_REVOKED"
	default:
		return "SESSION_INVALID"
	}
}
