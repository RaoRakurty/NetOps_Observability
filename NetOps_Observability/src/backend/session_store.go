package main

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
	sessionActive          = "active"
	sessionRevoked         = "revoked"
	sessionExpiredIdle     = "expired_idle"
	sessionExpiredAbsolute = "expired_absolute"

	maxSessionsPerUser = 5 // enterprise-safe concurrent cap; oldest evicted past it
)

// Typed validation errors → mapped to machine-readable codes for the SPA.
var (
	errSessionNotFound = errors.New("session not found")
	errSessionRevoked  = errors.New("session revoked")
	errSessionIdle     = errors.New("session idle timeout")
	errSessionAbsolute = errors.New("session absolute timeout")
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

type sessionStore struct {
	mu   sync.Mutex
	path string
	byID map[string]Session
}

func newSessionStore(path string) (*sessionStore, error) {
	if path == "" {
		path = "/data/sessions.json"
	}
	s := &sessionStore{path: path, byID: map[string]Session{}}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *sessionStore) load() error {
	b, err := kvLoad(s.path)
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

func (s *sessionStore) flushLocked() error {
	list := make([]Session, 0, len(s.byID))
	for _, x := range s.byID {
		list = append(list, x)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// gcLocked drops terminal sessions whose last activity is well in the past.
func (s *sessionStore) gcLocked(now time.Time) {
	for id, x := range s.byID {
		if x.Status != sessionActive && now.Sub(x.LastActivityAt) > 7*24*time.Hour {
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
func (s *sessionStore) Create(userID, ip, ua string, idle, absolute time.Duration) (Session, []string, error) {
	now := time.Now().UTC()
	sess := Session{
		ID: randHex(16), UserID: userID, CreatedAt: now, LastActivityAt: now, LastRefreshAt: now,
		IssuedIP: ip, UserAgentHash: uaHash(ua), Status: sessionActive,
		IdleTimeoutSec: int(idle.Seconds()), AbsoluteTimeoutSec: int(absolute.Seconds()),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	evicted := s.enforceCapLocked(userID)
	s.byID[sess.ID] = sess
	if err := s.flushLocked(); err != nil {
		delete(s.byID, sess.ID)
		return Session{}, nil, err
	}
	return sess, evicted, nil
}

// enforceCapLocked revokes the oldest-active sessions so that, after adding one
// more, the user holds at most maxSessionsPerUser active sessions.
func (s *sessionStore) enforceCapLocked(userID string) []string {
	var active []Session
	for _, x := range s.byID {
		if x.UserID == userID && x.Status == sessionActive {
			active = append(active, x)
		}
	}
	if len(active) < maxSessionsPerUser {
		return nil
	}
	sort.Slice(active, func(i, j int) bool { return active[i].LastActivityAt.Before(active[j].LastActivityAt) })
	var evicted []string
	for i := 0; i <= len(active)-maxSessionsPerUser; i++ {
		x := active[i]
		x.Status = sessionRevoked
		s.byID[x.ID] = x
		evicted = append(evicted, x.ID)
	}
	return evicted
}

// Validate checks a session at the refresh boundary: it must exist, be active and
// be within the idle + absolute windows (server time only). On expiry it flips
// and persists the status and returns the typed error. The enforce* flags gate
// each window (policy toggles).
func (s *sessionStore) Validate(id string, enforceIdle, enforceAbsolute bool) (Session, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[id]
	if !ok {
		return Session{}, errSessionNotFound
	}
	if x.Status != sessionActive {
		switch x.Status {
		case sessionExpiredIdle:
			return x, errSessionIdle
		case sessionExpiredAbsolute:
			return x, errSessionAbsolute
		default:
			return x, errSessionRevoked
		}
	}
	if enforceAbsolute && x.AbsoluteTimeoutSec > 0 &&
		now.Sub(x.CreatedAt) > time.Duration(x.AbsoluteTimeoutSec)*time.Second {
		x.Status = sessionExpiredAbsolute
		s.byID[id] = x
		_ = s.flushLocked()
		return x, errSessionAbsolute
	}
	if enforceIdle && x.IdleTimeoutSec > 0 &&
		now.Sub(x.LastActivityAt) > time.Duration(x.IdleTimeoutSec)*time.Second {
		x.Status = sessionExpiredIdle
		s.byID[id] = x
		_ = s.flushLocked()
		return x, errSessionIdle
	}
	return x, nil
}

// Touch records activity at the refresh boundary (last_activity + last_refresh).
func (s *sessionStore) Touch(id string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.byID[id]; ok && x.Status == sessionActive {
		x.LastActivityAt = now
		x.LastRefreshAt = now
		s.byID[id] = x
		_ = s.flushLocked()
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
func (s *sessionStore) Revoke(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[id]
	if !ok || x.Status != sessionActive {
		return false, nil
	}
	x.Status = sessionRevoked
	s.byID[id] = x
	if err := s.flushLocked(); err != nil {
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
func (s *sessionStore) RevokeAllForUser(userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, x := range s.byID {
		if x.UserID == userID && x.Status == sessionActive {
			x.Status = sessionRevoked
			s.byID[id] = x
			n++
		}
	}
	if n > 0 {
		if err := s.flushLocked(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Get returns a session by id.
func (s *sessionStore) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[id]
	return x, ok
}

// IsActive reports whether a session is currently active — the cheap per-request
// check withAuth uses for instant revocation (admin kill / logout / pw-change).
func (s *sessionStore) IsActive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[id]
	return ok && x.Status == sessionActive
}

// List returns all sessions, most-recently-active first (admin/device UI).
func (s *sessionStore) List() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.byID))
	for _, x := range s.byID {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastActivityAt.After(out[j].LastActivityAt) })
	return out
}

// ListForUser returns a user's sessions, newest first (for the admin/device UI).
func (s *sessionStore) ListForUser(userID string) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, x := range s.byID {
		if x.UserID == userID {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// sessionErrorCode maps a validation error to the SPA-facing machine code.
func sessionErrorCode(err error) string {
	switch {
	case errors.Is(err, errSessionIdle):
		return "SESSION_IDLE_TIMEOUT"
	case errors.Is(err, errSessionAbsolute):
		return "SESSION_ABSOLUTE_TIMEOUT"
	case errors.Is(err, errSessionRevoked):
		return "SESSION_REVOKED"
	default:
		return "SESSION_INVALID"
	}
}
