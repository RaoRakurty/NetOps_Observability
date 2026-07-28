package session

// refresh.go — rotating refresh tokens with reuse detection.
//
// The login flow issues a short-lived access JWT plus an opaque refresh token.
// The SPA trades the refresh token for a fresh access token at /api/auth/refresh;
// each use ROTATES the refresh token (the old one is invalidated). If a token
// that was already rotated is presented again, that's a replay/theft signal —
// the whole token family is revoked, forcing re-login. File-backed
// (refresh_tokens.json), same pattern as the other stores.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type refreshToken struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"` // sha256 hex of the full secret
	Username  string    `json:"username"`
	Family    string    `json:"family"`               // rotation lineage (reuse detection)
	SessionID string    `json:"session_id,omitempty"` // server-side session this token belongs to
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`    // rotated away from
	Revoked   bool      `json:"revoked"` // explicitly killed
}

type RefreshStore struct {
	mu   sync.Mutex
	path string
	kv   KV
	ttl  time.Duration
	toks map[string]refreshToken // keyed by ID
}

func NewRefreshStore(path string, ttl time.Duration, kv KV) (*RefreshStore, error) {
	if path == "" {
		path = "/data/refresh_tokens.json"
	}
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	if kv == nil {
		return nil, errors.New("session.NewRefreshStore: kv is required")
	}
	s := &RefreshStore{path: path, kv: kv, ttl: ttl, toks: make(map[string]refreshToken)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *RefreshStore) load() error {
	b, err := s.kv.Load(s.path)
	if err != nil {
		return err
	}
	var list []refreshToken
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, t := range list {
		s.toks[t.ID] = t
	}
	return nil
}

func (s *RefreshStore) flushLocked() error {
	list := make([]refreshToken, 0, len(s.toks))
	for _, t := range s.toks {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return s.kv.Save(s.path, b)
}

// gcLocked drops tokens that expired more than a day ago, keeping the file small.
func (s *RefreshStore) gcLocked(now time.Time) {
	for id, t := range s.toks {
		if now.Sub(t.ExpiresAt) > 24*time.Hour {
			delete(s.toks, id)
		}
	}
}

// issueLocked mints a token in the given family (empty = new family), bound to
// the given server-side session id (empty for legacy/federated logins).
func (s *RefreshStore) issueLocked(username, family, sessionID string) (string, error) {
	now := time.Now().UTC()
	if family == "" {
		family = randHex(8)
	}
	id := randHex(6)
	secret := id + "." + randHex(24)
	sum := sha256.Sum256([]byte(secret))
	s.toks[id] = refreshToken{
		ID: id, Hash: hex.EncodeToString(sum[:]), Username: username, Family: family, SessionID: sessionID,
		CreatedAt: now, ExpiresAt: now.Add(s.ttl),
	}
	if err := s.flushLocked(); err != nil {
		delete(s.toks, id)
		return "", err
	}
	return secret, nil
}

// SetTTL updates the refresh-token lifetime at runtime (token policy admin). It
// affects tokens issued after the change; existing tokens keep their expiry. A
// non-positive ttl is ignored.
func (s *RefreshStore) SetTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s.mu.Lock()
	s.ttl = ttl
	s.mu.Unlock()
}

// TTL returns the lifetime currently applied to newly issued tokens.
func (s *RefreshStore) TTL() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ttl
}

// Issue creates a brand-new refresh token (and family) for a username, with no
// server-side session (legacy / federated logins).
func (s *RefreshStore) Issue(username string) (string, error) {
	return s.IssueForSession(username, "")
}

// IssueForSession creates a brand-new refresh token (and family) bound to a
// server-side session id.
func (s *RefreshStore) IssueForSession(username, sessionID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(time.Now().UTC())
	return s.issueLocked(username, "", sessionID)
}

// SessionOf returns the session id a refresh token belongs to, without rotating
// it (used by logout). ok=false if the token is unknown/malformed.
func (s *RefreshStore) SessionOf(secret string) (string, bool) {
	id, ok := parseSecret(secret)
	if !ok {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.toks[id]; ok {
		return t.SessionID, true
	}
	return "", false
}

func parseSecret(secret string) (string, bool) {
	i := strings.IndexByte(secret, '.')
	if i <= 0 {
		return "", false
	}
	return secret[:i], true
}

func (s *RefreshStore) revokeFamilyLocked(family string) {
	for id, t := range s.toks {
		if t.Family == family {
			t.Revoked = true
			s.toks[id] = t
		}
	}
}

// Rotate validates a refresh token and swaps it for a fresh one (3-return form
// kept for the store's own tests). On replay of an already-used/revoked token,
// the whole family is revoked and an error returned.
func (s *RefreshStore) Rotate(secret string) (newSecret, username string, err error) {
	ns, u, _, e := s.RotateSession(secret)
	return ns, u, e
}

// RotateSession is Rotate plus the rotated token's server-side session id, so the
// refresh handler can enforce the session lifecycle. The replacement token keeps
// the same session id (and family) as the one it rotates away from.
func (s *RefreshStore) RotateSession(secret string) (newSecret, username, sessionID string, err error) {
	id, ok := parseSecret(secret)
	if !ok {
		return "", "", "", errors.New("malformed refresh token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.toks[id]
	if !ok {
		return "", "", "", errors.New("unknown refresh token")
	}
	sum := sha256.Sum256([]byte(secret))
	if hex.EncodeToString(sum[:]) != t.Hash {
		return "", "", "", errors.New("invalid refresh token")
	}
	now := time.Now().UTC()
	if t.Revoked || t.Used {
		// Replay of a rotated/killed token — treat as compromise.
		s.revokeFamilyLocked(t.Family)
		_ = s.flushLocked()
		return "", "", "", errors.New("refresh token reuse detected; family revoked")
	}
	if now.After(t.ExpiresAt) {
		return "", "", "", errors.New("refresh token expired")
	}
	t.Used = true
	t.Revoked = true
	s.toks[id] = t
	ns, err := s.issueLocked(t.Username, t.Family, t.SessionID)
	if err != nil {
		return "", "", "", err
	}
	return ns, t.Username, t.SessionID, nil
}

// Revoke kills a single refresh token (logout).
//
// Returns (revoked, err). `revoked` is false when the secret is malformed,
// unknown, or already revoked — all idempotent no-ops. `err` is a PERSIST
// failure: the token is dead in memory but alive on disk, so it will mint
// access tokens again after a restart.
//
// F-70: this returned nothing. A logout whose revoke never persisted — or
// whose token was never recognised at all — was reported to the caller as
// {"status":"ok"}, and the same token still minted a new access token.
func (s *RefreshStore) Revoke(secret string) (bool, error) {
	id, ok := parseSecret(secret)
	if !ok {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.toks[id]
	if !ok || t.Revoked {
		return false, nil
	}
	t.Revoked = true
	s.toks[id] = t
	if err := s.flushLocked(); err != nil {
		return true, err
	}
	return true, nil
}
