package main

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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type refreshToken struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"` // sha256 hex of the full secret
	Username  string    `json:"username"`
	Family    string    `json:"family"` // rotation lineage (reuse detection)
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`    // rotated away from
	Revoked   bool      `json:"revoked"` // explicitly killed
}

type refreshStore struct {
	mu   sync.Mutex
	path string
	ttl  time.Duration
	toks map[string]refreshToken // keyed by ID
}

func newRefreshStore(path string, ttl time.Duration) (*refreshStore, error) {
	if path == "" {
		path = "/data/refresh_tokens.json"
	}
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	s := &refreshStore{path: path, ttl: ttl, toks: make(map[string]refreshToken)}
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

func (s *refreshStore) load() error {
	b, err := os.ReadFile(s.path)
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

func (s *refreshStore) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	list := make([]refreshToken, 0, len(s.toks))
	for _, t := range s.toks {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// gcLocked drops tokens that expired more than a day ago, keeping the file small.
func (s *refreshStore) gcLocked(now time.Time) {
	for id, t := range s.toks {
		if now.Sub(t.ExpiresAt) > 24*time.Hour {
			delete(s.toks, id)
		}
	}
}

// issueLocked mints a token in the given family (empty = new family).
func (s *refreshStore) issueLocked(username, family string) (string, error) {
	now := time.Now().UTC()
	if family == "" {
		family = randHex(8)
	}
	id := randHex(6)
	secret := id + "." + randHex(24)
	sum := sha256.Sum256([]byte(secret))
	s.toks[id] = refreshToken{
		ID: id, Hash: hex.EncodeToString(sum[:]), Username: username, Family: family,
		CreatedAt: now, ExpiresAt: now.Add(s.ttl),
	}
	if err := s.flushLocked(); err != nil {
		delete(s.toks, id)
		return "", err
	}
	return secret, nil
}

// Issue creates a brand-new refresh token (and family) for a username.
func (s *refreshStore) Issue(username string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(time.Now().UTC())
	return s.issueLocked(username, "")
}

func parseSecret(secret string) (string, bool) {
	i := strings.IndexByte(secret, '.')
	if i <= 0 {
		return "", false
	}
	return secret[:i], true
}

func (s *refreshStore) revokeFamilyLocked(family string) {
	for id, t := range s.toks {
		if t.Family == family {
			t.Revoked = true
			s.toks[id] = t
		}
	}
}

// Rotate validates a refresh token and swaps it for a fresh one. On replay of an
// already-used/revoked token, the whole family is revoked and an error returned.
func (s *refreshStore) Rotate(secret string) (newSecret, username string, err error) {
	id, ok := parseSecret(secret)
	if !ok {
		return "", "", errors.New("malformed refresh token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.toks[id]
	if !ok {
		return "", "", errors.New("unknown refresh token")
	}
	sum := sha256.Sum256([]byte(secret))
	if hex.EncodeToString(sum[:]) != t.Hash {
		return "", "", errors.New("invalid refresh token")
	}
	now := time.Now().UTC()
	if t.Revoked || t.Used {
		// Replay of a rotated/killed token — treat as compromise.
		s.revokeFamilyLocked(t.Family)
		_ = s.flushLocked()
		return "", "", errors.New("refresh token reuse detected; family revoked")
	}
	if now.After(t.ExpiresAt) {
		return "", "", errors.New("refresh token expired")
	}
	t.Used = true
	t.Revoked = true
	s.toks[id] = t
	ns, err := s.issueLocked(t.Username, t.Family)
	if err != nil {
		return "", "", err
	}
	return ns, t.Username, nil
}

// Revoke kills a single refresh token (logout). Unknown tokens are ignored.
func (s *refreshStore) Revoke(secret string) {
	id, ok := parseSecret(secret)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.toks[id]; ok {
		t.Revoked = true
		s.toks[id] = t
		_ = s.flushLocked()
	}
}
