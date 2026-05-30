package main

// apikeys.go — scoped, tenant-bound API keys for non-interactive clients
// (CI, datasources, sync jobs). The plaintext key is shown exactly once at
// creation; only a SHA-256 hash is stored. File-backed (apikeys.json).
// See docs/API_ACCESS.md.

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

// keyPrefix makes keys recognizable and greppable in logs/secret scanners.
const keyPrefix = "ntk_" // "netra key"

type APIKey struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	Label           string     `json:"label"`
	Hash            string     `json:"hash"`   // sha256 hex of the secret
	Prefix          string     `json:"prefix"` // first chars, for display
	Scopes          []string   `json:"scopes"`
	RateLimitPerMin int        `json:"rate_limit_per_min,omitempty"` // 0 = server default
	UseCount        int64      `json:"use_count"`                    // lifetime authenticated calls
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// publicAPIKey omits the hash; it's what the API returns when listing. The
// window fields reflect the live (current-minute) rate-limit usage so the UI can
// show how close a key is to its cap.
type publicAPIKey struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	Label           string     `json:"label"`
	Prefix          string     `json:"prefix"`
	Scopes          []string   `json:"scopes"`
	RateLimitPerMin int        `json:"rate_limit_per_min"` // effective per-minute cap (0 = unlimited)
	UseCount        int64      `json:"use_count"`
	WindowUsed      int        `json:"window_used"` // calls counted in the current minute
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

func (k APIKey) public() publicAPIKey {
	return publicAPIKey{
		ID: k.ID, TenantID: k.TenantID, Label: k.Label, Prefix: k.Prefix,
		Scopes: k.Scopes, RateLimitPerMin: k.RateLimitPerMin, UseCount: k.UseCount,
		CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt,
		LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt,
	}
}

// roleFromScopes derives the RBAC role an API key principal acts under from its
// scope list. Keys are read-only by default; a write: scope grants operator-
// level write on the product modules, and admin:* grants super-admin. This keeps
// a key from ever exceeding what its scopes describe (see docs/API_ACCESS.md).
func roleFromScopes(scopes []string) string {
	role := RoleReadOnly
	for _, s := range scopes {
		s = strings.ToLower(strings.TrimSpace(s))
		switch {
		case s == "admin:*":
			return RoleSuperAdmin
		case strings.HasPrefix(s, "write:"):
			role = RoleOperator
		}
	}
	return role
}

func hashKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// keyWindow is a fixed-window per-minute counter for one key (in-memory only).
type keyWindow struct {
	start time.Time
	count int
}

type apiKeyStore struct {
	mu           sync.RWMutex
	path         string
	keys         map[string]APIKey     // id -> key
	windows      map[string]*keyWindow // id -> current rate-limit window
	defaultLimit int                   // per-minute cap when a key sets none (0 = unlimited)
}

// defaultKeyRateLimit is the fallback per-minute cap, overridable via
// APIKEY_RATE_LIMIT_PER_MIN (0 disables app-level limiting by default).
const defaultKeyRateLimit = 600

func newAPIKeyStore(path string) (*apiKeyStore, error) {
	if path == "" {
		path = "/data/apikeys.json"
	}
	limit := defaultKeyRateLimit
	if v := os.Getenv("APIKEY_RATE_LIMIT_PER_MIN"); v != "" {
		if n, err := parseIntStrict(v); err == nil && n >= 0 {
			limit = n
		}
	}
	s := &apiKeyStore{
		path:         path,
		keys:         make(map[string]APIKey),
		windows:      make(map[string]*keyWindow),
		defaultLimit: limit,
	}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// effectiveLimit resolves a key's per-minute cap: its own override, else the
// server default. 0 means unlimited.
func (s *apiKeyStore) effectiveLimit(k APIKey) int {
	if k.RateLimitPerMin > 0 {
		return k.RateLimitPerMin
	}
	return s.defaultLimit
}

// Allow applies a fixed-window-per-minute rate limit to key id. limit<=0 means
// unlimited. Returns whether the call is allowed and, when not, the seconds
// until the window resets (Retry-After). Counts the call when allowed.
func (s *apiKeyStore) Allow(id string, limit int) (ok bool, retryAfter int) {
	if limit <= 0 {
		return true, 0
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.windows[id]
	if w == nil || now.Sub(w.start) >= time.Minute {
		s.windows[id] = &keyWindow{start: now, count: 1}
		return true, 0
	}
	if w.count >= limit {
		return false, int(time.Minute-now.Sub(w.start))/int(time.Second) + 1
	}
	w.count++
	return true, 0
}

// windowUsedLocked returns the current-minute call count for id (0 if the window
// has rolled over). Caller must hold s.mu.
func (s *apiKeyStore) windowUsedLocked(id string) int {
	w := s.windows[id]
	if w == nil || time.Now().UTC().Sub(w.start) >= time.Minute {
		return 0
	}
	return w.count
}

func (s *apiKeyStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []APIKey
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, k := range list {
		s.keys[k.ID] = k
	}
	return nil
}

func (s *apiKeyStore) flushLocked() error {
	list := make([]APIKey, 0, len(s.keys))
	for _, k := range s.keys {
		list = append(list, k)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

func (s *apiKeyStore) List() []publicAPIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]publicAPIKey, 0, len(s.keys))
	for _, k := range s.keys {
		p := k.public()
		p.RateLimitPerMin = s.effectiveLimit(k)
		p.WindowUsed = s.windowUsedLocked(k.ID)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Create mints a new key and returns the one-time plaintext secret alongside
// the stored (hashless) record. rateLimitPerMin <= 0 inherits the server default.
func (s *apiKeyStore) Create(tenantID, label, createdBy string, scopes []string, rateLimitPerMin int) (publicAPIKey, string, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return publicAPIKey{}, "", errors.New("key label required")
	}
	if tenantID == "" {
		tenantID = TenantGlobal
	}
	if rateLimitPerMin < 0 {
		rateLimitPerMin = 0
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return publicAPIKey{}, "", err
	}
	secret := keyPrefix + hex.EncodeToString(raw)
	id := hex.EncodeToString(raw[:6])
	k := APIKey{
		ID: id, TenantID: tenantID, Label: label, Hash: hashKey(secret),
		Prefix: secret[:len(keyPrefix)+6] + "…", Scopes: scopes,
		RateLimitPerMin: rateLimitPerMin,
		CreatedBy:       createdBy, CreatedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[id] = k
	if err := s.flushLocked(); err != nil {
		delete(s.keys, id)
		return publicAPIKey{}, "", err
	}
	return k.public(), secret, nil
}

func (s *apiKeyStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return errors.New("no such key")
	}
	now := time.Now().UTC()
	k.RevokedAt = &now
	s.keys[id] = k
	return s.flushLocked()
}

// Verify resolves a presented secret to its (active) key record. Used by the
// auth middleware to authenticate machine clients. Updates last-used.
func (s *apiKeyStore) Verify(secret string) (APIKey, bool) {
	h := hashKey(secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, k := range s.keys {
		if k.Hash == h && k.RevokedAt == nil {
			now := time.Now().UTC()
			k.LastUsedAt = &now
			k.UseCount++
			s.keys[id] = k
			_ = s.flushLocked()
			return k, true
		}
	}
	return APIKey{}, false
}
