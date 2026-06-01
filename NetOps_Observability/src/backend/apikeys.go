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
	"fmt"
	"net"
	"net/url"
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

	// RFC 7591-style client metadata (non-secret).
	GrantTypes      []string   `json:"grant_types,omitempty"`
	ClientURI       string     `json:"client_uri,omitempty"`
	LogoURI         string     `json:"logo_uri,omitempty"`
	Contacts        []string   `json:"contacts,omitempty"`         // emails
	ContactPhone    string     `json:"contact_phone,omitempty"`
	SourceCIDRs     []string   `json:"source_cidrs,omitempty"`     // allowed source IPs
	ClientExpiresAt *time.Time `json:"client_expires_at,omitempty"`
	SecretExpiresAt *time.Time `json:"secret_expires_at,omitempty"`
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

	// RFC 7591-style client metadata (non-secret).
	GrantTypes      []string   `json:"grant_types,omitempty"`
	ClientURI       string     `json:"client_uri,omitempty"`
	LogoURI         string     `json:"logo_uri,omitempty"`
	Contacts        []string   `json:"contacts,omitempty"`
	ContactPhone    string     `json:"contact_phone,omitempty"`
	SourceCIDRs     []string   `json:"source_cidrs,omitempty"`
	ClientExpiresAt *time.Time `json:"client_expires_at,omitempty"`
	SecretExpiresAt *time.Time `json:"secret_expires_at,omitempty"`
}

func (k APIKey) public() publicAPIKey {
	return publicAPIKey{
		ID: k.ID, TenantID: k.TenantID, Label: k.Label, Prefix: k.Prefix,
		Scopes: k.Scopes, RateLimitPerMin: k.RateLimitPerMin, UseCount: k.UseCount,
		CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt,
		LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt,
		GrantTypes: k.GrantTypes, ClientURI: k.ClientURI, LogoURI: k.LogoURI,
		Contacts: k.Contacts, ContactPhone: k.ContactPhone, SourceCIDRs: k.SourceCIDRs,
		ClientExpiresAt: k.ClientExpiresAt, SecretExpiresAt: k.SecretExpiresAt,
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

// apiKeyInput carries the RFC 7591-style registration request for a new key.
// RateLimitPerMin <= 0 inherits the server default. GrantTypes defaults to
// ["client_credentials"] when empty (these are machine-to-machine keys).
type apiKeyInput struct {
	TenantID        string
	Label           string
	Scopes          []string
	RateLimitPerMin int
	GrantTypes      []string
	Contacts        []string
	SourceCIDRs     []string
	ClientURI       string
	LogoURI         string
	ContactPhone    string
	ClientExpiresAt *time.Time
	SecretExpiresAt *time.Time
}

// validGrantTypes is the set permitted per RFC 6749 / RFC 7591. The "password"
// grant is intentionally excluded (deprecated by RFC 9700 §2.4).
var validGrantTypes = map[string]bool{
	"authorization_code": true,
	"client_credentials": true,
	"refresh_token":      true,
}

// validate enforces the RFC 7591-style metadata rules. It normalizes the input
// in place (trims label, defaults grant types) and returns the first error.
func (in *apiKeyInput) validate() error {
	in.Label = strings.TrimSpace(in.Label)
	if in.Label == "" {
		return errors.New("key label required")
	}
	if in.TenantID == "" {
		in.TenantID = TenantGlobal
	}
	if in.RateLimitPerMin < 0 {
		in.RateLimitPerMin = 0
	}
	if len(in.GrantTypes) == 0 {
		in.GrantTypes = []string{"client_credentials"}
	}
	for _, g := range in.GrantTypes {
		g = strings.TrimSpace(g)
		if g == "password" {
			return errors.New("password grant is deprecated (RFC 9700 §2.4)")
		}
		if !validGrantTypes[g] {
			return fmt.Errorf("unsupported grant type %q", g)
		}
	}
	for _, c := range in.SourceCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("invalid source CIDR %q: %w", c, err)
		}
	}
	for _, e := range in.Contacts {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "@") {
			return fmt.Errorf("invalid contact email %q", e)
		}
	}
	if u := strings.TrimSpace(in.ClientURI); u != "" {
		if _, err := url.ParseRequestURI(u); err != nil {
			return fmt.Errorf("invalid client URI %q: %w", u, err)
		}
	}
	if u := strings.TrimSpace(in.LogoURI); u != "" {
		if _, err := url.ParseRequestURI(u); err != nil {
			return fmt.Errorf("invalid logo URI %q: %w", u, err)
		}
	}
	return nil
}

// Create mints a new key from a validated input and returns the one-time
// plaintext secret alongside the stored (hashless) record.
func (s *apiKeyStore) Create(in apiKeyInput, createdBy string) (publicAPIKey, string, error) {
	if err := in.validate(); err != nil {
		return publicAPIKey{}, "", err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return publicAPIKey{}, "", err
	}
	secret := keyPrefix + hex.EncodeToString(raw)
	id := hex.EncodeToString(raw[:6])
	k := APIKey{
		ID: id, TenantID: in.TenantID, Label: in.Label, Hash: hashKey(secret),
		Prefix: secret[:len(keyPrefix)+6] + "…", Scopes: in.Scopes,
		RateLimitPerMin: in.RateLimitPerMin,
		CreatedBy:       createdBy, CreatedAt: time.Now().UTC(),
		GrantTypes: in.GrantTypes, ClientURI: in.ClientURI, LogoURI: in.LogoURI,
		Contacts: in.Contacts, ContactPhone: in.ContactPhone, SourceCIDRs: in.SourceCIDRs,
		ClientExpiresAt: in.ClientExpiresAt, SecretExpiresAt: in.SecretExpiresAt,
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

// sourceAllowed reports whether ip is permitted to use this key. An empty
// SourceCIDRs list means any source is allowed; otherwise ip must fall within
// one of the configured CIDRs. Malformed CIDRs (already rejected at creation)
// are skipped defensively.
func (k APIKey) sourceAllowed(ip net.IP) bool {
	if len(k.SourceCIDRs) == 0 {
		return true
	}
	for _, c := range k.SourceCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, netw, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if ip != nil && netw.Contains(ip) {
			return true
		}
	}
	return false
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
			// Reject expired client identities or secrets (RFC 7591 lifecycle).
			if k.ClientExpiresAt != nil && k.ClientExpiresAt.Before(now) {
				return APIKey{}, false
			}
			if k.SecretExpiresAt != nil && k.SecretExpiresAt.Before(now) {
				return APIKey{}, false
			}
			k.LastUsedAt = &now
			k.UseCount++
			s.keys[id] = k
			_ = s.flushLocked()
			return k, true
		}
	}
	return APIKey{}, false
}
