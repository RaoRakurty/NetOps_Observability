// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package apikey

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

// KeyPrefix makes keys recognizable and greppable in logs/secret scanners.
const KeyPrefix = "ntk_" // "opsis key"

type Key struct {
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
	Contacts        []string   `json:"contacts,omitempty"` // emails
	ContactPhone    string     `json:"contact_phone,omitempty"`
	SourceCIDRs     []string   `json:"source_cidrs,omitempty"` // allowed source IPs
	ClientExpiresAt *time.Time `json:"client_expires_at,omitempty"`
	SecretExpiresAt *time.Time `json:"secret_expires_at,omitempty"`
}

// Public omits the hash; it's what the API returns when listing. The
// window fields reflect the live (current-minute) rate-limit usage so the UI can
// show how close a key is to its cap.
type Public struct {
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

func (k Key) Public() Public {
	return Public{
		ID: k.ID, TenantID: k.TenantID, Label: k.Label, Prefix: k.Prefix,
		Scopes: k.Scopes, RateLimitPerMin: k.RateLimitPerMin, UseCount: k.UseCount,
		CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt,
		LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt,
		GrantTypes: k.GrantTypes, ClientURI: k.ClientURI, LogoURI: k.LogoURI,
		Contacts: k.Contacts, ContactPhone: k.ContactPhone, SourceCIDRs: k.SourceCIDRs,
		ClientExpiresAt: k.ClientExpiresAt, SecretExpiresAt: k.SecretExpiresAt,
	}
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

type Store struct {
	mu            sync.RWMutex
	path          string
	kv            KV
	keys          map[string]Key        // id -> key
	windows       map[string]*keyWindow // id -> current rate-limit window
	defaultLimit  int                   // per-minute cap when a key sets none (0 = unlimited)
	defaultTenant string                // owner of keys created without a tenant

	// multiWriter is set when more than one API instance shares this backend
	// store (the cred-cache reload loop is active). It makes Verify update its
	// per-call usage stats (UseCount/LastUsedAt) IN MEMORY ONLY instead of
	// rewriting the whole-collection blob: a stale replica must never write its
	// map back over the shared store, or it would resurrect a key another replica
	// just revoked. Security-critical mutations (Create/Revoke) always write
	// through regardless. Single-writer (file) deployments leave this false and
	// keep per-call usage durability.
	multiWriter bool
}

// DefaultRateLimit is the fallback per-minute cap when the integrator supplies
// a negative defaultLimit (the APIKEY_RATE_LIMIT_PER_MIN env read lives in the
// entrypoint package; 0 means unlimited).
const DefaultRateLimit = 600

// KV abstracts where the store persists its JSON blob. The integrator supplies
// the platform kv layer (file or postgres); a missing key must return an
// os.ErrNotExist-wrapped error.
type KV interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// NewStore opens the key store. defaultLimit is the per-minute cap for keys
// that set none (0 = unlimited, negative = DefaultRateLimit); defaultTenant
// owns keys created without a tenant.
func NewStore(path string, defaultLimit int, defaultTenant string, kv KV) (*Store, error) {
	if path == "" {
		path = "/data/apikeys.json"
	}
	if kv == nil {
		return nil, errors.New("apikey.NewStore: kv is required")
	}
	if defaultLimit < 0 {
		defaultLimit = DefaultRateLimit
	}
	s := &Store{
		path:          path,
		kv:            kv,
		keys:          make(map[string]Key),
		windows:       make(map[string]*keyWindow),
		defaultLimit:  defaultLimit,
		defaultTenant: defaultTenant,
	}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// effectiveLimit resolves a key's per-minute cap: its own override, else the
// server default. 0 means unlimited.
// SetMultiWriter switches Verify to in-memory-only usage stats — required when
// several API instances share this backend store (see the multiWriter field).
func (s *Store) SetMultiWriter(v bool) {
	s.mu.Lock()
	s.multiWriter = v
	s.mu.Unlock()
}

func (s *Store) EffectiveLimit(k Key) int {
	if k.RateLimitPerMin > 0 {
		return k.RateLimitPerMin
	}
	return s.defaultLimit
}

// Allow applies a fixed-window-per-minute rate limit to key id. limit<=0 means
// unlimited. Returns whether the call is allowed and, when not, the seconds
// until the window resets (Retry-After). Counts the call when allowed.
func (s *Store) Allow(id string, limit int) (ok bool, retryAfter int) {
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
func (s *Store) windowUsedLocked(id string) int {
	w := s.windows[id]
	if w == nil || time.Now().UTC().Sub(w.start) >= time.Minute {
		return 0
	}
	return w.count
}

func (s *Store) load() error {
	b, err := s.kv.Load(s.path)
	if err != nil {
		return err
	}
	var list []Key
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, k := range list {
		s.keys[k.ID] = k
	}
	return nil
}

// reload re-reads the persisted key set from the shared backend and atomically
// replaces the in-memory map, so a revocation / rotation / expiry performed by
// ANOTHER API instance (which writes through the same kvBackend) takes effect
// here within one reload interval instead of lingering until restart. The
// per-instance rate-limit windows are deliberately kept (they are ephemeral and
// instance-local); windows for keys that no longer exist are pruned.
//
// This closes the security-critical multi-instance gap: a revoked or expired key
// must stop authenticating everywhere, which it now does once the persisted
// RevokedAt/expiry is observed here. Concurrent multi-instance *writes* still
// follow the blob store's last-writer-wins semantics — acceptable for this
// bounded, low-write config set (see the "cached by design" note in TRACKER #33).
// A missing store (never written yet) is treated as empty, not an error.
func (s *Store) Reload() error {
	b, err := s.kv.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		s.keys = make(map[string]Key)
		s.windows = make(map[string]*keyWindow)
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	var list []Key
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	next := make(map[string]Key, len(list))
	for _, k := range list {
		next[k.ID] = k
	}
	s.mu.Lock()
	s.keys = next
	for id := range s.windows {
		if _, ok := next[id]; !ok {
			delete(s.windows, id)
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Store) flushLocked() error {
	list := make([]Key, 0, len(s.keys))
	for _, k := range s.keys {
		list = append(list, k)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return s.kv.Save(s.path, b)
}

// Get returns the stored record for id (hash included — callers expose only
// Public() shapes to clients).
func (s *Store) Get(id string) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[id]
	return k, ok
}

func (s *Store) List() []Public {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Public, 0, len(s.keys))
	for _, k := range s.keys {
		p := k.Public()
		p.RateLimitPerMin = s.EffectiveLimit(k)
		p.WindowUsed = s.windowUsedLocked(k.ID)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Input carries the RFC 7591-style registration request for a new key.
// RateLimitPerMin <= 0 inherits the server default. GrantTypes defaults to
// ["client_credentials"] when empty (these are machine-to-machine keys).
type Input struct {
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

// ---- scope vocabulary ------------------------------------------------------
//
// A key's AUTHORITY is derived from its scopes by the integrator
// (roleFromScopes in auth.go): a key carrying only read: scopes acts read-only,
// any write: scope makes it an operator, and admin:* makes it an administrator
// of the tenant the key is bound to. The resource half of a read:/write: scope
// is descriptive (audit + operator intent); the verb half is what the middleware
// acts on. See docs/API_ACCESS.md for the full table.
//
// The vocabulary is CLOSED and validated at creation: an unknown scope is
// rejected rather than stored, so a typo ("write:device") can never silently
// mint a key with different authority than the operator intended, and the UI,
// the API and the docs share ONE list. Adding a scope is a deliberate edit here.
const (
	// ScopeAdminAll grants administrator authority WITHIN the key's tenant.
	// Bound to the platform/global realm it is a platform-administrator key —
	// which is why the integrator only lets a platform admin mint that one.
	ScopeAdminAll = "admin:*"
	// ScopeReadAll / ScopeWriteAll are the wildcards HasScope expands.
	ScopeReadAll  = "read:*"
	ScopeWriteAll = "write:*"
	// ScopeIngestCloud is the dedicated service scope for the cloud-ingest
	// poller; it is honoured only in the platform realm (cloud_ingest_service.go).
	ScopeIngestCloud = "ingest:cloud"
	// ScopeIngestExperience is the dedicated WRITE-ONLY scope for the DEM
	// experience lane (tracker 254): the first-party RUM snippet and the
	// business-event feed. Unlike ScopeIngestCloud it is honoured only for a
	// key bound to a CONCRETE tenant — the events it admits are stamped with
	// that tenant, so a platform-realm key would have no owner to stamp.
	//
	// It grants no read of any kind, ON PURPOSE. A RUM snippet is served to the
	// public, so its credential must be assumed public: a key that could also
	// read would hand a tenant's experience data to anyone who viewed source.
	ScopeIngestExperience = "ingest:experience"
)

// knownScopes is the closed vocabulary (immutable lookup table, same shape as
// validGrantTypes). Order for display comes from KnownScopes().
var knownScopes = map[string]bool{
	"read:metrics":        true,
	"read:alerts":         true,
	"read:devices":        true,
	"read:flows":          true,
	ScopeReadAll:          true,
	"write:incidents":     true,
	"write:alerts":        true,
	"write:devices":       true,
	ScopeWriteAll:         true,
	ScopeIngestCloud:      true,
	ScopeIngestExperience: true,
	ScopeAdminAll:         true,
}

// KnownScopes returns the closed scope vocabulary in display order (read →
// write → service → admin), so callers never have to restate the list.
func KnownScopes() []string {
	return []string{
		"read:metrics", "read:alerts", "read:devices", "read:flows", ScopeReadAll,
		"write:incidents", "write:alerts", "write:devices", ScopeWriteAll,
		ScopeIngestCloud, ScopeIngestExperience, ScopeAdminAll,
	}
}

// ScopeKnown reports whether s is in the closed vocabulary (case/space
// insensitive, matching the normalization Create applies).
func ScopeKnown(s string) bool {
	return knownScopes[strings.ToLower(strings.TrimSpace(s))]
}

// NormalizeScopes lowercases, trims, drops blanks and de-duplicates a requested
// scope list, preserving first-seen order. It returns an error naming the first
// scope outside the closed vocabulary. Exported so the HTTP layer can authorize
// the SAME normalized list it stores (no second, divergent parse).
func NormalizeScopes(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !knownScopes[s] {
			return nil, fmt.Errorf("unknown scope %q", s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
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
func (in *Input) validate() error {
	in.Label = strings.TrimSpace(in.Label)
	if in.Label == "" {
		return errors.New("key label required")
	}
	if in.RateLimitPerMin < 0 {
		in.RateLimitPerMin = 0
	}
	scopes, err := NormalizeScopes(in.Scopes)
	if err != nil {
		return err
	}
	in.Scopes = scopes
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
func (s *Store) Create(in Input, createdBy string) (Public, string, error) {
	if in.TenantID == "" {
		in.TenantID = s.defaultTenant
	}
	if err := in.validate(); err != nil {
		return Public{}, "", err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return Public{}, "", err
	}
	secret := KeyPrefix + hex.EncodeToString(raw)
	id := hex.EncodeToString(raw[:6])
	k := Key{
		ID: id, TenantID: in.TenantID, Label: in.Label, Hash: hashKey(secret),
		Prefix: secret[:len(KeyPrefix)+6] + "…", Scopes: in.Scopes,
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
		return Public{}, "", err
	}
	return k.Public(), secret, nil
}

// sourceAllowed reports whether ip is permitted to use this key. An empty
// SourceCIDRs list means any source is allowed; otherwise ip must fall within
// one of the configured CIDRs. Malformed CIDRs (already rejected at creation)
// are skipped defensively.
func (k Key) SourceAllowed(ip net.IP) bool {
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

func (s *Store) Revoke(id string) error {
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
func (s *Store) Verify(secret string) (Key, bool) {
	h := hashKey(secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, k := range s.keys {
		if k.Hash == h && k.RevokedAt == nil {
			now := time.Now().UTC()
			// Reject expired client identities or secrets (RFC 7591 lifecycle).
			if k.ClientExpiresAt != nil && k.ClientExpiresAt.Before(now) {
				return Key{}, false
			}
			if k.SecretExpiresAt != nil && k.SecretExpiresAt.Before(now) {
				return Key{}, false
			}
			k.LastUsedAt = &now
			k.UseCount++
			s.keys[id] = k
			// Single-writer: persist usage immediately (durable across restart).
			// Multi-writer: in-memory only — never rewrite the shared blob from a
			// possibly-stale map (see multiWriter doc); usage becomes per-instance.
			if !s.multiWriter {
				_ = s.flushLocked() // best-effort: usage stamp; a failed flush costs telemetry, not auth
			}
			return k, true
		}
	}
	return Key{}, false
}
