// Package secpolicy owns the scope-wide security policy domain (P2 RA.2): the
// Security Settings model + store, the password-rule validation, and the F-68
// account-lifecycle gate. It is pure policy over injected state — no HTTP, no
// env reads, no live server stores; scope authorization stays with the caller.
package secpolicy

// settings.go — scope-wide "Security Settings" (the User-Global-Settings
// equivalent): the password/lockout/session rules that apply to EVERYONE in a
// scope, set once. This replaces the abstract per-control policy editor with a
// flat settings object per scope (provider = the platform; or a specific tenant).
//
// Per-user security (require MFA, temporary account, idle timeout) lives on the
// user record / Create-User form instead — see users + the security split in
// docs/design/provider-org-tenant-ia.md §6.
//
// File-kv backed like the other stores; promotes to Postgres unchanged.

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"

	"netops/backend/internal/platformdb"
)

// ScopeProvider is the settings scope for the platform-owner (provider) realm.
const ScopeProvider = "provider"

// Settings is one scope's flat security ruleset. Defaults mirror common
// baselines; zero values are replaced by defaults on load.
type Settings struct {
	Scope                 string `json:"scope"`
	MinPasswordLength     int    `json:"min_password_length"`
	RequireUppercase      bool   `json:"require_uppercase"`
	RequireLowercase      bool   `json:"require_lowercase"`
	RequireNumber         bool   `json:"require_number"`
	RequireSpecial        bool   `json:"require_special"`
	PasswordExpireEnabled bool   `json:"password_expire_enabled"`
	PasswordExpireDays    int    `json:"password_expire_days"`
	PasswordHistory       bool   `json:"password_history"`
	ResetOnFirstLogin     bool   `json:"reset_on_first_login"`
	LoginAttemptsAllowed  int    `json:"login_attempts_allowed"`
	UnlockTimeSeconds     int    `json:"unlock_time_seconds"`
	AccountValidityDays   int    `json:"account_validity_days"`
	AccountInactivityDays int    `json:"account_inactivity_days"`
	ConcurrentLogin       string `json:"concurrent_login"` // allow | deny
	// Session lifecycle (per scope — Provider / Org / Tenant). Idle is operator-
	// facing; absolute is a hidden standard default (kept out of the UI to avoid
	// confusion). Enforced server-side at /api/auth/refresh.
	IdleTimeoutMinutes     int  `json:"idle_timeout_minutes"`
	AbsoluteTimeoutMinutes int  `json:"absolute_timeout_minutes"`
	EnforceIdleTimeout     bool `json:"enforce_idle_timeout"`
	EnforceAbsoluteTimeout bool `json:"enforce_absolute_timeout"`
}

// DefaultSettings is the baseline ruleset for a scope with nothing stored.
func DefaultSettings(scope string) Settings {
	return Settings{
		Scope:                 scope,
		MinPasswordLength:     8,
		RequireUppercase:      true,
		RequireLowercase:      true,
		RequireNumber:         true,
		RequireSpecial:        true,
		PasswordExpireEnabled: true,
		PasswordExpireDays:    90,
		PasswordHistory:       false,
		ResetOnFirstLogin:     false,
		LoginAttemptsAllowed:  3,
		UnlockTimeSeconds:     900,
		AccountValidityDays:   180,
		AccountInactivityDays: 90,
		ConcurrentLogin:       "allow",
		// Industry-aligned session defaults: idle 30 min (AWS Systems Manager idle
		// range 1–60; PCI 8.1.8 ≤15), absolute 12 h (enterprise SaaS; AWS IAM
		// Identity Center access-portal session default is 8 h). Both enforced.
		IdleTimeoutMinutes:     30,
		AbsoluteTimeoutMinutes: 720,
		EnforceIdleTimeout:     true,
		EnforceAbsoluteTimeout: true,
	}
}

// Store is the file-kv-backed per-scope settings store.
type Store struct {
	mu      sync.RWMutex
	path    string
	byScope map[string]Settings
}

// NewStore opens the store at path ("" → the standard location).
func NewStore(path string) (*Store, error) {
	if path == "" {
		path = "/data/security_settings.json"
	}
	s := &Store{path: path, byScope: map[string]Settings{}}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := platformdb.Load(s.path)
	if err != nil {
		return err
	}
	var list []Settings
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, ss := range list {
		s.byScope[ss.Scope] = ss
	}
	return nil
}

func (s *Store) flushLocked() error {
	list := make([]Settings, 0, len(s.byScope))
	for _, ss := range s.byScope {
		list = append(list, ss)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

// Get returns the scope's settings, or the defaults if unset.
func (s *Store) Get(scope string) Settings {
	scope = NormalizeScope(scope)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ss, ok := s.byScope[scope]; ok {
		return ss
	}
	return DefaultSettings(scope)
}

// Set persists the scope's settings (after light normalization).
func (s *Store) Set(scope string, in Settings) (Settings, error) {
	scope = NormalizeScope(scope)
	in.Scope = scope
	if in.MinPasswordLength < 4 {
		in.MinPasswordLength = 4
	}
	if in.LoginAttemptsAllowed < 1 {
		in.LoginAttemptsAllowed = 1
	}
	if in.ConcurrentLogin != "deny" {
		in.ConcurrentLogin = "allow"
	}
	// Session lifetimes: clamp to sane minimums; a zero/blank value falls back to
	// the standard default rather than disabling the control.
	if in.IdleTimeoutMinutes <= 0 {
		in.IdleTimeoutMinutes = 30
	} else if in.IdleTimeoutMinutes < 5 {
		in.IdleTimeoutMinutes = 5 // floor: avoid logging users out mid-action
	}
	if in.AbsoluteTimeoutMinutes <= 0 {
		in.AbsoluteTimeoutMinutes = 720
	}
	// Absolute must be ≥ idle to be coherent.
	if in.AbsoluteTimeoutMinutes < in.IdleTimeoutMinutes {
		in.AbsoluteTimeoutMinutes = in.IdleTimeoutMinutes
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byScope[scope] = in
	if err := s.flushLocked(); err != nil {
		return Settings{}, err
	}
	return in, nil
}

// NormalizeScope maps blank/global to the provider scope. "global" is pinned in
// lock-step with the entrypoint's TenantGlobal id (tenant.Global).
func NormalizeScope(scope string) string {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" || scope == "global" {
		return ScopeProvider
	}
	return scope
}

// ConcurrentLoginDenied reports whether the scope forbids a second concurrent
// session. Compared case-insensitively against "deny" and defaulting to ALLOW
// on an unrecognised value: this setting gates sign-in, and an unparseable
// value must not lock a tenant out of its own platform. The validating write
// path (Set) is what keeps junk from being stored at all.
func ConcurrentLoginDenied(ss Settings) bool {
	return strings.EqualFold(strings.TrimSpace(ss.ConcurrentLogin), "deny")
}
