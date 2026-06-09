package main

// security_settings.go — scope-wide "Security Settings" (the User-Global-Settings
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
	"net/http"
	"os"
	"strings"
	"sync"
)

// ScopeProvider is the settings scope for the platform-owner (provider) realm.
const ScopeProvider = "provider"

// SecuritySettings is one scope's flat security ruleset. Defaults mirror common
// baselines; zero values are replaced by defaults on load.
type SecuritySettings struct {
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
}

func defaultSecuritySettings(scope string) SecuritySettings {
	return SecuritySettings{
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
	}
}

type securitySettingsStore struct {
	mu      sync.RWMutex
	path    string
	byScope map[string]SecuritySettings
}

func newSecuritySettingsStore(path string) (*securitySettingsStore, error) {
	if path == "" {
		path = "/data/security_settings.json"
	}
	s := &securitySettingsStore{path: path, byScope: map[string]SecuritySettings{}}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *securitySettingsStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []SecuritySettings
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, ss := range list {
		s.byScope[ss.Scope] = ss
	}
	return nil
}

func (s *securitySettingsStore) flushLocked() error {
	list := make([]SecuritySettings, 0, len(s.byScope))
	for _, ss := range s.byScope {
		list = append(list, ss)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// Get returns the scope's settings, or the defaults if unset.
func (s *securitySettingsStore) Get(scope string) SecuritySettings {
	scope = normalizeSettingsScope(scope)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ss, ok := s.byScope[scope]; ok {
		return ss
	}
	return defaultSecuritySettings(scope)
}

// Set persists the scope's settings (after light normalization).
func (s *securitySettingsStore) Set(scope string, in SecuritySettings) (SecuritySettings, error) {
	scope = normalizeSettingsScope(scope)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byScope[scope] = in
	if err := s.flushLocked(); err != nil {
		return SecuritySettings{}, err
	}
	return in, nil
}

// normalizeSettingsScope maps blank/global to the provider scope.
func normalizeSettingsScope(scope string) string {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" || scope == TenantGlobal || scope == "global" {
		return ScopeProvider
	}
	return scope
}

// handleSecuritySettings serves GET/PUT /api/security-settings?scope=provider|<tenant>.
func (s *server) handleSecuritySettings(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	scope := normalizeSettingsScope(r.URL.Query().Get("scope"))
	// Provider-scope settings are platform-owner only; a tenant's settings need
	// the platform owner or that tenant's admin.
	if scope == ScopeProvider {
		if !isPlatformOwner(claims) {
			writeError(w, http.StatusForbidden, errors.New("platform administrator required"))
			return
		}
	} else if !isPlatformOwner(claims) && !s.reachesTenant(claims.Sub, scope) {
		writeError(w, http.StatusForbidden, errors.New("not your scope"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.securitySettings.Get(scope))
	case http.MethodPut:
		var in SecuritySettings
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.securitySettings.Set(scope, in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("security", "security settings updated", map[string]any{"scope": scope, "by": claims.Sub})
		writeJSON(w, http.StatusOK, out)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
