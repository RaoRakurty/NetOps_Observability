package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/vault"
	"os"
	"strings"
	"sync"
)

// oidc_config.go — runtime-configurable, kv-persisted overlay for the SSO/OIDC
// provider, plus its admin GET/PUT handler.
//
// Mirrors ldapConfigStore (auth_config.go) and copilotConfigStore exactly: a
// stored JSON document overlays the env-derived defaults (OIDC_* vars), so an
// operator can turn SSO on and configure the identity provider from the admin
// UI without editing .env and restarting. Two invariants, as elsewhere:
//
//   - The client secret is WRITE-ONLY. GET never returns it — only a
//     "client_secret_set" boolean. A PUT that omits the secret PRESERVES the
//     stored one, so saving the redacted form never wipes it.
//   - Every PUT is normalised and validated before persistence; an "enabled"
//     config missing the issuer or client ID is rejected, not half-applied.
//
// On a successful set() the store REBUILDS the live *oidcProvider and swaps it
// into the server's atomic pointer (s.oidc), so readers on the hot auth path
// and in the SSO handlers pick up the new config without a restart and without
// a data race.

// oidcConfig is the serialisable SSO provider configuration. It mirrors the
// fields newOIDCProvider() reads from the environment, so behaviour is
// unchanged when nothing has been saved.
type oidcConfig struct {
	Enabled       bool   `json:"enabled"`
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"` // write-only: persisted to the kv store; never returned by public()
	Scopes        string `json:"scopes"`
	RedirectURL   string `json:"redirect_url"`
	PostLoginURL  string `json:"post_login_url"`
	DefaultRole   string `json:"default_role"`
	DefaultTenant string `json:"default_tenant"`
	AdminRoles    string `json:"admin_roles"`    // csv
	OperatorRoles string `json:"operator_roles"` // csv
	Providers     string `json:"providers"`      // OIDC_PROVIDERS csv: "id:Label:kind,..."
	// RequireMFA rejects an SSO sign-in unless the IdP's token asserts a second
	// factor (amr/acr) — i.e. we HONOR the IdP's MFA instead of trusting it blindly.
	RequireMFA bool   `json:"require_mfa"`
	MFAAcr     string `json:"mfa_acr,omitempty"` // csv of acr values that count as MFA (IdP-specific; optional)
}

// newOIDCConfigFromEnv reads the same env vars newOIDCProvider() reads today so
// the env-only resolution is preserved until an operator saves from the UI.
func newOIDCConfigFromEnv() oidcConfig {
	return oidcConfig{
		Enabled:       os.Getenv("OIDC_ENABLED") == "true",
		Issuer:        strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/"),
		ClientID:      os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
		Scopes:        envOr("OIDC_SCOPES", "openid email profile"),
		RedirectURL:   os.Getenv("OIDC_REDIRECT_URL"),
		PostLoginURL:  envOr("OIDC_POST_LOGIN_URL", "/"),
		DefaultRole:   envOr("OIDC_DEFAULT_ROLE", RoleReadOnly),
		DefaultTenant: envOr("OIDC_DEFAULT_TENANT", TenantGlobal),
		AdminRoles:    envOr("OIDC_ADMIN_ROLES", "super-admin,admin,netops-admin"),
		OperatorRoles: envOr("OIDC_OPERATOR_ROLES", "operator,netops-operator"),
		Providers:     os.Getenv("OIDC_PROVIDERS"),
		RequireMFA:    os.Getenv("OIDC_REQUIRE_MFA") == "true",
		MFAAcr:        os.Getenv("OIDC_MFA_ACR"),
	}
}

// normalize trims fields and applies the same defaults newOIDCProviderFromConfig
// applies, so the stored document is canonical.
func (c *oidcConfig) normalize() {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.Scopes = strings.TrimSpace(c.Scopes)
	if c.Scopes == "" {
		c.Scopes = "openid email profile"
	}
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	c.PostLoginURL = strings.TrimSpace(c.PostLoginURL)
	if c.PostLoginURL == "" {
		c.PostLoginURL = "/"
	}
	c.DefaultRole = strings.TrimSpace(c.DefaultRole)
	if c.DefaultRole == "" {
		c.DefaultRole = RoleReadOnly
	}
	c.DefaultTenant = strings.TrimSpace(c.DefaultTenant)
	if c.DefaultTenant == "" {
		c.DefaultTenant = TenantGlobal
	}
	c.AdminRoles = strings.TrimSpace(c.AdminRoles)
	c.OperatorRoles = strings.TrimSpace(c.OperatorRoles)
	c.Providers = strings.TrimSpace(c.Providers)
}

// validate enforces the invariants required for an enabled OIDC provider.
func (c oidcConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Issuer == "" {
		return errors.New("oidc: issuer is required when enabled")
	}
	if c.ClientID == "" {
		return errors.New("oidc: client_id is required when enabled")
	}
	return nil
}

// publicOIDCConfig is the redacted view returned by GET: the client secret is
// replaced by a boolean so the secret never leaves the server.
type publicOIDCConfig struct {
	Enabled         bool   `json:"enabled"`
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	ClientSecretSet bool   `json:"client_secret_set"`
	Scopes          string `json:"scopes"`
	RedirectURL     string `json:"redirect_url"`
	PostLoginURL    string `json:"post_login_url"`
	DefaultRole     string `json:"default_role"`
	DefaultTenant   string `json:"default_tenant"`
	AdminRoles      string `json:"admin_roles"`
	OperatorRoles   string `json:"operator_roles"`
	Providers       string `json:"providers"`
	RequireMFA      bool   `json:"require_mfa"`
	MFAAcr          string `json:"mfa_acr,omitempty"`
}

func (c oidcConfig) public() publicOIDCConfig {
	return publicOIDCConfig{
		Enabled:         c.Enabled,
		Issuer:          c.Issuer,
		ClientID:        c.ClientID,
		ClientSecretSet: c.ClientSecret != "",
		Scopes:          c.Scopes,
		RedirectURL:     c.RedirectURL,
		PostLoginURL:    c.PostLoginURL,
		DefaultRole:     c.DefaultRole,
		DefaultTenant:   c.DefaultTenant,
		AdminRoles:      c.AdminRoles,
		OperatorRoles:   c.OperatorRoles,
		Providers:       c.Providers,
		RequireMFA:      c.RequireMFA,
		MFAAcr:          c.MFAAcr,
	}
}

// oidcConfigStore is the kv-backed overlay. It holds a back-reference to the
// server so set() can rebuild and atomically swap the live provider.
type oidcConfigStore struct {
	mu   sync.RWMutex
	cfg  *oidcConfig // nil until an operator saves; falls back to env defaults
	path string
	srv  *server
	// loadErr: the stored client secret could not be unsealed — see ldapConfigStore.
	loadErr error
}

func newOIDCConfigStore(path string, srv *server) *oidcConfigStore {
	s := &oidcConfigStore{path: path, srv: srv}
	if err := s.load(); err != nil {
		s.loadErr = err
		// SSO silently reverting to the env defaults is a sign-in outage; the
		// cause used to share a branch with "no operator has configured SSO yet".
		logError("oidc.config", "stored SSO config unreadable — SSO falls back to the env defaults", errf(err))
	}
	return s
}

// load reads the stored OIDC overlay. THREE states, never two (the
// cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob — env defaults apply) / loaded.
func (s *oidcConfigStore) load() error {
	b, err := kvLoad(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = never configured; env defaults apply
	}
	if err != nil {
		return fmt.Errorf("read OIDC config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = never configured
	}
	var c oidcConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("decode OIDC config: %w", err)
	}
	var loadErr error
	if dec, derr := mapOIDC(c, openFn(s.vault())); derr != nil {
		// Never send the SEALED bytes to the IdP as the client secret.
		c.ClientSecret = ""
		loadErr = fmt.Errorf("unseal OIDC client secret: %w", derr)
		logError("oidc.config", "decrypt secret", errf(derr))
	} else {
		c = dec
	}
	s.mu.Lock()
	s.cfg = &c
	s.mu.Unlock()
	return loadErr
}

// vault returns the secret-custody vault.Vault (nil → dormant/passthrough).
func (s *oidcConfigStore) vault() *vault.Vault {
	if s.srv == nil {
		return nil
	}
	return s.srv.vault
}

// effective returns the stored overlay when present, else the env-derived
// defaults so behaviour matches the original env-only resolution until an
// operator saves from the UI.
func (s *oidcConfigStore) effective() oidcConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	if c == nil {
		return newOIDCConfigFromEnv()
	}
	return *c
}

// set validates and persists in, then rebuilds + atomically swaps the live
// provider. When in.ClientSecret is empty the previously stored secret is
// preserved (the redacted GET form does not round-trip the secret). Returns the
// stored effective config.
func (s *oidcConfigStore) set(in oidcConfig) (oidcConfig, error) {
	in.normalize()
	if err := in.validate(); err != nil {
		return oidcConfig{}, err
	}
	s.mu.Lock()
	if in.ClientSecret == "" && s.cfg != nil {
		if s.loadErr != nil {
			s.mu.Unlock()
			return oidcConfig{}, errors.New("the stored client secret could not be read — re-enter it with this save")
		}
		in.ClientSecret = s.cfg.ClientSecret
	}
	// #nosec G117 -- the OIDC client secret is intentionally persisted to the kv
	// store so the provider is UI-configurable; it is redacted from every API
	// response by publicOIDCConfig and never logged. At rest it is encrypted under
	// the platform DEK (the in-memory copy below stays plaintext for the provider).
	sealed, err := mapOIDC(in, sealFn(s.vault()))
	if err != nil {
		s.mu.Unlock()
		return oidcConfig{}, err
	}
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		s.mu.Unlock()
		return oidcConfig{}, err
	}
	if err := kvSave(s.path, b); err != nil {
		s.mu.Unlock()
		return oidcConfig{}, err
	}
	stored := in
	s.cfg = &stored
	s.loadErr = nil // a successful save IS the repair
	s.mu.Unlock()

	// Rebuild and swap the live provider so the hot auth path and SSO handlers
	// pick up the new config immediately, without a restart or a data race.
	if s.srv != nil {
		s.srv.oidc.Store(newOIDCProviderFromConfig(stored))
	}
	return stored, nil
}

// handleOIDCConfig: GET/PUT /api/auth/oidc/config (admin-gated). GET returns the
// redacted effective config plus whether the provider is ready; PUT validates,
// persists, rebuilds the live provider and returns the redacted config + ready.
func (s *server) handleOIDCConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"config": s.oidcCfg.effective().public(),
			"ready":  s.oidcProvider().ready(),
		})
	case http.MethodPut:
		var in oidcConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.oidcCfg.set(in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("auth", "oidc config updated", map[string]any{"enabled": out.Enabled, "issuer": out.Issuer})
		writeJSON(w, http.StatusOK, map[string]any{
			"config": out.public(),
			"ready":  s.oidcProvider().ready(),
		})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
