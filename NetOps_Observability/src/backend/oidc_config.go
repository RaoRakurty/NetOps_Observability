package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"os"
	"strings"
	"sync"

	"netops/backend/internal/oidc"
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
// fields the env-derived initial provider reads, so behaviour is unchanged
// when nothing has been saved.
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
	b, err := platformdb.Load(s.path)
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
	// A stored record that was never actually filled in is NOT a configuration —
	// it is the same "never configured" state as an absent or empty key, and it
	// must fall through to the environment the same way.
	//
	// Without this, a default-shaped record (`enabled:false`, empty issuer and
	// client_id — which is what a first GET of the config page persists) silently
	// OVERRODE a completely correct `OIDC_*` environment. docker-compose.yml tells
	// the operator to "set OIDC_ENABLED=true and the OIDC_* vars in .env — the api
	// service reads them", and they were read, parsed, and then discarded: the
	// stored blank won. `/api/auth/sso/config` answered {"enabled": false} and
	// every SSO route 404'd, with no error anywhere to explain why (found while
	// bringing Okta up for the first time, 2026-08-03).
	//
	// Deliberately narrow: ONLY the all-blank disabled shape falls through. A
	// record someone genuinely saved — even a disabled one with an issuer set —
	// is a real decision and keeps overriding the environment.
	if c.NeverConfigured() {
		return nil
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
	in.Normalize()
	if err := in.Validate(); err != nil {
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
	if err := platformdb.Save(s.path, b); err != nil {
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
		s.srv.oidc.Store(oidc.NewProviderFromConfig(stored, jwksTTL()))
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
			"config": s.oidcCfg.effective().Public(),
			"ready":  s.oidcProvider().Ready(),
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
			"config": out.Public(),
			"ready":  s.oidcProvider().Ready(),
		})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
