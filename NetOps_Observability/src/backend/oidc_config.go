package backend

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"os"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/keycloak"
	"netops/backend/internal/oidc"
	"netops/backend/internal/ssoidp"
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

// ───────────────────────────────────────────────────────────────────────────
// GUI-configurable SSO identity providers — the HTTP boundary + apply path.
//
// The desired-state DOMAIN (model, validation, sealed store) lives in
// internal/ssoidp; the Keycloak admin client in internal/keycloak. This
// section is only what belongs in the root: the platform-admin handlers, the
// reconcile orchestration, and the auto-wiring of the relying-party config
// above, so a saved IdP is live end to end with zero console work:
//
//	GET    /api/auth/sso/idp          → configured IdPs (redacted) + Keycloak ping
//	PUT    /api/auth/sso/idp/{alias}  → validate → persist → reconcile → wire RP
//	DELETE /api/auth/sso/idp/{alias}  → remove from Keycloak + store + login page
//	POST   /api/auth/sso/idp/{alias}/test → probe IdP metadata/discovery + Keycloak
// ───────────────────────────────────────────────────────────────────────────

// Type shims (the jwtClaims-alias technique) for the extracted ssoidp domain.
type (
	ssoIdPConfig = ssoidp.Config
	ssoIdPPublic = ssoidp.Public
)

// ssoPublicBase derives the deployment's public base URL from the (proxied)
// admin request — the same X-Forwarded derivation the SSO callback uses — so
// redirect URIs, the SAML entity ID and the issuer all agree with what the
// operator's browser reaches.
func ssoPublicBase(r *http.Request) string {
	scheme := "http"
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if xh := r.Header.Get("X-Forwarded-Host"); xh != "" {
		host = xh
	}
	return scheme + "://" + host
}

// csvEnsure appends val to a comma-separated set when absent (case-insensitive).
func csvEnsure(csv, val string) string {
	for _, p := range strings.Split(csv, ",") {
		if strings.EqualFold(strings.TrimSpace(p), val) {
			return csv
		}
	}
	if strings.TrimSpace(csv) == "" {
		return val
	}
	return csv + "," + val
}

// upsertProviderCSV reconciles one "alias:Label:kind" entry in the login-page
// provider list (oidc.ParseProviders format): replaced when present, appended
// when include and absent, dropped when !include.
func upsertProviderCSV(csv, alias, label, kind string, include bool) string {
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.TrimSpace(strings.SplitN(raw, ":", 2)[0]) == alias {
			continue
		}
		out = append(out, raw)
	}
	if include {
		out = append(out, alias+":"+label+":"+kind)
	}
	return strings.Join(out, ",")
}

// handleSSOIdPList: GET /api/auth/sso/idp (platform-admin). Lists the redacted
// desired state plus a live Keycloak reachability summary so the UI can tell
// "not configured" from "Keycloak is down" before the operator hits Save.
func (s *server) handleSSOIdPList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idps := s.ssoIdPCfg.List()
	pub := make([]ssoIdPPublic, 0, len(idps))
	for _, c := range idps {
		pub = append(pub, c.Public())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"idps":     pub,
		"keycloak": s.kc.Ping(r.Context()),
	})
}

// handleSSOIdPItem routes /api/auth/sso/idp/{alias} (GET/PUT/DELETE) and
// /api/auth/sso/idp/{alias}/test (POST). All platform-admin.
func (s *server) handleSSOIdPItem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/auth/sso/idp/")
	if alias, ok := strings.CutSuffix(rest, "/test"); ok {
		s.handleSSOIdPTest(w, r, alias)
		return
	}
	alias := rest
	if strings.Contains(alias, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		idp, ok := s.ssoIdPCfg.Get(alias)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"idp": idp.Public()})
	case http.MethodPut:
		s.handleSSOIdPPut(w, r, alias)
	case http.MethodDelete:
		s.handleSSOIdPDelete(w, r, alias)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSSOIdPPut validates and persists the desired state, then applies it to
// Keycloak and auto-wires the relying-party config. Keycloak being down does
// NOT lose the save: the desired state is already persisted, the answer is 502
// with the ping detail and a warning, and the next successful save re-applies.
func (s *server) handleSSOIdPPut(w http.ResponseWriter, r *http.Request, alias string) {
	// Metadata cap (256 KiB) + JSON overhead; nothing legitimate is bigger.
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10)
	var in ssoIdPConfig
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if a := strings.ToLower(strings.TrimSpace(in.Alias)); a != "" && a != alias {
		writeError(w, http.StatusBadRequest, errors.New("alias in body does not match URL"))
		return
	}
	in.Alias = alias
	out, err := s.ssoIdPCfg.Set(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	warnings, err := s.applySSOIdP(r, out)
	logInfo("auth", "sso idp config updated", map[string]any{
		"alias": out.Alias, "protocol": out.Protocol, "enabled": out.Enabled,
		"applied": err == nil, "role_mappings": len(out.RoleMappings),
	})
	if err != nil {
		warnings = append(warnings, "desired state saved but NOT applied to Keycloak — it will be re-applied on the next successful save")
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"idp": out.Public(), "applied": false, "warnings": warnings, "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"idp": out.Public(), "applied": true, "warnings": warnings,
	})
}

// handleSSOIdPDelete removes the IdP from Keycloak (tolerating already-gone or
// an unreachable broker — the store and login page are cleaned up regardless).
func (s *server) handleSSOIdPDelete(w http.ResponseWriter, r *http.Request, alias string) {
	idp, ok := s.ssoIdPCfg.Get(alias)
	if !ok {
		http.NotFound(w, r)
		return
	}
	var warnings []string
	if err := s.kc.DeleteIdentityProvider(r.Context(), s.kc.Realm(), alias); err != nil {
		warnings = append(warnings, "keycloak removal failed (removed from Correlix anyway): "+err.Error())
	}
	if err := s.ssoIdPCfg.Remove(alias); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Drop the login-page button for this alias.
	cfg := s.oidcCfg.effective()
	cfg.Providers = upsertProviderCSV(cfg.Providers, alias, idp.DisplayName, idp.Protocol, false)
	if _, err := s.oidcCfg.set(cfg); err != nil {
		warnings = append(warnings, "provider list update failed: "+err.Error())
	}
	logInfo("auth", "sso idp deleted", map[string]any{"alias": alias, "protocol": idp.Protocol})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "warnings": warnings})
}

// applySSOIdP reconciles one saved record into Keycloak and auto-wires the
// relying-party side. Returns operator-facing warnings; a non-nil error means
// Keycloak could not be (fully) reconciled — desired state is already saved.
func (s *server) applySSOIdP(r *http.Request, idp ssoIdPConfig) ([]string, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	realm := s.kc.Realm()
	base := ssoPublicBase(r)

	ping := s.kc.Ping(ctx)
	if !ping.OK() {
		return nil, errors.New(ping.Detail)
	}
	if err := s.kc.EnsureRealm(ctx, realm); err != nil {
		return nil, err
	}
	// Kill the invisible-role trap before any role mapping exists to fall into it.
	if err := s.kc.EnsureRolesInIDToken(ctx, realm); err != nil {
		return nil, err
	}
	rpCfg := s.oidcCfg.effective()
	clientID := rpCfg.ClientID
	if clientID == "" {
		clientID = "netops"
	}
	secret, err := s.kc.EnsureClient(ctx, realm, clientID,
		[]string{base + "/api/auth/sso/callback"}, []string{base})
	if err != nil {
		return nil, err
	}
	// One realm role per mapped Correlix role, named after the role id, so the
	// ID token's realm_access.roles carries exactly the names the RP role lists
	// below match against.
	seen := map[string]bool{}
	var roleMappings []keycloak.RoleMapping
	for _, m := range idp.RoleMappings {
		if !seen[m.Role] {
			seen[m.Role] = true
			if err := s.kc.EnsureRealmRole(ctx, realm, m.Role); err != nil {
				return nil, err
			}
		}
		roleMappings = append(roleMappings, keycloak.RoleMapping{GroupsAttr: idp.GroupsAttr, Value: m.Value, Role: m.Role})
	}
	if err := s.kc.EnsureIdentityProvider(ctx, realm, keycloak.IdP{
		Alias:          idp.Alias,
		DisplayName:    idp.DisplayName,
		Protocol:       idp.Protocol,
		Enabled:        idp.Enabled,
		MetadataURL:    idp.MetadataURL,
		MetadataXML:    idp.MetadataXML,
		SigningCertPEM: idp.SigningCertPEM,
		EntityID:       base + "/auth/realms/" + realm,
		DiscoveryURL:   idp.DiscoveryURL,
		ClientID:       idp.ClientID,
		ClientSecret:   idp.ClientSecret,
	}); err != nil {
		return nil, err
	}
	if err := s.kc.EnsureIdPMappers(ctx, realm, idp.Alias, idp.Protocol, ssoIdPAttrs(idp), roleMappings); err != nil {
		return nil, err
	}
	return s.wireSSORelyingParty(base, realm, clientID, secret, idp)
}

// ssoIdPAttrs is the attribute-importer set: the standard email/first/last
// importers (per protocol) plus the operator's custom rows, deduped by target
// user attribute (a custom row overrides the standard source for that target).
func ssoIdPAttrs(idp ssoIdPConfig) []keycloak.AttrMapping {
	std := []keycloak.AttrMapping{
		{IdPAttr: "email", UserAttr: "email"},
		{IdPAttr: "firstName", UserAttr: "firstName"},
		{IdPAttr: "lastName", UserAttr: "lastName"},
	}
	if idp.Protocol == "oidc" {
		std = []keycloak.AttrMapping{
			{IdPAttr: "email", UserAttr: "email"},
			{IdPAttr: "given_name", UserAttr: "firstName"},
			{IdPAttr: "family_name", UserAttr: "lastName"},
		}
	}
	var out []keycloak.AttrMapping
	byTarget := map[string]bool{}
	for _, a := range idp.AttrMappings {
		byTarget[a.UserAttr] = true
		out = append(out, keycloak.AttrMapping{IdPAttr: a.IdPAttr, UserAttr: a.UserAttr})
	}
	for _, a := range std {
		if !byTarget[a.UserAttr] {
			out = append(out, a)
		}
	}
	return out
}

// wireSSORelyingParty updates the RP config above so the saved IdP is usable
// immediately: issuer pointed at the realm, broker client id/secret, a
// login-page button for the alias, and role lists that include every mapped
// realm-role name — closing the RoleFor() fallthrough for the roles Correlix
// SSO can express (super-admin / operator / the default role).
func (s *server) wireSSORelyingParty(base, realm, clientID, secret string, idp ssoIdPConfig) ([]string, error) {
	var warnings []string
	cfg := s.oidcCfg.effective()
	cfg.Issuer = base + "/auth/realms/" + realm
	cfg.ClientID = clientID
	if secret != "" {
		cfg.ClientSecret = secret
	}
	cfg.Providers = upsertProviderCSV(cfg.Providers, idp.Alias, idp.DisplayName, idp.Protocol, idp.Enabled)
	if idp.Enabled {
		cfg.Enabled = true
	}
	defaultRole := cfg.DefaultRole
	if defaultRole == "" {
		defaultRole = RoleReadOnly
	}
	for _, m := range idp.RoleMappings {
		switch {
		case isSuperAdminRole(m.Role):
			cfg.AdminRoles = csvEnsure(cfg.AdminRoles, m.Role)
		case m.Role == RoleOperator:
			cfg.OperatorRoles = csvEnsure(cfg.OperatorRoles, m.Role)
		case strings.EqualFold(m.Role, defaultRole):
			// Matching the default role is a no-op mapping — fine, not a warning.
		default:
			warnings = append(warnings, fmt.Sprintf(
				"role mapping %q → %q: SSO sign-in can only grant super-admin, operator, or the default role (%q); users matching this group will receive the default role",
				m.Value, m.Role, defaultRole))
		}
	}
	if os.Getenv("FEDERATION_ALLOW_PLATFORM_OWNER") == "true" {
		for _, m := range idp.RoleMappings {
			if isSuperAdminRole(m.Role) {
				warnings = append(warnings,
					"FEDERATION_ALLOW_PLATFORM_OWNER=true: federated identities mapping to super-admin in the global tenant become PLATFORM OWNERS")
				break
			}
		}
	}
	if _, err := s.oidcCfg.set(cfg); err != nil {
		// Keycloak is fully reconciled at this point; only the RP overlay failed.
		warnings = append(warnings, "keycloak applied, but updating the SSO relying-party config failed: "+err.Error())
	}
	return warnings, nil
}

// ---------------------------------------------------------------------------
// POST /api/auth/sso/idp/{alias}/test — bounded pre-flight probe
// ---------------------------------------------------------------------------

type ssoIdPCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

const ssoTestFetchMax = 1 << 20 // 1 MiB cap on fetched metadata/discovery docs

// samlIdPMetadata is the slice of SAML EntityDescriptor the probe reads.
// encoding/xml matches local names, so namespace prefixes don't matter.
type samlIdPMetadata struct {
	EntityID string   `xml:"entityID,attr"`
	Certs    []string `xml:"IDPSSODescriptor>KeyDescriptor>KeyInfo>X509Data>X509Certificate"`
}

// handleSSOIdPTest probes the stored record without touching Keycloak state:
// SAML metadata reachability + entityID + signing-cert expiry, or the OIDC
// discovery document's endpoints, plus the Keycloak admin connection. Bounded:
// 5s per fetch, 1 MiB per document.
func (s *server) handleSSOIdPTest(w http.ResponseWriter, r *http.Request, alias string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idp, ok := s.ssoIdPCfg.Get(alias)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var checks []ssoIdPCheck
	var certNotAfter *time.Time

	ping := s.kc.Ping(ctx)
	detail := ping.Detail
	if detail == "" {
		detail = "reachable"
		if ping.Version != "" {
			detail = "reachable, version " + ping.Version
		}
	}
	checks = append(checks, ssoIdPCheck{Name: "keycloak", OK: ping.OK(), Detail: detail})

	switch idp.Protocol {
	case "saml":
		raw := []byte(idp.MetadataXML)
		if idp.MetadataURL != "" {
			var err error
			if raw, err = ssoTestFetch(ctx, idp.MetadataURL); err != nil {
				checks = append(checks, ssoIdPCheck{Name: "metadata", Detail: err.Error()})
				break
			}
		}
		var md samlIdPMetadata
		if err := xml.Unmarshal(raw, &md); err != nil {
			checks = append(checks, ssoIdPCheck{Name: "metadata", Detail: "metadata does not parse as SAML EntityDescriptor: " + err.Error()})
			break
		}
		checks = append(checks, ssoIdPCheck{Name: "metadata", OK: md.EntityID != "", Detail: "entityID " + md.EntityID})
		notAfter, err := latestCertExpiry(md.Certs)
		switch {
		case err != nil:
			checks = append(checks, ssoIdPCheck{Name: "signing_cert", Detail: err.Error()})
		case notAfter == nil:
			checks = append(checks, ssoIdPCheck{Name: "signing_cert", Detail: "no signing certificate in metadata"})
		default:
			certNotAfter = notAfter
			checks = append(checks, ssoIdPCheck{
				Name: "signing_cert", OK: notAfter.After(time.Now()),
				Detail: "expires " + notAfter.UTC().Format(time.RFC3339),
			})
		}
	case "oidc":
		raw, err := ssoTestFetch(ctx, idp.DiscoveryURL)
		if err != nil {
			checks = append(checks, ssoIdPCheck{Name: "discovery", Detail: err.Error()})
			break
		}
		var disc struct {
			Issuer  string `json:"issuer"`
			AuthEP  string `json:"authorization_endpoint"`
			TokenEP string `json:"token_endpoint"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(raw, &disc); err != nil {
			checks = append(checks, ssoIdPCheck{Name: "discovery", Detail: "discovery document does not parse: " + err.Error()})
			break
		}
		ok := disc.Issuer != "" && disc.AuthEP != "" && disc.TokenEP != ""
		checks = append(checks, ssoIdPCheck{Name: "discovery", OK: ok, Detail: fmt.Sprintf(
			"issuer %s; authorization %s; token %s; jwks %s", disc.Issuer, disc.AuthEP, disc.TokenEP, disc.JWKSURI)})
	}

	allOK := true
	for _, c := range checks {
		allOK = allOK && c.OK
	}
	resp := map[string]any{"ok": allOK, "checks": checks}
	if certNotAfter != nil {
		resp["cert_not_after"] = certNotAfter.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ssoTestFetch GETs one probe document with a 5s budget and a 1 MiB cap;
// hitting the cap is an error, not a truncated success.
func ssoTestFetch(ctx context.Context, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, ssoTestFetchMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > ssoTestFetchMax {
		return nil, fmt.Errorf("document exceeds %d bytes", ssoTestFetchMax)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return b, nil
}

// latestCertExpiry parses the metadata's base64-DER certificates and returns
// the latest NotAfter (the active signing cert during a rollover).
func latestCertExpiry(certs []string) (*time.Time, error) {
	var latest *time.Time
	for _, c := range certs {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c), ""))
		if err != nil {
			return nil, fmt.Errorf("signing certificate does not decode: %w", err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("signing certificate does not parse: %w", err)
		}
		if latest == nil || parsed.NotAfter.After(*latest) {
			na := parsed.NotAfter
			latest = &na
		}
	}
	return latest, nil
}
