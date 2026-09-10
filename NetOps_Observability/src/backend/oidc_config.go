// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	"net/url"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"os"
	"strings"
	"sync"
	"time"

	// LICENCE-BEGIN
	"netops/backend/internal/entitlement"
	// LICENCE-END
	"netops/backend/internal/keycloak"
	"netops/backend/internal/oidc"
	"netops/backend/internal/ssoidp"
	"netops/backend/internal/tenantlocator"
	"netops/backend/internal/users"
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

// upsertProviderCSV reconciles one "alias:Label:kind[:access]" entry in the
// login-page provider list (oidc.ParseProviders format): replaced when present,
// appended when include and absent, dropped when !include.
//
// The fourth segment carries the ACCESS MODEL and is written only for an
// elevation door, so a standing provider's entry is byte-identical to what this
// function produced before elevation existed.
func upsertProviderCSV(csv, alias, label, kind, access string, include bool) string {
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.TrimSpace(strings.SplitN(raw, ":", 2)[0]) == alias {
			continue
		}
		out = append(out, raw)
	}
	if include {
		entry := alias + ":" + label + ":" + kind
		if strings.EqualFold(strings.TrimSpace(access), oidc.AccessElevation) {
			entry += ":" + oidc.AccessElevation
		}
		out = append(out, entry)
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
	// LICENCE-BEGIN — SAML is in the owner's LOCKED Enterprise set; OIDC is CORE
	// and always available at every tier, which is why this gate is on the
	// PROTOCOL and not on the route.
	//
	// It gates CONFIGURING a SAML connection, not signing in with one. Core
	// authentication must stay reachable in every licence state: a lapsed
	// licence that logged people out would be a licence problem touching
	// authentication, which the owner spec forbids outright.
	if strings.EqualFold(strings.TrimSpace(in.Protocol), "saml") {
		if err := entitlement.Require(s.entitlements, entitlement.FeatureSAML); err != nil {
			entitlement.WriteRefusal(w, err)
			return
		}
	}
	// LICENCE-END
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
	cfg.Providers = upsertProviderCSV(cfg.Providers, alias, idp.DisplayName, idp.Protocol, idp.KindOrStanding(), false)
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
		s.ssoClientRedirectURIs(base), []string{base})
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
	cfg.Providers = upsertProviderCSV(cfg.Providers, idp.Alias, idp.DisplayName, idp.Protocol, idp.KindOrStanding(), idp.Enabled)
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

// ---------------------------------------------------------------------------
// Per-tenant SSO URLs (design §6.1/§6.3, tracker 276)
// ---------------------------------------------------------------------------
//
// A connection bound to a tenant gets its OWN redirect URI:
//
//	/t/{tenant-slug}/sso/{alias}/callback        the URI handed to the IdP
//	/org/{org_public_id}/sso/{alias}/callback    the rename-proof twin
//	/t/{tenant-slug}/sso/{alias}/login           IdP-initiated entry (the tile URL)
//
// The URL is the BINDING. Before the ordinary callback runs, three things must
// agree: the realm named by the URL, the realm in the signed candidate cookie
// the browser got when it started this flow, and the realm the connection is
// registered to. A token replayed on another tenant's callback URL, or a
// provider that is not registered for the realm in the URL, is refused and
// audited — no session is ever minted.
//
// Connections that predate this feature carry no tenant. They keep the generic
// /api/auth/sso/callback exactly as before: an existing IdP registration must
// never have to change for an upgrade.

// handleTenantSSO serves the /t/… and /org/… SSO entry points. Public: it runs
// before any session exists, and it authenticates nothing itself — it only
// decides whether this URL may carry this provider's flow for this realm.
func (s *server) handleTenantSSO(w http.ResponseWriter, r *http.Request) {
	kind, ref, alias, leaf, ok := tenantlocator.ParseCallbackPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// 1. The realm named by the URL. Unknown or not-active is a plain 404 —
	//    identical for "no such tenant" and "that tenant is suspended".
	cand, ok := tenantlocator.Resolve(s.locatorDir(), kind, ref)
	if !ok {
		s.auditSSOBindingRefusal(r, "unknown or inactive locator", alias, "")
		http.NotFound(w, r)
		return
	}
	// 2. The connection must be BOUND TO THIS REALM. A per-tenant URL exists
	//    only for a tenant-bound connection: an alias nobody registered, one
	//    that is platform-realm (those keep the generic callback), and one
	//    belonging to another tenant are all refused here, identically.
	bound, isBound := s.connectionLocator(alias)
	if !isBound || !cand.Reaches(bound.TenantID, bound.OrgID) {
		s.auditSSOBindingRefusal(r, "provider not registered for this realm", alias, cand.TenantID)
		s.ssoLocatorRefuse(w, r, cand, ssoBindingRefusalMessage(alias, cand))
		return
	}
	switch leaf {
	case "login":
		// IdP-initiated / bookmark entry: pin the realm, then run the ordinary
		// SP-initiated flow through this provider. The browser never gets to
		// name the provider — the URL the IdP admin registered does.
		s.setLocatorCookie(w, r, cand)
		q := r.URL.Query()
		q.Set("idp", alias)
		r2 := r.Clone(r.Context())
		r2.URL = &url.URL{Path: r.URL.Path, RawQuery: q.Encode()}
		s.handleSSOLogin(w, r2)
	default: // "callback"
		// 3. The browser must have STARTED this flow in this realm. The signed
		//    candidate cookie is the proof; a token delivered to a browser that
		//    was never here, or that was here for a DIFFERENT tenant, dies now.
		held, ok := s.locatorCandidate(r)
		if !ok || held.Kind != cand.Kind || held.TenantID != cand.TenantID || held.OrgID != cand.OrgID {
			s.auditSSOBindingRefusal(r, "callback realm does not match the realm this browser signed in from", alias, cand.TenantID)
			s.ssoLocatorRefuse(w, r, cand,
				"This sign-in did not start at "+cand.DisplayName+". Open your organization's sign-in link and try again.")
			return
		}
		s.handleSSOCallback(w, r)
	}
}

// ssoLocatorRefuse sends the browser back to the realm's OWN sign-in page with
// an honest, named message. It never says which other tenant a provider belongs
// to — the caller is told what is wrong here, not what exists elsewhere.
func (s *server) ssoLocatorRefuse(w http.ResponseWriter, r *http.Request, c tenantlocator.Candidate, msg string) {
	frag := url.Values{}
	frag.Set("sso_error", msg)
	// c.Path() is composed by the server from a validated locator ("/t/<slug>"
	// or "/org/<id>"), never from request input; the guard below pins that
	// contract so this can never become a protocol-relative or absolute URL.
	target := c.Path()
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.ContainsAny(target, "\\\r\n") {
		target = "/"
	}
	http.Redirect(w, r, target+"#"+frag.Encode(), http.StatusFound) // #nosec G710 -- same-origin path, guarded above
}

// ssoBindingRefusalMessage is the ONE sentence every realm refusal says. It is
// one function so the two refusals that must be indistinguishable stay so: a
// provider that is not registered for this realm, and an account that does not
// belong to it. Anything more specific on the second case would hand a tenant
// administrator a cross-tenant username-existence oracle — type a name, read
// the error, learn whether another customer has that user. The real reason is
// recorded in the audit trail, which only an operator can read.
func ssoBindingRefusalMessage(alias string, c tenantlocator.Candidate) string {
	return "“" + alias + "” is not an identity provider for " + c.DisplayName + ". Ask your administrator for this organization's sign-in link."
}

// ssoCallbackRealm is the realm constraint a federated sign-in runs under.
//
// ONLY a tenant-bound callback carries one. A platform-realm connection keeps
// the generic /api/auth/sso/callback and legitimately signs in users of every
// tenant, so the zero Realm — no constraint — is what those flows get, exactly
// as before.
func (s *server) ssoCallbackRealm(r *http.Request) users.Realm {
	kind, ref, _, leaf, ok := tenantlocator.ParseCallbackPath(r.URL.Path)
	if !ok || leaf != "callback" {
		return users.Realm{}
	}
	cand, resolved := tenantlocator.Resolve(s.locatorDir(), kind, ref)
	if !resolved {
		// handleTenantSSO 404s an unresolvable locator before the callback runs,
		// so this is belt and braces — but the answer to "the URL names a realm I
		// cannot resolve" is to refuse, never to drop the constraint.
		return users.Realm{Reaches: func(string) bool { return false }}
	}
	return users.Realm{Reaches: func(accountTenant string) bool {
		return s.realmReachesAccount(cand, accountTenant)
	}}
}

// realmReachesAccount answers the question the user store cannot: does an
// account in this tenant belong to the realm the URL names? It uses the SAME
// Reaches helper the connection binding uses, so an /org/{id} locator still
// reaches every tenant its org owns.
func (s *server) realmReachesAccount(c tenantlocator.Candidate, accountTenant string) bool {
	t := strings.TrimSpace(accountTenant)
	if t == "" {
		// Reaches reads a BLANK tenant as the platform realm — right for a
		// provider registration (a shared front door), wrong for an ACCOUNT: it
		// would let any tenant's URL capture a tenant-less record. Fail closed.
		return false
	}
	// The account's org is known only to the tenant directory. An account whose
	// tenant no longer resolves (deleted, or suspended) reaches no realm.
	owner, ok := tenantlocator.ResolveID(s.locatorDir(), tenantlocator.KindTenant, t)
	if !ok {
		return false
	}
	return c.Reaches(t, owner.OrgID)
}

// ssoRefuseForeignRealm answers a sign-in whose ACCOUNT is not in the realm the
// URL names. The browser is told exactly what a mis-registered provider is told
// and not one byte more (see ssoBindingRefusalMessage); the real reason goes to
// the audit trail. The refusal deliberately lands AFTER the code exchange, so
// the two cases do not separate on timing either.
func (s *server) ssoRefuseForeignRealm(w http.ResponseWriter, r *http.Request, username string) {
	kind, ref, alias, _, parsed := tenantlocator.ParseCallbackPath(r.URL.Path)
	cand, resolved := tenantlocator.Resolve(s.locatorDir(), kind, ref)
	if !parsed || !resolved {
		// No realm to name. Refuse generically rather than inventing a message.
		s.ssoFail(w, r, "sign-in refused")
		return
	}
	logWarn("auth", "sso login refused — account is not in this realm", map[string]any{"user": username, "idp": alias, "src": "oidc"})
	s.auditSSOBindingRefusal(r, "account does not belong to the realm this connection is bound to", alias, cand.TenantID)
	s.ssoLocatorRefuse(w, r, cand, ssoBindingRefusalMessage(alias, cand))
}

// auditSSOBindingRefusal records a refused per-tenant callback. Every refusal is
// evidence: an attempt to replay a token onto another tenant's URL is exactly
// the event an investigator needs to see (§10 — no silent failures).
func (s *server) auditSSOBindingRefusal(r *http.Request, reason, alias, tenantID string) {
	logWarn("auth", "per-tenant sso callback refused", map[string]any{
		"reason": reason, "idp": alias, "path": r.URL.Path,
	})
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		Actor:    "anonymous",
		Tenant:   tenantID,
		Method:   r.Method,
		Path:     r.URL.Path,
		Decision: "deny",
		Remote:   auditClientIP(r),
		Detail:   map[string]any{"action": "sso.callback.binding_refused", "reason": reason, "idp": alias},
	})
}

// ssoLoginRedirectURI is the redirect_uri handed to the IdP when a login STARTS.
// A tenant-bound connection comes back to a per-tenant callback URL; everything
// else keeps the generic callback, unchanged.
//
// The URL names the realm the browser IS IN, not the connection's tenant. It
// used to name the connection's tenant unconditionally, which broke the
// /org/{org_public_id} locator outright — the immutable, rename-proof entry URL
// the admin page publishes as callback_url_immutable. A browser that started
// there was sent to the IdP with the /t/{slug} callback, so it returned to a
// TENANT URL holding a candidate cookie that said ORG, and ssoTenantCallback's
// realm check refused every one of those sign-ins at its own callback. An IdP
// registered with the immutable URL instead would have failed a step earlier,
// at the exchange, because the code exchange echoes the callback it landed on
// and that would never have matched the authorization request.
//
// The realm is server-derived either way — parsed from the locator path and
// resolved through the directory, or read from the HMAC-signed candidate cookie
// — and it must REACH the connection's binding, so the value can only ever be
// one of the callback URLs already enumerated for this connection in
// ssoClientRedirectURIs. Nothing the browser can assert widens it.
func (s *server) ssoLoginRedirectURI(r *http.Request, p *oidcProvider, alias string) string {
	c, ok := s.connectionLocator(alias)
	if !ok {
		return p.CallbackURL(r)
	}
	if entry, ok := s.ssoEntryRealm(r); ok && entry.Reaches(c.TenantID, c.OrgID) {
		if path := entry.CallbackPath(alias); path != "" {
			return ssoPublicBase(r) + path
		}
	}
	// No locator in play: an IdP-initiated flow through the generic entry, and
	// every deployment from before locators existed. The connection's own
	// tenant callback is what those registered.
	return ssoPublicBase(r) + c.CallbackPath(alias)
}

// ssoEntryRealm is the realm the browser started this flow in: the locator in
// the request path when the entry was /t/… or /org/…, and otherwise the signed
// candidate cookie the sign-in page armed. ok=false means the browser is on the
// generic front door with no realm pinned.
func (s *server) ssoEntryRealm(r *http.Request) (tenantlocator.Candidate, bool) {
	if kind, ref, _, _, ok := tenantlocator.ParseCallbackPath(r.URL.Path); ok {
		return tenantlocator.Resolve(s.locatorDir(), kind, ref)
	}
	return s.locatorCandidate(r)
}

// ssoCallbackRedirectURI is the same value re-derived at the callback, where the
// code exchange must echo the exact redirect_uri the authorization used. It is
// read from the REQUEST PATH: the IdP just sent the browser to that URL, and the
// binding checks above have already proved the path names the right realm.
func (s *server) ssoCallbackRedirectURI(r *http.Request, p *oidcProvider) string {
	if _, _, _, leaf, ok := tenantlocator.ParseCallbackPath(r.URL.Path); ok && leaf == "callback" {
		return ssoPublicBase(r) + r.URL.Path
	}
	return p.CallbackURL(r)
}

// ssoPostLoginPath is where the SPA is dropped after a per-tenant flow: back at
// the tenant's OWN sign-in URL, so a deep link into /t/{slug}/#/… returns to
// that path (the SPA restores the hash it stashed). Generic flows are unchanged.
func (s *server) ssoPostLoginPath(r *http.Request, p *oidcProvider) string {
	if kind, ref, _, leaf, ok := tenantlocator.ParseCallbackPath(r.URL.Path); ok && leaf == "callback" {
		if c, ok := tenantlocator.Resolve(s.locatorDir(), kind, ref); ok {
			return c.Path()
		}
	}
	return p.PostLoginURL()
}

// connectionLocator returns the canonical locator of the tenant a connection is
// bound to. ok=false for an unbound (platform-realm) connection — those keep the
// generic callback URL, which is what makes this change upgrade-safe.
func (s *server) connectionLocator(alias string) (tenantlocator.Candidate, bool) {
	tid, _, ok := s.providerRealm(alias)
	if !ok || tid == "" {
		return tenantlocator.Candidate{}, false
	}
	return tenantlocator.ResolveID(s.locatorDir(), tenantlocator.KindTenant, tid)
}

// ssoIDPAllowedForLocator gates the generic /api/auth/sso/login when the browser
// is carrying a candidate: a tenant may only start a flow through a provider its
// own realm reaches. Without a candidate nothing changes.
func (s *server) ssoIDPAllowedForLocator(r *http.Request, alias string) bool {
	c, ok := s.locatorCandidate(r)
	if !ok {
		return true
	}
	return s.providerVisible(&c, alias)
}

// ssoClientRedirectURIs is the exact set of redirect URIs the broker client may
// return to. The generic callback is always present (unbound connections, and
// every registration that predates per-tenant URLs). Each TENANT-BOUND
// connection adds its own two: the tenant form, which is the URI handed to the
// IdP, and the org form, which is the same door under the immutable org id so a
// slug rename does not strand a customer.
//
// Enumerated explicitly rather than wildcarded: an open redirect_uri pattern on
// the broker client is the classic way an authorization code is delivered
// somewhere it should never go.
func (s *server) ssoClientRedirectURIs(base string) []string {
	out := []string{base + "/api/auth/sso/callback"}
	if s.ssoIdPCfg == nil {
		return out
	}
	seen := map[string]bool{out[0]: true}
	for _, reg := range s.ssoIdPCfg.List() {
		c, ok := s.connectionLocator(reg.Alias)
		if !ok {
			continue
		}
		org := tenantlocator.Candidate{Kind: tenantlocator.KindOrg, OrgID: c.OrgID}
		for _, u := range []string{base + c.CallbackPath(reg.Alias), base + org.CallbackPath(reg.Alias)} {
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

// ssoProvisionTenant decides which tenant a NEWLY provisioned federated account
// belongs to. For a tenant-bound connection that is the tenant the OPERATOR
// bound the connection to, read from the callback URL the binding checks have
// already validated. Every other flow keeps the global OIDC default, unchanged.
//
// It never MOVES anyone: UpsertFederated leaves an existing federated account's
// tenant untouched, so the design's "a claim never moves a tenant" invariant
// holds — and this is not a claim at all, it is the operator's registration.
func (s *server) ssoProvisionTenant(r *http.Request, p *oidcProvider) string {
	if _, _, alias, leaf, ok := tenantlocator.ParseCallbackPath(r.URL.Path); ok && leaf == "callback" {
		if tid, _, ok := s.providerRealm(alias); ok && tid != "" {
			return tid
		}
	}
	return p.DefaultTenant()
}

// ---------------------------------------------------------------------------
// Tenant-managed identity providers (CLAUDE.md §3a, design §6.3, tracker 276)
// ---------------------------------------------------------------------------
//
// /api/auth/sso/idp is PLATFORM-GLOBAL plumbing and stays requirePlatformAdmin:
// it can create a connection in ANY realm, including the unbound platform-realm
// ones every tenant sees. This surface is the tenant-admin half of the same
// store: a tenant administrator manages the connections OF THEIR OWN TENANT and
// nothing else.
//
// The §3a rules, all enforced here:
//   - the owning tenant is stamped from the TOKEN, never from the payload;
//   - a list returns only the caller's own connections;
//   - a connection belonging to another tenant answers 404 on get/put/delete —
//     never 403, which would confirm the alias exists;
//   - an `as_tenant` selector can only ever narrow (principalTenant already
//     enforces that), and a non-owner's is ignored outright;
//   - an UNBOUND (platform-realm) connection is invisible and immutable here.

// tenantIdPBody is the wire type for a tenant-managed connection. It has NO
// tenant field ON PURPOSE: a tenant a caller could name is a tenant a caller
// could get wrong, so the binding is inexpressible in the request.
type tenantIdPBody struct {
	DisplayName    string               `json:"display_name"`
	Protocol       string               `json:"protocol"`
	Enabled        bool                 `json:"enabled"`
	MetadataURL    string               `json:"metadata_url,omitempty"`
	MetadataXML    string               `json:"metadata_xml,omitempty"`
	SigningCertPEM string               `json:"signing_cert_pem,omitempty"`
	DiscoveryURL   string               `json:"discovery_url,omitempty"`
	ClientID       string               `json:"client_id,omitempty"`
	ClientSecret   string               `json:"client_secret,omitempty"`
	GroupsAttr     string               `json:"groups_attr,omitempty"`
	AttrMappings   []ssoidp.AttrMapping `json:"attr_mappings,omitempty"`
	RoleMappings   []ssoidp.RoleMapping `json:"role_mappings,omitempty"`

	// Kind and Elevation are the ACCESS MODEL, and it is PLATFORM-GOVERNED
	// (§3a rule 3): a platform administrator may bind an elevation door to one
	// tenant, and this surface must never be able to turn it back into an
	// ordinary standing door. They are POINTERS so an absent field is
	// distinguishable from a submitted one: absent is carried forward from the
	// stored record, and a submitted value that DISAGREES with the stored one
	// is refused by name rather than ignored. Nothing here is ever written from
	// the body — these fields exist only so a round-tripped record can be saved
	// and a real change can be refused out loud.
	Kind      *string           `json:"kind,omitempty"`
	Elevation *ssoidp.Elevation `json:"elevation,omitempty"`
}

// tenantIdPAccessModel settles the access model of a tenant-admin save: the
// STORED one, always, plus a loud refusal when the body asks for another.
//
// A blank/absent kind reads as standing, exactly as the stored record does, so
// a client that never heard of the field saves normally. found=false is a
// creation, and a creation is standing: making an elevation door is a platform
// administrator's privilege, and the refusal for "you asked to create one" is
// word-for-word the refusal for "you asked to convert a standing one", so the
// answer never says whether the alias already exists.
func tenantIdPAccessModel(in tenantIdPBody, existing ssoidp.Config, found bool) (string, ssoidp.Elevation, error) {
	kind, elev := ssoidp.KindStanding, ssoidp.Elevation{}.Normalize()
	if found {
		kind, elev = existing.KindOrStanding(), existing.Elevation.Normalize()
	}
	if in.Kind != nil {
		want := strings.ToLower(strings.TrimSpace(*in.Kind))
		if want == "" {
			want = ssoidp.KindStanding
		}
		if want != kind {
			if kind == ssoidp.KindElevation {
				return "", ssoidp.Elevation{}, errors.New("this is a just-in-time elevation connection: only a platform administrator can change its access model. Send the save without \"kind\" to keep the rest of your changes, or set \"enabled\" to false to switch the connection off")
			}
			return "", ssoidp.Elevation{}, errors.New("only a platform administrator can make a just-in-time elevation connection. Send the save without \"kind\" to store this as an ordinary sign-in connection")
		}
	}
	if in.Elevation != nil && in.Elevation.Normalize() != elev {
		return "", ssoidp.Elevation{}, errors.New("the time limits of a just-in-time elevation connection are set by a platform administrator. Send the save without \"elevation\" to keep the rest of your changes")
	}
	return kind, elev, nil
}

// auditTenantIdPRefusal records a refused tenant-admin write. A refusal is
// evidence: an attempt to convert an elevation door into a standing one, or to
// delete it so the alias can be re-made as one, is exactly the event an
// investigator needs to see (§10 — no silent failures).
func (s *server) auditTenantIdPRefusal(r *http.Request, c jwtClaims, action, reason, alias, tenantID string) {
	logWarn("auth", "tenant sso idp write refused", map[string]any{
		"reason": reason, "idp": alias, "path": r.URL.Path,
	})
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		Actor:    c.Sub,
		Tenant:   tenantID,
		Method:   r.Method,
		Path:     r.URL.Path,
		Decision: "deny",
		Remote:   auditClientIP(r),
		Detail:   map[string]any{"action": action, "reason": reason, "idp": alias},
	})
}

// tenantIdPScope resolves the realm a tenant-admin request acts in: the caller's
// own tenant, taken from the token. A cross-tenant caller (the platform owner
// with no "view as tenant" selection) has no single realm to act in — reads
// span every bound connection, and a WRITE is refused until they pick a tenant,
// because silently choosing one for them is how a connection lands in the wrong
// customer's realm.
func (s *server) tenantIdPScope(claims jwtClaims) (tenantID string, cross bool) {
	return principalTenant(claims)
}

// tenantOwnsIdP reports whether a stored connection belongs to the caller's
// realm. An UNBOUND connection belongs to the platform realm and is owned by
// nobody here, so it is invisible on this surface at every scope.
func (s *server) tenantOwnsIdP(reg ssoidp.Config, tenantID string, cross bool) bool {
	realm := reg.Realm()
	if realm == "" {
		return false
	}
	if cross {
		return true
	}
	return realm == strings.ToLower(strings.TrimSpace(tenantID))
}

// handleTenantIdPList: GET /api/auth/sso/tenant-idp — this tenant's connections,
// each with the sign-in and callback URLs its IdP team needs.
func (s *server) handleTenantIdPList(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID, cross := s.tenantIdPScope(claims)
	out := []map[string]any{}
	if s.ssoIdPCfg != nil {
		for _, reg := range s.ssoIdPCfg.List() {
			if s.tenantOwnsIdP(reg, tenantID, cross) {
				out = append(out, s.tenantIdPView(r, reg))
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"idps": out, "sign_in_url": s.tenantSignInURL(r, tenantID, cross)})
}

// tenantIdPView is the redacted record plus the three URLs an IdP team pastes
// into Okta/Entra. The client secret never appears — Public() replaces it with a
// boolean, exactly as on the platform surface.
func (s *server) tenantIdPView(r *http.Request, reg ssoidp.Config) map[string]any {
	v := map[string]any{"idp": reg.Public()}
	if c, ok := s.connectionLocator(reg.Alias); ok {
		base := ssoPublicBase(r)
		org := tenantlocator.Candidate{Kind: tenantlocator.KindOrg, OrgID: c.OrgID}
		v["sign_in_url"] = base + c.Path()
		v["callback_url"] = base + c.CallbackPath(reg.Alias)
		v["callback_url_immutable"] = base + org.CallbackPath(reg.Alias)
		v["idp_initiated_url"] = base + c.LoginPath(reg.Alias)
	}
	return v
}

// tenantSignInURL is the customer-facing sign-in link for the caller's realm.
func (s *server) tenantSignInURL(r *http.Request, tenantID string, cross bool) string {
	if cross || strings.TrimSpace(tenantID) == "" {
		return ""
	}
	c, ok := tenantlocator.ResolveID(s.locatorDir(), tenantlocator.KindTenant, tenantID)
	if !ok {
		return ""
	}
	return ssoPublicBase(r) + c.Path()
}

// handleTenantIdPItem routes /api/auth/sso/tenant-idp/{alias} (GET/PUT/DELETE).
func (s *server) handleTenantIdPItem(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	alias := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/auth/sso/tenant-idp/")))
	if alias == "" || strings.Contains(alias, "/") {
		http.NotFound(w, r)
		return
	}
	tenantID, cross := s.tenantIdPScope(claims)
	switch r.Method {
	case http.MethodGet:
		reg, found := s.tenantIdPOwned(alias, tenantID, cross)
		if !found {
			http.NotFound(w, r) // unknown and someone-else's are the SAME answer
			return
		}
		writeJSON(w, http.StatusOK, s.tenantIdPView(r, reg))
	case http.MethodPut:
		s.handleTenantIdPPut(w, r, claims, alias)
	case http.MethodDelete:
		s.handleTenantIdPDelete(w, r, claims, alias, tenantID, cross)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// tenantIdPOwned fetches a connection only if the caller's realm owns it.
func (s *server) tenantIdPOwned(alias, tenantID string, cross bool) (ssoidp.Config, bool) {
	if s.ssoIdPCfg == nil {
		return ssoidp.Config{}, false
	}
	reg, found := s.ssoIdPCfg.Get(alias)
	if !found || !s.tenantOwnsIdP(reg, tenantID, cross) {
		return ssoidp.Config{}, false
	}
	return reg, true
}

// handleTenantIdPPut creates or edits a connection in the caller's own realm.
func (s *server) handleTenantIdPPut(w http.ResponseWriter, r *http.Request, claims jwtClaims, alias string) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10) // metadata cap + JSON overhead
	tenantID, cross := s.tenantIdPScope(claims)
	if cross {
		writeError(w, http.StatusBadRequest, errors.New("choose a tenant before adding an identity provider — a connection belongs to exactly one tenant"))
		return
	}
	if strings.TrimSpace(tenantID) == "" || tenantID == TenantGlobal {
		// The global realm IS the platform realm; its connections are platform
		// plumbing and stay on the platform-admin surface (§3a rule 3).
		writeError(w, http.StatusForbidden, errors.New("platform-realm identity providers are managed by a platform administrator"))
		return
	}
	if s.tenants != nil {
		if t, ok := s.tenants.Get(tenantID); !ok || t.EffectiveStatus() != TenantStatusActive {
			writeError(w, http.StatusForbidden, errors.New("this tenant cannot own an identity provider"))
			return
		}
	}
	var in tenantIdPBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// An alias is a Keycloak-wide path segment: it can name only ONE connection
	// on the whole broker. Taking one another tenant already holds answers 404,
	// the same as editing theirs would — the caller learns nothing either way.
	existing, found := s.ssoIdPCfg.Get(alias)
	if found && !s.tenantOwnsIdP(existing, tenantID, cross) {
		http.NotFound(w, r)
		return
	}
	// The access model comes from the STORED record, never from the body. Set()
	// is a full replace, so a field this surface does not carry forward is a
	// field this surface silently DELETES — which is how an elevation door
	// became a standing one that hands out permanent roles.
	kind, elev, err := tenantIdPAccessModel(in, existing, found)
	if err != nil {
		s.auditTenantIdPRefusal(r, claims, "sso.tenant_idp.access_model_refused", err.Error(), alias, tenantID)
		writeError(w, http.StatusForbidden, err)
		return
	}
	cfg := ssoidp.Config{
		Alias: alias, DisplayName: in.DisplayName, Protocol: in.Protocol, Enabled: in.Enabled,
		MetadataURL: in.MetadataURL, MetadataXML: in.MetadataXML, SigningCertPEM: in.SigningCertPEM,
		DiscoveryURL: in.DiscoveryURL, ClientID: in.ClientID, ClientSecret: in.ClientSecret,
		GroupsAttr: in.GroupsAttr, AttrMappings: in.AttrMappings, RoleMappings: in.RoleMappings,
		Kind: kind, Elevation: elev, // carried forward — platform-governed, see above
		TenantID: tenantID, // stamped from the token — the body cannot say otherwise
	}
	// LICENCE-BEGIN — SAML is in the LOCKED Enterprise set; OIDC is core. Gates
	// CONFIGURING a SAML connection, never signing in with one (see the platform
	// handler for the full reasoning).
	if strings.EqualFold(strings.TrimSpace(cfg.Protocol), "saml") {
		if err := entitlement.Require(s.entitlements, entitlement.FeatureSAML); err != nil {
			entitlement.WriteRefusal(w, err)
			return
		}
	}
	// LICENCE-END
	out, err := s.ssoIdPCfg.Set(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	warnings, err := s.applySSOIdP(r, out)
	if out.IsElevation() {
		// Say it, rather than let the record quietly disagree with whoever just
		// saved it: the response also carries kind and elevation in full.
		warnings = append(warnings, "this is a just-in-time elevation connection: its access model and time limits are set by a platform administrator and were kept unchanged by this save")
	}
	s.recordIdentityAudit(r, claims, "sso.tenant_idp.save", map[string]any{
		"idp": out.Alias, "protocol": out.Protocol, "enabled": out.Enabled,
		"tenant_id": out.TenantID, "kind": out.KindOrStanding(),
	})
	logInfo("auth", "tenant sso idp saved", map[string]any{
		"alias": out.Alias, "protocol": out.Protocol, "enabled": out.Enabled, "applied": err == nil,
	})
	view := s.tenantIdPView(r, out)
	if err != nil {
		warnings = append(warnings, "desired state saved but NOT applied to Keycloak — it will be re-applied on the next successful save")
		view["applied"] = false
		view["warnings"] = warnings
		view["error"] = err.Error()
		writeJSON(w, http.StatusBadGateway, view)
		return
	}
	view["applied"] = true
	view["warnings"] = warnings
	writeJSON(w, http.StatusOK, view)
}

// handleTenantIdPDelete removes one of the caller's own connections.
func (s *server) handleTenantIdPDelete(w http.ResponseWriter, r *http.Request, claims jwtClaims, alias, tenantID string, cross bool) {
	reg, found := s.tenantIdPOwned(alias, tenantID, cross)
	if !found {
		http.NotFound(w, r)
		return
	}
	// Delete is the OTHER way to change an access model: remove the elevation
	// door and re-create the same alias as a standing one, in two calls, with
	// the same result the carry-forward above refuses in one. An elevation
	// connection is a platform administrator's to remove; a tenant admin who
	// needs it stopped can still set enabled=false on it.
	if reg.IsElevation() {
		reason := "this is a just-in-time elevation connection: a platform administrator manages it. Set \"enabled\" to false if you need it switched off"
		s.auditTenantIdPRefusal(r, claims, "sso.tenant_idp.delete_refused", reason, alias, reg.Realm())
		writeError(w, http.StatusForbidden, errors.New(reason))
		return
	}
	s.recordIdentityAudit(r, claims, "sso.tenant_idp.delete", map[string]any{"idp": alias, "tenant_id": reg.Realm()})
	// Ownership is settled; the removal itself (Keycloak, the store, the
	// login-page button) is the SAME operation the platform surface performs —
	// delegate rather than keep a second copy that can drift out of step.
	s.handleSSOIdPDelete(w, r, alias)
}
