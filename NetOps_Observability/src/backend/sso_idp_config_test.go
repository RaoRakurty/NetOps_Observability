// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// sso_idp_config_test.go — HTTP tests for GUI-configurable SSO identity
// providers (oidc_config.go boundary over internal/ssoidp + internal/keycloak):
// the platform-admin gate, CRUD round-trip against a mock Keycloak admin API,
// write-only secret semantics, validation rejections (including the SR-025
// super-admin guard), the /test probe against mock IdP metadata, and the
// Keycloak-down 502 path. Store-level unit tests live in internal/ssoidp.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/keycloak"
	"netops/backend/internal/oidc"
	"netops/backend/internal/ssoidp"
)

// mockKC is a minimal stateful Keycloak admin API double for the apply path.
type mockKC struct {
	mu           sync.Mutex
	realm        bool
	client       map[string]any
	rolesInIDTok bool
	realmRoles   map[string]bool
	idps         map[string]map[string]any
	mappers      map[string][]map[string]any
}

func (m *mockKC) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 300})
	})
	mux.HandleFunc("/auth/admin/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/auth/admin")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		switch {
		case path == "/serverinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"systemInfo": map[string]any{"version": "25.0.0"}})
		case path == "/realms" && r.Method == http.MethodPost:
			m.realm = true
			w.WriteHeader(http.StatusCreated)
		case len(parts) == 2 && parts[0] == "realms":
			if !m.realm {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"realm": parts[1]})
		case len(parts) == 3 && parts[2] == "client-scopes":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": "scope-roles", "name": "roles",
				"protocolMappers": []map[string]any{{
					"id": "pm-1", "name": "realm roles", "protocolMapper": "oidc-usermodel-realm-role-mapper",
					"config": map[string]string{"access.token.claim": "true"},
				}},
			}})
		case len(parts) == 7 && parts[2] == "client-scopes" && r.Method == http.MethodPut:
			m.rolesInIDTok = true
			w.WriteHeader(http.StatusNoContent)
		case len(parts) == 3 && parts[2] == "clients" && r.Method == http.MethodGet:
			if m.client == nil {
				_ = json.NewEncoder(w).Encode([]map[string]any{})
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{m.client})
		case len(parts) == 3 && parts[2] == "clients" && r.Method == http.MethodPost:
			rep := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&rep)
			rep["id"] = "uuid-1"
			m.client = rep
			w.WriteHeader(http.StatusCreated)
		case len(parts) == 4 && parts[2] == "clients" && r.Method == http.MethodPut:
			rep := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&rep)
			m.client = rep
			w.WriteHeader(http.StatusNoContent)
		case len(parts) == 5 && parts[2] == "clients" && parts[4] == "client-secret":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": "kc-generated-secret"})
		case len(parts) == 4 && parts[2] == "roles" && r.Method == http.MethodGet:
			if !m.realmRoles[parts[3]] {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": parts[3]})
		case len(parts) == 3 && parts[2] == "roles" && r.Method == http.MethodPost:
			var rep struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&rep)
			if m.realmRoles == nil {
				m.realmRoles = map[string]bool{}
			}
			m.realmRoles[rep.Name] = true
			w.WriteHeader(http.StatusCreated)
		case len(parts) == 4 && parts[3] == "import-config":
			_ = json.NewEncoder(w).Encode(map[string]string{"singleSignOnServiceUrl": "https://idp/sso"})
		case len(parts) == 4 && parts[3] == "instances" && r.Method == http.MethodPost:
			rep := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&rep)
			if m.idps == nil {
				m.idps = map[string]map[string]any{}
			}
			m.idps[rep["alias"].(string)] = rep
			w.WriteHeader(http.StatusCreated)
		case len(parts) == 5 && parts[3] == "instances":
			alias := parts[4]
			switch r.Method {
			case http.MethodGet:
				rep, ok := m.idps[alias]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(rep)
			case http.MethodPut:
				rep := map[string]any{}
				_ = json.NewDecoder(r.Body).Decode(&rep)
				m.idps[alias] = rep
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				if _, ok := m.idps[alias]; !ok {
					http.NotFound(w, r)
					return
				}
				delete(m.idps, alias)
				w.WriteHeader(http.StatusNoContent)
			}
		case len(parts) == 6 && parts[5] == "mappers":
			alias := parts[4]
			switch r.Method {
			case http.MethodGet:
				list := m.mappers[alias]
				if list == nil {
					list = []map[string]any{}
				}
				_ = json.NewEncoder(w).Encode(list)
			case http.MethodPost:
				rep := map[string]any{}
				_ = json.NewDecoder(r.Body).Decode(&rep)
				rep["id"] = "m-" + rep["name"].(string)
				if m.mappers == nil {
					m.mappers = map[string][]map[string]any{}
				}
				m.mappers[alias] = append(m.mappers[alias], rep)
				w.WriteHeader(http.StatusCreated)
			}
		case len(parts) == 7 && parts[5] == "mappers" && r.Method == http.MethodDelete:
			alias, id := parts[4], parts[6]
			list := m.mappers[alias]
			for i, mm := range list {
				if mm["id"] == id {
					m.mappers[alias] = append(list[:i:i], list[i+1:]...)
					break
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

// newSSOIdPServer wires a full test server (real router + auth middleware) with
// the SSO IdP store and an admin client pointed at the mock Keycloak.
func newSSOIdPServer(t *testing.T) (*httptest.Server, *server, *mockKC) {
	t.Helper()
	srv, s := newTestServerState(t)
	dir := t.TempDir()
	s.oidcCfg = newOIDCConfigStore(dir+"/oidc_config.json", s)
	s.oidc.Store(oidc.NewProviderFromConfig(newOIDCConfigFromEnv(), jwksTTL()))
	s.ssoIdPCfg = ssoidp.NewStore(dir+"/sso_idp_config.json", ssoidp.Deps{
		RoleValid:          func(role string) bool { _, ok := s.roles.Get(role); return ok },
		AllowPlatformOwner: func() bool { return os.Getenv("FEDERATION_ALLOW_PLATFORM_OWNER") == "true" },
		Errorf:             logError,
	})
	kc := &mockKC{}
	kcSrv := httptest.NewServer(kc.handler())
	t.Cleanup(kcSrv.Close)
	s.kc = keycloak.New(keycloak.Config{
		BaseURL: kcSrv.URL + "/auth", AdminUser: "admin", AdminPassword: "pw",
		Realm: "correlix", Timeout: 5 * time.Second,
	})
	return srv, s, kc
}

func samlIdPBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"display_name": "Okta",
		"protocol":     "saml",
		"enabled":      true,
		"metadata_xml": `<EntityDescriptor entityID="https://okta.example.com/exk1"><IDPSSODescriptor/></EntityDescriptor>`,
		"role_mappings": []map[string]string{
			{"value": "correlix-ops", "role": "operator"},
		},
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func TestSSOIdPPlatformAdminGate(t *testing.T) {
	srv, _, _ := newSSOIdPServer(t)
	admin := adminToken(t, srv)

	// A tenant-scoped admin holds administration:admin but is NOT the platform
	// owner — every SSO IdP surface must refuse it.
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme"})
	if st != 201 && st != 200 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "acme-admin", "password": "Passw0rd!2345", "role": RoleSuperAdmin, "tenant_id": tenantID,
	}); st != 201 && st != 200 {
		t.Fatalf("create tenant admin: %d %s", st, b)
	}
	tok := login(t, srv, "acme-admin", "Passw0rd!2345").Token

	for _, c := range []struct{ method, path string }{
		{"GET", "/api/auth/sso/idp"},
		{"PUT", "/api/auth/sso/idp/okta-saml"},
		{"DELETE", "/api/auth/sso/idp/okta-saml"},
		{"POST", "/api/auth/sso/idp/okta-saml/test"},
	} {
		if st, _ := do(t, srv, c.method, c.path, tok, samlIdPBody(nil)); st != http.StatusForbidden {
			t.Errorf("%s %s as tenant admin: status %d, want 403", c.method, c.path, st)
		}
		if st, _ := do(t, srv, c.method, c.path, "", nil); st != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated: status %d, want 401", c.method, c.path, st)
		}
	}
}

func TestSSOIdPCRUDRoundTripAppliesToKeycloak(t *testing.T) {
	srv, s, kc := newSSOIdPServer(t)
	admin := adminToken(t, srv)

	st, b := do(t, srv, "PUT", "/api/auth/sso/idp/okta-saml", admin, samlIdPBody(nil))
	if st != 200 {
		t.Fatalf("PUT: %d %s", st, b)
	}
	var putResp struct {
		IdP      ssoIdPPublic `json:"idp"`
		Applied  bool         `json:"applied"`
		Warnings []string     `json:"warnings"`
	}
	if err := json.Unmarshal(b, &putResp); err != nil {
		t.Fatal(err)
	}
	if !putResp.Applied {
		t.Fatalf("applied=false: %s", b)
	}
	if putResp.IdP.Alias != "okta-saml" || putResp.IdP.Protocol != "saml" {
		t.Fatalf("idp echo wrong: %+v", putResp.IdP)
	}

	// Keycloak side: realm, ID-token roles fix, client, realm role, IdP, mappers.
	kc.mu.Lock()
	if !kc.realm {
		t.Error("realm not created")
	}
	if !kc.rolesInIDTok {
		t.Error("realm-roles mapper not flipped into the ID token (silent read-only path 1)")
	}
	if kc.client == nil || kc.client["clientId"] != "netops" || kc.client["publicClient"] != false {
		t.Errorf("client wrong: %v", kc.client)
	}
	if !kc.realmRoles["operator"] {
		t.Errorf("realm role not ensured: %v", kc.realmRoles)
	}
	idp := kc.idps["okta-saml"]
	if idp == nil {
		t.Fatal("identity provider not created")
	}
	cfg, _ := idp["config"].(map[string]any)
	entityID, _ := cfg["entityId"].(string)
	if !strings.HasSuffix(entityID, "/auth/realms/correlix") {
		t.Errorf("entityId = %q, want …/auth/realms/correlix", entityID)
	}
	mapperNames := map[string]bool{}
	for _, m := range kc.mappers["okta-saml"] {
		mapperNames[m["name"].(string)] = true
	}
	kc.mu.Unlock()
	for _, want := range []string{
		keycloak.ManagedPrefix + "attr-email",
		keycloak.ManagedPrefix + "attr-firstName",
		keycloak.ManagedPrefix + "attr-lastName",
		keycloak.ManagedPrefix + "role-correlix-ops-operator",
	} {
		if !mapperNames[want] {
			t.Errorf("mapper %q not created; have %v", want, mapperNames)
		}
	}

	// RP side auto-wired: issuer, client id/secret, provider button, role lists.
	rp := s.oidcCfg.effective()
	if !rp.Enabled || !strings.HasSuffix(rp.Issuer, "/auth/realms/correlix") {
		t.Errorf("RP not wired: enabled=%v issuer=%q", rp.Enabled, rp.Issuer)
	}
	if rp.ClientID != "netops" || rp.ClientSecret != "kc-generated-secret" {
		t.Errorf("RP client not wired: %q / secret set=%v", rp.ClientID, rp.ClientSecret != "")
	}
	if !strings.Contains(rp.Providers, "okta-saml:Okta:saml") {
		t.Errorf("provider button missing: %q", rp.Providers)
	}
	if !strings.Contains(rp.OperatorRoles, "operator") {
		t.Errorf("operator role list missing mapped role: %q", rp.OperatorRoles)
	}

	// List: redacted view + keycloak summary.
	st, b = do(t, srv, "GET", "/api/auth/sso/idp", admin, nil)
	if st != 200 {
		t.Fatalf("GET list: %d %s", st, b)
	}
	var list struct {
		IdPs     []ssoIdPPublic      `json:"idps"`
		Keycloak keycloak.PingResult `json:"keycloak"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.IdPs) != 1 || list.IdPs[0].Alias != "okta-saml" {
		t.Fatalf("list = %+v", list.IdPs)
	}
	if !list.Keycloak.Reachable || !list.Keycloak.RealmExists {
		t.Fatalf("keycloak summary = %+v", list.Keycloak)
	}

	// DELETE: gone from Keycloak, the store, and the login-page provider list.
	if st, b = do(t, srv, "DELETE", "/api/auth/sso/idp/okta-saml", admin, nil); st != 200 {
		t.Fatalf("DELETE: %d %s", st, b)
	}
	kc.mu.Lock()
	_, still := kc.idps["okta-saml"]
	kc.mu.Unlock()
	if still {
		t.Error("identity provider not removed from keycloak")
	}
	if _, ok := s.ssoIdPCfg.Get("okta-saml"); ok {
		t.Error("idp not removed from store")
	}
	if p := s.oidcCfg.effective().Providers; strings.Contains(p, "okta-saml") {
		t.Errorf("provider button not removed: %q", p)
	}
	if st, _ = do(t, srv, "DELETE", "/api/auth/sso/idp/okta-saml", admin, nil); st != 404 {
		t.Errorf("second DELETE: %d, want 404", st)
	}
}

func TestSSOIdPSecretWriteOnly(t *testing.T) {
	srv, s, kc := newSSOIdPServer(t)
	admin := adminToken(t, srv)
	body := map[string]any{
		"display_name": "Okta OIDC", "protocol": "oidc", "enabled": true,
		"discovery_url": "https://okta.example.com/.well-known/openid-configuration",
		"client_id":     "cid", "client_secret": "s3cret-value",
	}
	st, b := do(t, srv, "PUT", "/api/auth/sso/idp/okta-oidc", admin, body)
	if st != 200 {
		t.Fatalf("PUT: %d %s", st, b)
	}
	if strings.Contains(string(b), "s3cret-value") {
		t.Fatal("PUT response leaks the client secret")
	}
	st, b = do(t, srv, "GET", "/api/auth/sso/idp/okta-oidc", admin, nil)
	if st != 200 || strings.Contains(string(b), "s3cret-value") {
		t.Fatalf("GET leaks the secret or failed: %d %s", st, b)
	}
	if !strings.Contains(string(b), `"client_secret_set":true`) {
		t.Fatalf("client_secret_set missing: %s", b)
	}

	// Redacted round-trip (no client_secret) must PRESERVE the stored secret.
	delete(body, "client_secret")
	body["display_name"] = "Okta OIDC v2"
	if st, b = do(t, srv, "PUT", "/api/auth/sso/idp/okta-oidc", admin, body); st != 200 {
		t.Fatalf("second PUT: %d %s", st, b)
	}
	stored, ok := s.ssoIdPCfg.Get("okta-oidc")
	if !ok || stored.ClientSecret != "s3cret-value" {
		t.Fatalf("secret not preserved: %+v", stored.Public())
	}
	if stored.DisplayName != "Okta OIDC v2" {
		t.Fatalf("update lost: %q", stored.DisplayName)
	}
	// And the broker got the real secret both times.
	kc.mu.Lock()
	defer kc.mu.Unlock()
	cfg, _ := kc.idps["okta-oidc"]["config"].(map[string]any)
	if cfg["clientSecret"] != "s3cret-value" {
		t.Fatalf("broker clientSecret = %v", cfg["clientSecret"])
	}
}

func TestSSOIdPValidationRejections(t *testing.T) {
	srv, _, _ := newSSOIdPServer(t)
	admin := adminToken(t, srv)
	cases := []struct {
		name    string
		alias   string
		mutate  map[string]any
		wantErr string
	}{
		{"bad alias", "Okta_SAML!", nil, "alias"},
		{"both metadata sources", "okta-saml", map[string]any{"metadata_url": "https://okta.example.com/metadata"}, "exactly one"},
		{"no metadata source", "okta-saml", map[string]any{"metadata_xml": ""}, "exactly one"},
		{"oidc missing client", "okta-oidc", map[string]any{
			"protocol": "oidc", "metadata_xml": "", "discovery_url": "https://x.example.com/.well-known/openid-configuration",
		}, "client_id"},
		{"non-http metadata url", "okta-saml", map[string]any{
			"metadata_xml": "", "metadata_url": "ftp://okta.example.com/metadata",
		}, "http(s)"},
		{"unknown role", "okta-saml", map[string]any{
			"role_mappings": []map[string]string{{"value": "g", "role": "warlord"}},
		}, "unknown role"},
		{"super-admin guard", "okta-saml", map[string]any{
			"role_mappings": []map[string]string{{"value": "correlix-admins", "role": "super-admin"}},
		}, "FEDERATION_ALLOW_PLATFORM_OWNER"},
	}
	for _, c := range cases {
		st, b := do(t, srv, "PUT", "/api/auth/sso/idp/"+c.alias, admin, samlIdPBody(c.mutate))
		if st != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", c.name, st, b)
			continue
		}
		if !strings.Contains(string(b), c.wantErr) {
			t.Errorf("%s: error %s does not mention %q", c.name, b, c.wantErr)
		}
	}
	// The super-admin guard message must explain the silent downgrade.
	_, b := do(t, srv, "PUT", "/api/auth/sso/idp/okta-saml", admin, samlIdPBody(map[string]any{
		"role_mappings": []map[string]string{{"value": "correlix-admins", "role": "super-admin"}},
	}))
	if !strings.Contains(string(b), "DOWNGRADED") || !strings.Contains(string(b), "guardFederatedRole") {
		t.Errorf("guard message must explain the SR-025 downgrade: %s", b)
	}

	// With the explicit opt-in the same mapping is accepted.
	t.Setenv("FEDERATION_ALLOW_PLATFORM_OWNER", "true")
	st, b := do(t, srv, "PUT", "/api/auth/sso/idp/okta-saml", admin, samlIdPBody(map[string]any{
		"role_mappings": []map[string]string{{"value": "correlix-admins", "role": "super-admin"}},
	}))
	if st != 200 {
		t.Fatalf("opt-in PUT: %d %s", st, b)
	}
	if !strings.Contains(string(b), "PLATFORM OWNERS") {
		t.Errorf("opt-in save should warn about platform-owner federation: %s", b)
	}
}

// testCertPEMAndB64 builds a self-signed cert, returning its metadata base64.
func testCertB64(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "okta-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestSSOIdPTestEndpoint(t *testing.T) {
	srv, _, _ := newSSOIdPServer(t)
	admin := adminToken(t, srv)
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	metadata := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://okta.example.com/exk1">
  <md:IDPSSODescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:X509Data><ds:X509Certificate>` + testCertB64(t, notAfter) + `</ds:X509Certificate></ds:X509Data>
  </ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>`
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(metadata))
	}))
	t.Cleanup(idpSrv.Close)

	st, b := do(t, srv, "PUT", "/api/auth/sso/idp/okta-saml", admin, samlIdPBody(map[string]any{
		"metadata_xml": "", "metadata_url": idpSrv.URL + "/metadata",
	}))
	if st != 200 {
		t.Fatalf("PUT: %d %s", st, b)
	}
	st, b = do(t, srv, "POST", "/api/auth/sso/idp/okta-saml/test", admin, nil)
	if st != 200 {
		t.Fatalf("test: %d %s", st, b)
	}
	var res struct {
		OK           bool          `json:"ok"`
		Checks       []ssoIdPCheck `json:"checks"`
		CertNotAfter string        `json:"cert_not_after"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("probe not ok: %s", b)
	}
	byName := map[string]ssoIdPCheck{}
	for _, c := range res.Checks {
		byName[c.Name] = c
	}
	if !byName["keycloak"].OK || !byName["metadata"].OK || !byName["signing_cert"].OK {
		t.Fatalf("checks = %+v", res.Checks)
	}
	if !strings.Contains(byName["metadata"].Detail, "https://okta.example.com/exk1") {
		t.Errorf("metadata detail missing entityID: %q", byName["metadata"].Detail)
	}
	if res.CertNotAfter != notAfter.Format(time.RFC3339) {
		t.Errorf("cert_not_after = %q, want %q", res.CertNotAfter, notAfter.Format(time.RFC3339))
	}
	// Unknown alias → 404.
	if st, _ = do(t, srv, "POST", "/api/auth/sso/idp/ghost/test", admin, nil); st != 404 {
		t.Errorf("test unknown alias: %d, want 404", st)
	}
}

func TestSSOIdPKeycloakDownPersistsAndAnswers502(t *testing.T) {
	srv, s, _ := newSSOIdPServer(t)
	admin := adminToken(t, srv)
	// Point the admin client at a dead endpoint.
	s.kc = keycloak.New(keycloak.Config{
		BaseURL: "http://127.0.0.1:1/auth", AdminUser: "a", AdminPassword: "b",
		Realm: "correlix", Timeout: time.Second,
	})
	st, b := do(t, srv, "PUT", "/api/auth/sso/idp/okta-saml", admin, samlIdPBody(nil))
	if st != http.StatusBadGateway {
		t.Fatalf("PUT with keycloak down: %d %s", st, b)
	}
	var resp struct {
		Applied  bool     `json:"applied"`
		Warnings []string `json:"warnings"`
		Error    string   `json:"error"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Applied || resp.Error == "" || len(resp.Warnings) == 0 {
		t.Fatalf("502 body = %s", b)
	}
	// The desired state survived the outage — the save is not lost.
	if _, ok := s.ssoIdPCfg.Get("okta-saml"); !ok {
		t.Fatal("desired state was not persisted")
	}
}
