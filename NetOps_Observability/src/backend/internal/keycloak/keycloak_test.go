// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package keycloak

// keycloak_test.go — unit tests over an httptest.Server mocking the Keycloak 25
// admin API: token caching + refresh-on-401, ensure-idempotency (existing vs
// absent), SAML metadata import-config, mapper reconciliation including
// deletion of removed mappings, retry-on-5xx and no-retry-on-4xx.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKC is a minimal stateful Keycloak admin API double.
type fakeKC struct {
	mu sync.Mutex

	tokenRequests int
	tokenValue    string
	expireToken   bool // answer 401 to the next admin call, then accept the refreshed token

	realms      map[string]bool
	clients     map[string]map[string]any // uuid → rep
	secrets     map[string]string         // uuid → secret
	roles       map[string]bool
	idps        map[string]map[string]any // alias → rep
	idpMappers  map[string][]idpMapper    // alias → mappers
	scopeMapper protocolMapper            // the "realm roles" mapper

	importConfigCalls []string // content types seen on import-config

	failuresLeft int  // answer 503 this many times before succeeding
	badRequest   bool // answer 400 to every admin call
	attempts     int  // admin-call attempts observed (incl. failures)
}

func newFakeKC() *fakeKC {
	return &fakeKC{
		tokenValue: "tok-1",
		realms:     map[string]bool{},
		clients:    map[string]map[string]any{},
		secrets:    map[string]string{},
		roles:      map[string]bool{},
		idps:       map[string]map[string]any{},
		idpMappers: map[string][]idpMapper{},
		scopeMapper: protocolMapper{
			ID: "pm-1", Name: "realm roles", ProtocolMapper: "oidc-usermodel-realm-role-mapper",
			Config: map[string]string{"access.token.claim": "true", "id.token.claim": "false"},
		},
	}
}

func writeOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeKC) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenRequests++
		writeOK(w, map[string]any{"access_token": f.tokenValue, "expires_in": 300})
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.attempts++
		if f.badRequest {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		if f.failuresLeft > 0 {
			f.failuresLeft--
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if f.expireToken {
			f.expireToken = false
			f.tokenValue = "tok-2"
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		if auth != f.tokenValue {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		f.route(w, r)
	})
	return mux
}

// route implements the admin endpoints the reconciler touches. Callers hold f.mu.
func (f *fakeKC) route(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case path == "/serverinfo":
		writeOK(w, map[string]any{"systemInfo": map[string]any{"version": "25.0.0"}})

	case path == "/realms" && r.Method == http.MethodPost:
		var rep struct {
			Realm string `json:"realm"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.realms[rep.Realm] = true
		w.WriteHeader(http.StatusCreated)

	case len(parts) == 2 && parts[0] == "realms" && r.Method == http.MethodGet:
		if !f.realms[parts[1]] {
			http.NotFound(w, r)
			return
		}
		writeOK(w, map[string]any{"realm": parts[1]})

	case len(parts) == 3 && parts[2] == "clients" && r.Method == http.MethodGet:
		want := r.URL.Query().Get("clientId")
		var out []map[string]any
		for _, rep := range f.clients {
			if rep["clientId"] == want || want == "" {
				out = append(out, rep)
			}
		}
		writeOK(w, out)

	case len(parts) == 3 && parts[2] == "clients" && r.Method == http.MethodPost:
		rep := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&rep)
		id := "uuid-" + rep["clientId"].(string)
		rep["id"] = id
		f.clients[id] = rep
		f.secrets[id] = "secret-" + rep["clientId"].(string)
		w.WriteHeader(http.StatusCreated)

	case len(parts) == 4 && parts[2] == "clients" && r.Method == http.MethodPut:
		rep := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.clients[parts[3]] = rep
		w.WriteHeader(http.StatusNoContent)

	case len(parts) == 5 && parts[2] == "clients" && parts[4] == "client-secret":
		writeOK(w, map[string]any{"type": "secret", "value": f.secrets[parts[3]]})

	case len(parts) == 3 && parts[2] == "client-scopes" && r.Method == http.MethodGet:
		writeOK(w, []map[string]any{{
			"id": "scope-roles", "name": "roles",
			"protocolMappers": []protocolMapper{f.scopeMapper},
		}})

	case len(parts) == 6 && parts[2] == "client-scopes" && parts[4] == "protocol-mappers" && r.Method == http.MethodPut:
		// .../client-scopes/{sid}/protocol-mappers/models/{mid} has 7 parts; accept both
		fallthrough
	case len(parts) == 7 && parts[2] == "client-scopes" && r.Method == http.MethodPut:
		var m protocolMapper
		_ = json.NewDecoder(r.Body).Decode(&m)
		f.scopeMapper = m
		w.WriteHeader(http.StatusNoContent)

	case len(parts) == 4 && parts[2] == "roles" && r.Method == http.MethodGet:
		if !f.roles[parts[3]] {
			http.NotFound(w, r)
			return
		}
		writeOK(w, map[string]any{"name": parts[3]})

	case len(parts) == 3 && parts[2] == "roles" && r.Method == http.MethodPost:
		var rep struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.roles[rep.Name] = true
		w.WriteHeader(http.StatusCreated)

	case len(parts) == 4 && parts[2] == "identity-provider" && parts[3] == "import-config":
		f.importConfigCalls = append(f.importConfigCalls, r.Header.Get("Content-Type"))
		writeOK(w, map[string]string{
			"singleSignOnServiceUrl": "https://idp.example.com/sso",
			"entityId":               "https://imported.example.com/realm", // overridden by the reconciler
			"validateSignature":      "true",
		})

	case len(parts) == 4 && parts[2] == "identity-provider" && parts[3] == "instances" && r.Method == http.MethodPost:
		rep := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.idps[rep["alias"].(string)] = rep
		w.WriteHeader(http.StatusCreated)

	case len(parts) == 5 && parts[3] == "instances":
		alias := parts[4]
		switch r.Method {
		case http.MethodGet:
			rep, ok := f.idps[alias]
			if !ok {
				http.NotFound(w, r)
				return
			}
			writeOK(w, rep)
		case http.MethodPut:
			rep := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&rep)
			f.idps[alias] = rep
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if _, ok := f.idps[alias]; !ok {
				http.NotFound(w, r)
				return
			}
			delete(f.idps, alias)
			w.WriteHeader(http.StatusNoContent)
		}

	case len(parts) == 6 && parts[3] == "instances" && parts[5] == "mappers":
		alias := parts[4]
		switch r.Method {
		case http.MethodGet:
			writeOK(w, f.idpMappers[alias])
		case http.MethodPost:
			var m idpMapper
			_ = json.NewDecoder(r.Body).Decode(&m)
			m.ID = "m-" + m.Name
			f.idpMappers[alias] = append(f.idpMappers[alias], m)
			w.WriteHeader(http.StatusCreated)
		}

	case len(parts) == 7 && parts[3] == "instances" && parts[5] == "mappers":
		alias, id := parts[4], parts[6]
		list := f.idpMappers[alias]
		for i, m := range list {
			if m.ID != id {
				continue
			}
			switch r.Method {
			case http.MethodPut:
				var upd idpMapper
				_ = json.NewDecoder(r.Body).Decode(&upd)
				upd.ID = id
				list[i] = upd
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				f.idpMappers[alias] = append(list[:i:i], list[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		http.NotFound(w, r)

	default:
		http.NotFound(w, r)
	}
}

func newTestClient(t *testing.T, f *fakeKC) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c := New(Config{
		BaseURL: srv.URL, AdminUser: "admin", AdminPassword: "pw", Realm: "correlix",
		Timeout: 5 * time.Second,
	})
	c.sleep = func(time.Duration) {} // no real backoff waits in tests
	return c
}

func TestTokenCachedAcrossCalls(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	f.mu.Lock()
	f.realms["correlix"] = true
	f.mu.Unlock()
	for i := 0; i < 3; i++ {
		if err := c.EnsureRealm(context.Background(), "correlix"); err != nil {
			t.Fatalf("EnsureRealm: %v", err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1 (cached until expiry)", f.tokenRequests)
	}
}

func TestReauthOnceOn401(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	f.mu.Lock()
	f.realms["correlix"] = true
	f.mu.Unlock()
	if err := c.EnsureRealm(context.Background(), "correlix"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	f.mu.Lock()
	f.expireToken = true // the cached tok-1 is now stale; server expects tok-2 next
	f.mu.Unlock()
	if err := c.EnsureRealm(context.Background(), "correlix"); err != nil {
		t.Fatalf("EnsureRealm after expiry: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenRequests != 2 {
		t.Fatalf("token requests = %d, want 2 (one refresh after the 401)", f.tokenRequests)
	}
}

func TestEnsureRealmCreatesWhenAbsent(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	if err := c.EnsureRealm(context.Background(), "correlix"); err != nil {
		t.Fatalf("EnsureRealm: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.realms["correlix"] {
		t.Fatal("realm was not created")
	}
}

func TestEnsureClientCreateAndUpdate(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	ctx := context.Background()
	secret, err := c.EnsureClient(ctx, "correlix", "netops",
		[]string{"https://x/api/auth/sso/callback"}, []string{"https://x"})
	if err != nil {
		t.Fatalf("EnsureClient (create): %v", err)
	}
	if secret != "secret-netops" {
		t.Fatalf("secret = %q, want secret-netops", secret)
	}
	// Second call must UPDATE, not duplicate, and keep returning the secret.
	secret, err = c.EnsureClient(ctx, "correlix", "netops",
		[]string{"https://y/api/auth/sso/callback"}, []string{"https://y"})
	if err != nil {
		t.Fatalf("EnsureClient (update): %v", err)
	}
	if secret != "secret-netops" {
		t.Fatalf("secret after update = %q", secret)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.clients) != 1 {
		t.Fatalf("clients = %d, want 1 (idempotent)", len(f.clients))
	}
	rep := f.clients["uuid-netops"]
	uris, _ := rep["redirectUris"].([]any)
	if len(uris) != 1 || uris[0] != "https://y/api/auth/sso/callback" {
		t.Fatalf("redirectUris not updated: %v", rep["redirectUris"])
	}
	if rep["publicClient"] != false {
		t.Fatal("client must stay confidential")
	}
}

func TestEnsureRolesInIDToken(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	if err := c.EnsureRolesInIDToken(context.Background(), "correlix"); err != nil {
		t.Fatalf("EnsureRolesInIDToken: %v", err)
	}
	f.mu.Lock()
	cfg := f.scopeMapper.Config
	f.mu.Unlock()
	if cfg["id.token.claim"] != "true" || cfg["access.token.claim"] != "true" {
		t.Fatalf("realm-roles mapper config = %v, want id+access token claims true", cfg)
	}
	// Idempotent: a second call must not rewrite the mapper.
	f.mu.Lock()
	before := f.attempts
	f.mu.Unlock()
	if err := c.EnsureRolesInIDToken(context.Background(), "correlix"); err != nil {
		t.Fatalf("second EnsureRolesInIDToken: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attempts != before+1 { // exactly one GET, no PUT
		t.Fatalf("expected a read-only second pass, got %d extra calls", f.attempts-before)
	}
}

func TestEnsureIdentityProviderSAMLFromXML(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	idp := IdP{
		Alias: "okta-saml", DisplayName: "Okta", Protocol: "saml", Enabled: true,
		MetadataXML: `<EntityDescriptor entityID="https://okta.example.com"/>`,
		EntityID:    "https://correlix.example.com/auth/realms/correlix",
	}
	if err := c.EnsureIdentityProvider(context.Background(), "correlix", idp); err != nil {
		t.Fatalf("EnsureIdentityProvider: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.importConfigCalls) != 1 || !strings.HasPrefix(f.importConfigCalls[0], "multipart/form-data") {
		t.Fatalf("raw-XML import must POST multipart import-config, got %v", f.importConfigCalls)
	}
	rep := f.idps["okta-saml"]
	if rep == nil {
		t.Fatal("identity provider not created")
	}
	cfg, _ := rep["config"].(map[string]any)
	if cfg["entityId"] != idp.EntityID {
		t.Fatalf("entityId = %v — must be pinned to the public realm URL, not the imported value", cfg["entityId"])
	}
	if cfg["singleSignOnServiceUrl"] != "https://idp.example.com/sso" {
		t.Fatalf("imported SSO URL lost: %v", cfg)
	}
}

func TestEnsureIdentityProviderOIDCUpdateKeepsAlias(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	idp := IdP{
		Alias: "okta-oidc", DisplayName: "Okta OIDC", Protocol: "oidc", Enabled: true,
		DiscoveryURL: "https://okta.example.com/.well-known/openid-configuration",
		ClientID:     "cid", ClientSecret: "cs",
	}
	ctx := context.Background()
	if err := c.EnsureIdentityProvider(ctx, "correlix", idp); err != nil {
		t.Fatalf("create: %v", err)
	}
	idp.DisplayName = "Okta (renamed)"
	idp.Enabled = false
	if err := c.EnsureIdentityProvider(ctx, "correlix", idp); err != nil {
		t.Fatalf("update: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.idps) != 1 {
		t.Fatalf("idps = %d, want 1 (alias immutable, updated in place)", len(f.idps))
	}
	rep := f.idps["okta-oidc"]
	if rep["displayName"] != "Okta (renamed)" || rep["enabled"] != false {
		t.Fatalf("update not applied: %v", rep)
	}
	cfg, _ := rep["config"].(map[string]any)
	if cfg["clientId"] != "cid" || cfg["clientSecret"] != "cs" {
		t.Fatalf("oidc broker credentials missing: %v", cfg)
	}
}

func TestEnsureIdPMappersReconciles(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	ctx := context.Background()
	f.mu.Lock()
	// Pre-existing state: one console-made mapper (must survive) and one managed
	// mapper whose mapping row has been removed (must be deleted).
	f.idpMappers["okta-saml"] = []idpMapper{
		{ID: "m-console", Name: "hand-made", IdentityProviderAlias: "okta-saml",
			IdentityProviderMapper: "saml-user-attribute-idp-mapper", Config: map[string]string{}},
		{ID: "m-old", Name: ManagedPrefix + "role-correlix-ops-operator", IdentityProviderAlias: "okta-saml",
			IdentityProviderMapper: "saml-advanced-role-idp-mapper", Config: map[string]string{}},
	}
	f.mu.Unlock()

	attrs := []AttrMapping{{IdPAttr: "email", UserAttr: "email"}}
	roles := []RoleMapping{{GroupsAttr: "groups", Value: "correlix-admins", Role: "netops-admin"}}
	if err := c.EnsureIdPMappers(ctx, "correlix", "okta-saml", "saml", attrs, roles); err != nil {
		t.Fatalf("EnsureIdPMappers: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	names := map[string]idpMapper{}
	for _, m := range f.idpMappers["okta-saml"] {
		names[m.Name] = m
	}
	if _, ok := names["hand-made"]; !ok {
		t.Fatal("console-made mapper was deleted — reconciler must only own the managed prefix")
	}
	if _, ok := names[ManagedPrefix+"role-correlix-ops-operator"]; ok {
		t.Fatal("removed role mapping's managed mapper was not deleted")
	}
	rm, ok := names[ManagedPrefix+"role-correlix-admins-netops-admin"]
	if !ok {
		t.Fatalf("role mapper not created; have %v", f.idpMappers["okta-saml"])
	}
	if rm.IdentityProviderMapper != "saml-advanced-role-idp-mapper" {
		t.Fatalf("wrong mapper type %q", rm.IdentityProviderMapper)
	}
	if !strings.Contains(rm.Config["attributes"], `"key":"groups"`) || !strings.Contains(rm.Config["attributes"], `"value":"correlix-admins"`) {
		t.Fatalf("attributes match list wrong: %s", rm.Config["attributes"])
	}
	if rm.Config["role"] != "netops-admin" || rm.Config["syncMode"] != "FORCE" {
		t.Fatalf("role/syncMode wrong: %v", rm.Config)
	}
	am, ok := names[ManagedPrefix+"attr-email"]
	if !ok || am.Config["attribute.name"] != "email" {
		t.Fatalf("attribute importer missing/wrong: %+v", am)
	}
}

func TestRetryOn503ThenSuccess(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	var slept []time.Duration
	c.sleep = func(d time.Duration) { slept = append(slept, d) }
	f.mu.Lock()
	f.realms["correlix"] = true
	f.failuresLeft = 2
	f.mu.Unlock()
	if err := c.EnsureRealm(context.Background(), "correlix"); err != nil {
		t.Fatalf("EnsureRealm should survive two 503s: %v", err)
	}
	if len(slept) != 2 {
		t.Fatalf("backoff sleeps = %d, want 2", len(slept))
	}
	if slept[1] <= slept[0]-200*time.Millisecond {
		t.Fatalf("backoff not increasing: %v", slept)
	}
}

func TestNoRetryOn400(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	f.mu.Lock()
	f.badRequest = true
	f.mu.Unlock()
	err := c.EnsureRealm(context.Background(), "correlix")
	if err == nil {
		t.Fatal("expected error")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx is never retried)", f.attempts)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusBadRequest {
		t.Fatalf("error should carry the 400: %v", err)
	}
}

func TestPingDistinguishesStates(t *testing.T) {
	f := newFakeKC()
	c := newTestClient(t, f)
	// Realm missing.
	res := c.Ping(context.Background())
	if !res.Reachable || !res.Authorized || res.RealmExists {
		t.Fatalf("ping (no realm) = %+v", res)
	}
	if res.Version != "25.0.0" {
		t.Fatalf("version = %q", res.Version)
	}
	// Realm present.
	f.mu.Lock()
	f.realms["correlix"] = true
	f.mu.Unlock()
	if res = c.Ping(context.Background()); !res.RealmExists {
		t.Fatalf("ping (realm) = %+v", res)
	}
	// Unreachable.
	dead := New(Config{BaseURL: "http://127.0.0.1:1", AdminUser: "a", AdminPassword: "b", Realm: "correlix", Timeout: time.Second})
	dead.sleep = func(time.Duration) {}
	if res = dead.Ping(context.Background()); res.Reachable {
		t.Fatalf("ping (dead) = %+v", res)
	}
}
