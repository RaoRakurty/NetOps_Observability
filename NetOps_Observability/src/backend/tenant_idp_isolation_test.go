// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/auth/sso/tenant-idp"  "/api/auth/sso/tenant-idp/"
//
// tenant_idp_isolation_test.go — CROSS-ORG isolation for tenant-managed identity
// providers (CLAUDE.md §3a, design §6.3, tracker 276), through the REAL router
// and auth middleware.
//
// The five obligations, each asserted below:
//   1. own-only list — a tenant admin sees ONLY its own connections;
//   2. a foreign alias answers 404 on get/put/delete — never 403, which would
//      confirm the alias exists;
//   3. the owning tenant is stamped from the TOKEN; the request type cannot
//      even express one, and a tenant_id smuggled into the body is ignored;
//   4. an `as_tenant` selector into another org is ignored;
//   5. platform-realm (unbound) connections are invisible and immutable here —
//      they stay on /api/auth/sso/idp behind requirePlatformAdmin.

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/ssoidp"
)

type tenantIdPFixture struct {
	srv              *httptest.Server
	s                *server
	admin            string
	tenantA, tenantB string
	slugA            string
	tokenA, tokenB   string
}

func newTenantIdPFixture(t *testing.T) *tenantIdPFixture {
	t.Helper()
	srv, s, _ := newSSOIdPServer(t)
	f := &tenantIdPFixture{srv: srv, s: s, admin: adminToken(t, srv)}

	mk := func(orgName, tenantName, user string) (tenantID, slug, token string) {
		st, b := do(t, srv, "POST", "/api/orgs", f.admin, map[string]any{"name": orgName})
		if st != 201 && st != 200 {
			t.Fatalf("create org: %d %s", st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", f.admin, map[string]any{"name": tenantName, "org_id": orgID})
		if st != 201 && st != 200 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		tenantID = idOf(t, b)
		var rec struct {
			Slug string `json:"slug"`
		}
		_ = json.Unmarshal(b, &rec) // slug is a convenience for URL assertions
		if st, b = do(t, srv, "POST", "/api/users", f.admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": RoleSuperAdmin, "tenant_id": tenantID,
		}); st != 201 && st != 200 {
			t.Fatalf("create tenant admin: %d %s", st, b)
		}
		return tenantID, rec.Slug, login(t, srv, user, "Passw0rd!2345").Token
	}
	f.tenantA, f.slugA, f.tokenA = mk("Org Alpha", "Acme", "acme-admin")
	f.tenantB, _, f.tokenB = mk("Org Beta", "Globex", "globex-admin")
	return f
}

func oidcIdPBody(name string) map[string]any {
	return map[string]any{
		"display_name":  name,
		"protocol":      "oidc",
		"enabled":       true,
		"discovery_url": "https://idp.example.com/.well-known/openid-configuration",
		"client_id":     "cid",
		"client_secret": "shh",
	}
}

// aliasesFor lists the aliases a token can see on the tenant surface.
func aliasesFor(t *testing.T, srv *httptest.Server, token string, query string) []string {
	t.Helper()
	st, b := do(t, srv, "GET", "/api/auth/sso/tenant-idp"+query, token, nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var got struct {
		IdPs []struct {
			IdP struct {
				Alias    string `json:"alias"`
				TenantID string `json:"tenant_id"`
			} `json:"idp"`
		} `json:"idps"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode list: %v (%s)", err, b)
	}
	out := make([]string, 0, len(got.IdPs))
	for _, row := range got.IdPs {
		out = append(out, row.IdP.Alias)
	}
	return out
}

func TestTenantIdPCrossOrgIsolation(t *testing.T) {
	f := newTenantIdPFixture(t)

	// Each tenant admin creates a connection in its own realm.
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, oidcIdPBody("Acme Okta")); st != 200 {
		t.Fatalf("acme create: %d %s", st, b)
	}
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/globex-entra", f.tokenB, oidcIdPBody("Globex Entra")); st != 200 {
		t.Fatalf("globex create: %d %s", st, b)
	}
	// …and the platform owner owns an unbound, platform-realm connection.
	if _, err := f.s.ssoIdPCfg.Set(ssoidp.Config{
		Alias: "shared-idp", DisplayName: "Corporate", Protocol: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration", ClientID: "cid",
	}); err != nil {
		t.Fatalf("seed platform-realm connection: %v", err)
	}

	// 3. The owner is stamped from the TOKEN.
	reg, ok := f.s.ssoIdPCfg.Get("acme-okta")
	if !ok || reg.Realm() != f.tenantA {
		t.Fatalf("connection realm = %q, want the caller's tenant %q", reg.Realm(), f.tenantA)
	}

	// 1. Own-only list.
	if got := aliasesFor(t, f.srv, f.tokenA, ""); len(got) != 1 || got[0] != "acme-okta" {
		t.Fatalf("CROSS-TENANT LEAK: acme sees %v, want only its own connection", got)
	}
	if got := aliasesFor(t, f.srv, f.tokenB, ""); len(got) != 1 || got[0] != "globex-entra" {
		t.Fatalf("CROSS-TENANT LEAK: globex sees %v", got)
	}

	// 4. as_tenant into another org is ignored (it can only ever narrow).
	if got := aliasesFor(t, f.srv, f.tokenA, "?as_tenant="+f.tenantB); len(got) != 1 || got[0] != "acme-okta" {
		t.Fatalf("CROSS-TENANT LEAK: as_tenant widened acme's view to %v", got)
	}

	// 2. A foreign alias is a 404 on every verb — the SAME answer an unknown
	//    alias gets, so the caller cannot probe for existence.
	for _, c := range []struct{ method, alias string }{
		{"GET", "globex-entra"}, {"PUT", "globex-entra"}, {"DELETE", "globex-entra"},
		{"GET", "no-such-idp"}, {"DELETE", "no-such-idp"},
	} {
		var body any
		if c.method == "PUT" {
			body = oidcIdPBody("Hijack")
		}
		if st, b := do(t, f.srv, c.method, "/api/auth/sso/tenant-idp/"+c.alias, f.tokenA, body); st != http.StatusNotFound {
			t.Errorf("%s %s as the other tenant: status %d, want 404 (%s)", c.method, c.alias, st, b)
		}
	}
	// The hijack attempt must not have touched the record.
	if reg, ok := f.s.ssoIdPCfg.Get("globex-entra"); !ok || reg.Realm() != f.tenantB || reg.DisplayName == "Hijack" {
		t.Fatalf("globex's connection was mutated by acme: %+v", reg)
	}

	// 5. Platform-realm connections are invisible and immutable here.
	if st, _ := do(t, f.srv, "GET", "/api/auth/sso/tenant-idp/shared-idp", f.tokenA, nil); st != http.StatusNotFound {
		t.Errorf("platform-realm connection visible to a tenant admin: %d", st)
	}
	if st, _ := do(t, f.srv, "DELETE", "/api/auth/sso/tenant-idp/shared-idp", f.tokenA, nil); st != http.StatusNotFound {
		t.Errorf("platform-realm connection deletable by a tenant admin: %d", st)
	}
	if reg, ok := f.s.ssoIdPCfg.Get("shared-idp"); !ok || reg.Realm() != "" {
		t.Fatalf("the platform-realm connection was altered: %+v ok=%v", reg, ok)
	}

	// A tenant admin CAN delete its own.
	if st, b := do(t, f.srv, "DELETE", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, nil); st != 200 {
		t.Fatalf("acme delete own: %d %s", st, b)
	}
	if _, ok := f.s.ssoIdPCfg.Get("acme-okta"); ok {
		t.Error("the connection was not removed")
	}
}

// A tenant_id in the body is ignored: the wire type cannot express it, and even
// a hand-rolled payload carrying one is stamped from the token instead.
func TestTenantIdPIgnoresATenantInTheBody(t *testing.T) {
	f := newTenantIdPFixture(t)
	body := oidcIdPBody("Acme Okta")
	body["tenant_id"] = f.tenantB
	body["alias"] = "globex-entra"
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, body); st != 200 {
		t.Fatalf("create: %d %s", st, b)
	}
	reg, ok := f.s.ssoIdPCfg.Get("acme-okta")
	if !ok {
		t.Fatal("connection not stored")
	}
	if reg.Realm() != f.tenantA {
		t.Fatalf("OWNER SPOOFED: realm = %q, want the token's tenant %q", reg.Realm(), f.tenantA)
	}
	if reg.Alias != "acme-okta" {
		t.Fatalf("alias came from the body: %q", reg.Alias)
	}
}

// An alias is a broker-wide path segment: one connection may hold it. Taking one
// another tenant already holds answers 404 — the same as editing theirs.
func TestTenantIdPAliasCannotBeStolen(t *testing.T) {
	f := newTenantIdPFixture(t)
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/shared-name", f.tokenB, oidcIdPBody("Globex")); st != 200 {
		t.Fatalf("globex create: %d %s", st, b)
	}
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/shared-name", f.tokenA, oidcIdPBody("Acme")); st != http.StatusNotFound {
		t.Fatalf("alias takeover: status %d, want 404 (%s)", st, b)
	}
	if reg, _ := f.s.ssoIdPCfg.Get("shared-name"); reg.Realm() != f.tenantB {
		t.Fatalf("the alias changed hands: realm %q", reg.Realm())
	}
}

func TestTenantIdPGate(t *testing.T) {
	f := newTenantIdPFixture(t)

	// Unauthenticated and non-admin are refused everywhere.
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/auth/sso/tenant-idp"},
		{"GET", "/api/auth/sso/tenant-idp/acme-okta"},
		{"PUT", "/api/auth/sso/tenant-idp/acme-okta"},
		{"DELETE", "/api/auth/sso/tenant-idp/acme-okta"},
	} {
		if st, _ := do(t, f.srv, c.method, c.path, "", nil); st != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated: %d, want 401", c.method, c.path, st)
		}
	}
	if st, b := do(t, f.srv, "POST", "/api/users", f.admin, map[string]any{
		"username": "acme-viewer", "password": "Passw0rd!2345", "role": RoleReadOnly, "tenant_id": f.tenantA,
	}); st != 201 && st != 200 {
		t.Fatalf("create viewer: %d %s", st, b)
	}
	viewer := login(t, f.srv, "acme-viewer", "Passw0rd!2345").Token
	if st, _ := do(t, f.srv, "GET", "/api/auth/sso/tenant-idp", viewer, nil); st != http.StatusForbidden {
		t.Errorf("read-only user: %d, want 403", st)
	}

	// The platform owner has no single realm to write in until it picks one:
	// silently choosing would land a connection in the wrong customer's realm.
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/owner-idp", f.admin, oidcIdPBody("Owner")); st != http.StatusBadRequest {
		t.Errorf("cross-tenant write: %d, want 400 (%s)", st, b)
	}
	// …and with a tenant selected it acts inside that tenant's realm.
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/owner-idp?as_tenant="+f.tenantA, f.admin, oidcIdPBody("Owner")); st != 200 {
		t.Fatalf("scoped write: %d %s", st, b)
	}
	if reg, _ := f.s.ssoIdPCfg.Get("owner-idp"); reg.Realm() != f.tenantA {
		t.Fatalf("scoped write landed in realm %q, want %q", reg.Realm(), f.tenantA)
	}
}

// The list hands a tenant admin the exact URLs its IdP team needs, and the
// secret never appears in any of them.
func TestTenantIdPListCarriesTheSignInAndCallbackURLs(t *testing.T) {
	f := newTenantIdPFixture(t)
	if st, b := do(t, f.srv, "PUT", "/api/auth/sso/tenant-idp/acme-okta", f.tokenA, oidcIdPBody("Acme Okta")); st != 200 {
		t.Fatalf("create: %d %s", st, b)
	}
	st, b := do(t, f.srv, "GET", "/api/auth/sso/tenant-idp", f.tokenA, nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	body := string(b)
	for _, want := range []string{
		`"sign_in_url"`, "/t/" + f.slugA,
		"/t/" + f.slugA + "/sso/acme-okta/callback",
		"/t/" + f.slugA + "/sso/acme-okta/login",
		`"client_secret_set":true`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list is missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "shh") {
		t.Fatalf("THE CLIENT SECRET LEAKED into the tenant surface: %s", body)
	}
}
