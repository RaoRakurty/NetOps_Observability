// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tenant_signin_test.go — per-tenant sign-in and SSO URLs (design §6.1, tracker
// 276), exercised through the REAL router + auth middleware.
//
// What is proved here, in order:
//   - locator resolution: slug, immutable org id, unknown, suspended tenant,
//     malformed — and that unknown and suspended are BYTE-IDENTICAL answers;
//   - provider filtering: /api/auth/methods lists only the connections the
//     candidate realm reaches, and unbound (platform-realm) ones stay visible;
//   - callback-URL binding: an unregistered provider, a provider registered to
//     another tenant, and a cross-tenant replay are each refused with no
//     session, and audited;
//   - the redirect URI handed to the IdP and echoed at the exchange;
//   - the deep-link round trip: a per-tenant flow lands back on /t/{slug}.
//
// The tenant-admin CRUD half lives in tenant_idp_isolation_test.go.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/oidc"
	"netops/backend/internal/ssoidp"
	"netops/backend/internal/tenantlocator"
)

// noRedirect never follows a 302 — the whole point of several assertions below
// is WHERE the browser is sent, and following it would hide that.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// getWith issues a GET carrying the supplied cookies and returns the raw
// response (status, body, Set-Cookie, Location all matter here).
func getWith(t *testing.T, srv *httptest.Server, path string, cookies ...*http.Cookie) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, b
}

// cookieNamed pulls one Set-Cookie by name, or nil.
func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// locatorFor resolves a locator path and returns the armed candidate cookie.
func locatorFor(t *testing.T, srv *httptest.Server, path string) *http.Cookie {
	t.Helper()
	resp, b := getWith(t, srv, "/api/auth/locator?path="+url.QueryEscape(path))
	if resp.StatusCode != 200 {
		t.Fatalf("locator %s: status %d: %s", path, resp.StatusCode, b)
	}
	ck := cookieNamed(resp, loginLocatorCookie)
	if ck == nil || ck.Value == "" {
		t.Fatalf("locator %s armed no candidate cookie: %s", path, b)
	}
	return ck
}

// signinFixture builds two tenants in two orgs, each with one bound SSO
// connection, plus one UNBOUND (platform-realm) connection.
type signinFixture struct {
	srv              *httptest.Server
	s                *server
	admin            string
	orgA, orgB       string
	tenantA, tenantB string
	slugA, slugB     string
}

func newSigninFixture(t *testing.T) *signinFixture {
	t.Helper()
	srv, s, _ := newSSOIdPServer(t)
	// /api/auth/methods reads the native provider stores; the SSO harness does
	// not wire them, so point them at this test's own temp dir.
	dir := t.TempDir()
	s.ldap = newLDAPConfigStore(dir+"/ldap.json", nil)
	s.tacacs = newTACACSConfigStore(dir+"/tacacs.json", nil)
	s.ssoTxns = newSSOTxnStore()
	f := &signinFixture{srv: srv, s: s, admin: adminToken(t, srv)}

	mk := func(orgName, tenantName string) (orgID, tenantID, slug string) {
		st, b := do(t, srv, "POST", "/api/orgs", f.admin, map[string]any{"name": orgName})
		if st != 201 && st != 200 {
			t.Fatalf("create org %s: %d %s", orgName, st, b)
		}
		orgID = idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", f.admin, map[string]any{"name": tenantName, "org_id": orgID})
		if st != 201 && st != 200 {
			t.Fatalf("create tenant %s: %d %s", tenantName, st, b)
		}
		tenantID = idOf(t, b)
		var rec struct {
			Slug string `json:"slug"`
		}
		if err := json.Unmarshal(b, &rec); err != nil || rec.Slug == "" {
			t.Fatalf("tenant %s has no slug: %s", tenantName, b)
		}
		return orgID, tenantID, rec.Slug
	}
	f.orgA, f.tenantA, f.slugA = mk("Org Alpha", "Acme")
	f.orgB, f.tenantB, f.slugB = mk("Org Beta", "Globex")

	// Three connections: one per tenant, plus one nobody bound.
	f.bind("acme-idp", "Acme SSO", f.tenantA)
	f.bind("globex-idp", "Globex SSO", f.tenantB)
	f.bind("shared-idp", "Corporate SSO", "")
	// The login page's button list is the OIDC provider CSV; mirror the three
	// aliases into it exactly as a real save through applySSOIdP would.
	cfg := s.oidcCfg.effective()
	cfg.Enabled = true
	cfg.Issuer = "https://idp.example.com/realms/correlix"
	cfg.ClientID = "netops"
	cfg.Providers = "acme-idp:Acme SSO:oidc,globex-idp:Globex SSO:oidc,shared-idp:Corporate SSO:oidc"
	if _, err := s.oidcCfg.set(cfg); err != nil {
		t.Fatalf("seed provider buttons: %v", err)
	}
	return f
}

// bind stores one connection, optionally bound to a tenant.
func (f *signinFixture) bind(alias, name, tenantID string) {
	if _, err := f.s.ssoIdPCfg.Set(ssoidp.Config{
		Alias: alias, DisplayName: name, Protocol: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration",
		ClientID:     "cid", TenantID: tenantID,
	}); err != nil {
		panic("seed connection " + alias + ": " + err.Error())
	}
}

// ---- 1. locator resolution -------------------------------------------------

func TestLocatorResolvesTenantSlugAndOrgID(t *testing.T) {
	f := newSigninFixture(t)

	resp, b := getWith(t, f.srv, "/api/auth/locator?path=/t/"+f.slugA)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var got struct {
		Locator *struct {
			Kind, Name, Path string
		} `json:"locator"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
	if got.Locator == nil || got.Locator.Name != "Acme" || got.Locator.Kind != tenantlocator.KindTenant {
		t.Fatalf("tenant locator = %+v, want the Acme tenant", got.Locator)
	}
	if got.Locator.Path != "/t/"+f.slugA {
		t.Errorf("path = %q, want /t/%s", got.Locator.Path, f.slugA)
	}
	// The cookie carries the IMMUTABLE id, never the mutable slug or the name.
	ck := cookieNamed(resp, loginLocatorCookie)
	if ck == nil || !ck.HttpOnly {
		t.Fatalf("candidate cookie must be set and HttpOnly: %+v", ck)
	}
	if strings.Contains(ck.Value, f.slugA) || strings.Contains(ck.Value, "Acme") {
		t.Error("the candidate cookie must not carry the slug or display name")
	}
	claim, err := f.s.locatorSigner().Verify(ck.Value, time.Now())
	if err != nil || claim.ID != f.tenantA {
		t.Fatalf("cookie claim = %+v err=%v, want the immutable tenant id %s", claim, err, f.tenantA)
	}

	// The immutable org URL resolves to the org realm.
	resp, b = getWith(t, f.srv, "/api/auth/locator?path=/org/"+f.orgA)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
	if got.Locator == nil || got.Locator.Kind != tenantlocator.KindOrg || got.Locator.Path != "/org/"+f.orgA {
		t.Fatalf("org locator = %+v", got.Locator)
	}
	if cookieNamed(resp, loginLocatorCookie) == nil {
		t.Error("the org locator must arm a candidate too")
	}
}

// The one that matters most: an unknown customer and a KNOWN-BUT-SUSPENDED one
// must be indistinguishable. Same status, same bytes, same cleared cookie.
func TestLocatorUnknownAndSuspendedAreIndistinguishable(t *testing.T) {
	f := newSigninFixture(t)
	if st, b := do(t, f.srv, "PATCH", "/api/tenants/"+f.tenantB, f.admin, map[string]any{"status": TenantStatusSuspended}); st != 200 {
		t.Fatalf("suspend tenant: %d %s", st, b)
	}
	respUnknown, bodyUnknown := getWith(t, f.srv, "/api/auth/locator?path=/t/no-such-customer")
	respHidden, bodyHidden := getWith(t, f.srv, "/api/auth/locator?path=/t/"+f.slugB)

	if respUnknown.StatusCode != respHidden.StatusCode || respUnknown.StatusCode != 200 {
		t.Fatalf("status %d vs %d", respUnknown.StatusCode, respHidden.StatusCode)
	}
	if string(bodyUnknown) != string(bodyHidden) {
		t.Fatalf("INFORMATION LEAK: unknown %q differs from suspended %q", bodyUnknown, bodyHidden)
	}
	if !strings.Contains(string(bodyUnknown), `"locator":null`) {
		t.Fatalf("unresolved locator must answer a null locator, got %s", bodyUnknown)
	}
	// Both must CLEAR a stale candidate rather than leave an earlier tenant's
	// doors on screen.
	for name, resp := range map[string]*http.Response{"unknown": respUnknown, "suspended": respHidden} {
		ck := cookieNamed(resp, loginLocatorCookie)
		if ck == nil || ck.Value != "" || ck.MaxAge >= 0 {
			t.Errorf("%s locator must expire the candidate cookie, got %+v", name, ck)
		}
	}
}

func TestLocatorRejectsMalformedPaths(t *testing.T) {
	f := newSigninFixture(t)
	for _, p := range []string{"", "/", "/t/", "/t/..", "/api/auth/login", "/org/", "/t/" + strings.Repeat("x", 300)} {
		resp, b := getWith(t, f.srv, "/api/auth/locator?path="+url.QueryEscape(p))
		if resp.StatusCode != 200 || !strings.Contains(string(b), `"locator":null`) {
			t.Errorf("path %q: status %d body %s, want 200 + null locator", p, resp.StatusCode, b)
		}
	}
	if resp, _ := getWith(t, f.srv, "/api/auth/locator"); resp.StatusCode != 200 {
		t.Errorf("no path at all: status %d", resp.StatusCode)
	}
}

// ---- 2. provider filtering -------------------------------------------------

func ssoButtons(t *testing.T, srv *httptest.Server, cookies ...*http.Cookie) []string {
	t.Helper()
	resp, b := getWith(t, srv, "/api/auth/methods", cookies...)
	if resp.StatusCode != 200 {
		t.Fatalf("methods: %d %s", resp.StatusCode, b)
	}
	var got struct {
		SSO struct {
			Providers []oidc.ProviderInfo `json:"providers"`
		} `json:"sso"`
		Locator *struct{ Name string } `json:"locator"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode methods: %v (%s)", err, b)
	}
	out := make([]string, 0, len(got.SSO.Providers))
	for _, p := range got.SSO.Providers {
		out = append(out, p.ID)
	}
	return out
}

func TestSignInPageListsOnlyTheCandidateRealmsProviders(t *testing.T) {
	f := newSigninFixture(t)

	// No locator — today's behaviour: every configured button.
	if got := ssoButtons(t, f.srv); len(got) != 3 {
		t.Fatalf("generic sign-in should list every button, got %v", got)
	}

	acme := locatorFor(t, f.srv, "/t/"+f.slugA)
	got := ssoButtons(t, f.srv, acme)
	want := map[string]bool{"acme-idp": true, "shared-idp": true}
	for _, id := range got {
		if !want[id] {
			t.Errorf("CROSS-TENANT LEAK: %q offered on Acme's sign-in page (%v)", id, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("acme sign-in = %v, want its own connection plus the platform-realm one", got)
	}

	globex := locatorFor(t, f.srv, "/t/"+f.slugB)
	got = ssoButtons(t, f.srv, globex)
	for _, id := range got {
		if id == "acme-idp" {
			t.Errorf("CROSS-TENANT LEAK: acme-idp offered on Globex's sign-in page (%v)", got)
		}
	}

	// The org locator reaches its own tenant's connections and nobody else's.
	orgA := locatorFor(t, f.srv, "/org/"+f.orgA)
	got = ssoButtons(t, f.srv, orgA)
	for _, id := range got {
		if id == "globex-idp" {
			t.Errorf("CROSS-ORG LEAK: globex-idp offered on org Alpha's sign-in page (%v)", got)
		}
	}

	// A forged / foreign cookie value resolves to nothing and must not widen the
	// list into another tenant's — it falls back to the generic page.
	forged := &http.Cookie{Name: loginLocatorCookie, Value: "not.a.real.token"}
	if got := ssoButtons(t, f.srv, forged); len(got) != 3 {
		t.Errorf("an unverifiable candidate must fall back to the generic page, got %v", got)
	}
}

func TestSignInPageNamesTheCandidate(t *testing.T) {
	f := newSigninFixture(t)
	acme := locatorFor(t, f.srv, "/t/"+f.slugA)
	_, b := getWith(t, f.srv, "/api/auth/methods", acme)
	if !strings.Contains(string(b), `"name":"Acme"`) {
		t.Fatalf("the sign-in page must name the candidate tenant: %s", b)
	}
	// …and the generic page names nobody.
	_, b = getWith(t, f.srv, "/api/auth/methods")
	if strings.Contains(string(b), `"locator"`) {
		t.Fatalf("the generic sign-in page must carry no locator: %s", b)
	}
}

// A tenant may not START a flow through another tenant's provider, even by
// hand-typing the generic login URL: same 404 an unknown alias gets.
func TestSSOLoginRefusesAProviderOutsideTheCandidateRealm(t *testing.T) {
	f := newSigninFixture(t)
	acme := locatorFor(t, f.srv, "/t/"+f.slugA)
	resp, _ := getWith(t, f.srv, "/api/auth/sso/login?idp=globex-idp", acme)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-realm idp: status %d, want 404", resp.StatusCode)
	}
	// Its own provider passes the same gate. Asserted on the predicate rather
	// than by following the redirect: continuing would send the test out to a
	// real IdP discovery endpoint, and what is under test here is the gate.
	req := httptest.NewRequest(http.MethodGet, "http://x/api/auth/sso/login?idp=acme-idp", nil)
	req.AddCookie(acme)
	if !f.s.ssoIDPAllowedForLocator(req, "acme-idp") {
		t.Fatal("a tenant's own provider must not be refused")
	}
	if f.s.ssoIDPAllowedForLocator(req, "globex-idp") {
		t.Fatal("another tenant's provider must be refused")
	}
	// Unbound platform-realm connections stay startable from any realm.
	if !f.s.ssoIDPAllowedForLocator(req, "shared-idp") {
		t.Fatal("a platform-realm provider must stay available")
	}
	// With no candidate at all nothing is gated — today's behaviour.
	plain := httptest.NewRequest(http.MethodGet, "http://x/api/auth/sso/login?idp=globex-idp", nil)
	if !f.s.ssoIDPAllowedForLocator(plain, "globex-idp") {
		t.Fatal("the generic sign-in page must gate nothing")
	}
}

// ---- 3. callback-URL binding ----------------------------------------------

func TestPerTenantCallbackRefusals(t *testing.T) {
	f := newSigninFixture(t)
	acme := locatorFor(t, f.srv, "/t/"+f.slugA)

	cases := []struct {
		name, path string
		cookie     *http.Cookie
		wantStatus int
		wantFrag   string
	}{
		{
			name: "unknown locator", path: "/t/no-such-customer/sso/acme-idp/callback",
			cookie: acme, wantStatus: http.StatusNotFound,
		},
		{
			name: "malformed per-tenant path", path: "/t/" + f.slugA + "/sso/acme-idp/callback/extra",
			cookie: acme, wantStatus: http.StatusNotFound,
		},
		{
			name: "provider not registered at all", path: "/t/" + f.slugA + "/sso/ghost-idp/callback",
			cookie: acme, wantStatus: http.StatusFound, wantFrag: "not an identity provider",
		},
		{
			// A platform-realm connection keeps the GENERIC callback; it has no
			// per-tenant URL, so this one is refused too.
			name: "unbound platform-realm provider", path: "/t/" + f.slugA + "/sso/shared-idp/callback",
			cookie: acme, wantStatus: http.StatusFound, wantFrag: "not an identity provider",
		},
		{
			name: "provider registered to ANOTHER tenant", path: "/t/" + f.slugA + "/sso/globex-idp/callback",
			cookie: acme, wantStatus: http.StatusFound, wantFrag: "not an identity provider",
		},
		{
			name: "cross-tenant replay: acme's candidate on globex's callback URL",
			path: "/t/" + f.slugB + "/sso/globex-idp/callback", cookie: acme,
			wantStatus: http.StatusFound, wantFrag: "did not start at",
		},
		{
			name: "no candidate at all", path: "/t/" + f.slugA + "/sso/acme-idp/callback",
			cookie: nil, wantStatus: http.StatusFound, wantFrag: "did not start at",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if c.cookie != nil {
				cookies = append(cookies, c.cookie)
			}
			resp, b := getWith(t, f.srv, c.path+"?code=stolen&state=stolen", cookies...)
			if resp.StatusCode != c.wantStatus {
				t.Fatalf("status %d, want %d (%s)", resp.StatusCode, c.wantStatus, b)
			}
			// No session, ever: nothing that looks like a token may come back.
			if strings.Contains(resp.Header.Get("Location"), "token=") || strings.Contains(string(b), "refresh_token") {
				t.Fatalf("a refused callback must mint NO session: %s / %s", resp.Header.Get("Location"), b)
			}
			if c.wantFrag == "" {
				return
			}
			loc, err := url.QueryUnescape(resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("location: %v", err)
			}
			if !strings.Contains(loc, c.wantFrag) {
				t.Fatalf("refusal %q does not say %q", loc, c.wantFrag)
			}
			// Refused by NAME, back on the realm's own sign-in page.
			if !strings.HasPrefix(loc, "/t/") && !strings.HasPrefix(loc, "/org/") {
				t.Fatalf("a refusal must land on the realm's own sign-in page, got %q", loc)
			}
		})
	}
}

// The refusal is evidence: an attempt to replay a token onto another tenant's
// URL is exactly what an investigator needs to find later (§10).
func TestPerTenantCallbackRefusalIsAudited(t *testing.T) {
	f := newSigninFixture(t)
	acme := locatorFor(t, f.srv, "/t/"+f.slugA)
	getWith(t, f.srv, "/t/"+f.slugA+"/sso/globex-idp/callback?code=x&state=y", acme)
	events, err := f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Decision == "deny" && strings.Contains(e.Path, "/sso/globex-idp/callback") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the cross-realm callback refusal was not audited (%d entries)", len(events))
	}
}

// ---- 4. redirect URIs and the deep-link round trip ------------------------

func TestPerTenantRedirectURIs(t *testing.T) {
	f := newSigninFixture(t)
	p := f.s.oidcProvider()
	req := httptest.NewRequest(http.MethodGet, "https://netops.example.com/api/auth/sso/login?idp=acme-idp", nil)
	req.Host = "netops.example.com"

	// A tenant-BOUND connection is handed its own per-tenant callback URL,
	// derived from the connection's tenant — not from anything the browser said.
	got := f.s.ssoLoginRedirectURI(req, p, "acme-idp")
	want := "https://netops.example.com/t/" + f.slugA + "/sso/acme-idp/callback"
	if got != want {
		t.Fatalf("bound redirect_uri = %q, want %q", got, want)
	}
	// An UNBOUND connection keeps the generic callback: an IdP registration that
	// predates this change must never have to be re-registered.
	if got, want := f.s.ssoLoginRedirectURI(req, p, "shared-idp"), p.CallbackURL(req); got != want {
		t.Fatalf("unbound redirect_uri = %q, want the generic %q", got, want)
	}

	// At the callback the exchange must echo the SAME value, re-derived from the
	// request path.
	cb := httptest.NewRequest(http.MethodGet, "https://netops.example.com/t/"+f.slugA+"/sso/acme-idp/callback?code=x", nil)
	cb.Host = "netops.example.com"
	if got := f.s.ssoCallbackRedirectURI(cb, p); got != want {
		t.Fatalf("callback redirect_uri = %q, want %q", got, want)
	}
	generic := httptest.NewRequest(http.MethodGet, "https://netops.example.com/api/auth/sso/callback?code=x", nil)
	generic.Host = "netops.example.com"
	if got, want := f.s.ssoCallbackRedirectURI(generic, p), p.CallbackURL(generic); got != want {
		t.Fatalf("generic callback redirect_uri = %q, want %q", got, want)
	}

	// The broker client must be allowed to return to every one of those URLs,
	// enumerated — never wildcarded.
	uris := f.s.ssoClientRedirectURIs("https://netops.example.com")
	joined := strings.Join(uris, " ")
	for _, must := range []string{
		"https://netops.example.com/api/auth/sso/callback",
		"https://netops.example.com/t/" + f.slugA + "/sso/acme-idp/callback",
		"https://netops.example.com/org/" + f.orgA + "/sso/acme-idp/callback",
		"https://netops.example.com/t/" + f.slugB + "/sso/globex-idp/callback",
	} {
		if !strings.Contains(joined, must) {
			t.Errorf("broker redirect URIs missing %q (have %v)", must, uris)
		}
	}
	if strings.Contains(joined, "*") {
		t.Errorf("broker redirect URIs must never be wildcarded: %v", uris)
	}
}

// Deep links keep the tenant: a flow that returned to /t/{slug}/sso/… is dropped
// back at /t/{slug}, so the SPA can restore the hash route it stashed.
func TestPerTenantFlowReturnsToTheTenantPath(t *testing.T) {
	f := newSigninFixture(t)
	p := f.s.oidcProvider()
	cb := httptest.NewRequest(http.MethodGet, "http://x/t/"+f.slugA+"/sso/acme-idp/callback?code=x", nil)
	if got, want := f.s.ssoPostLoginPath(cb, p), "/t/"+f.slugA; got != want {
		t.Fatalf("post-login path = %q, want %q", got, want)
	}
	org := httptest.NewRequest(http.MethodGet, "http://x/org/"+f.orgA+"/sso/acme-idp/callback?code=x", nil)
	if got, want := f.s.ssoPostLoginPath(org, p), "/org/"+f.orgA; got != want {
		t.Fatalf("org post-login path = %q, want %q", got, want)
	}
	generic := httptest.NewRequest(http.MethodGet, "http://x/api/auth/sso/callback?code=x", nil)
	if got, want := f.s.ssoPostLoginPath(generic, p), p.PostLoginURL(); got != want {
		t.Fatalf("generic post-login path = %q, want %q", got, want)
	}
}

// A user arriving through a tenant's own connection is PROVISIONED into that
// tenant — the binding is the operator's, not a claim, and it never moves an
// account that already exists (UpsertFederated leaves an existing tenant alone).
func TestProvisionTenantFollowsTheConnectionBinding(t *testing.T) {
	f := newSigninFixture(t)
	p := f.s.oidcProvider()
	bound := httptest.NewRequest(http.MethodGet, "http://x/t/"+f.slugA+"/sso/acme-idp/callback?code=x", nil)
	if got := f.s.ssoProvisionTenant(bound, p); got != f.tenantA {
		t.Fatalf("provision tenant = %q, want the bound tenant %q", got, f.tenantA)
	}
	unbound := httptest.NewRequest(http.MethodGet, "http://x/t/"+f.slugA+"/sso/shared-idp/callback?code=x", nil)
	if got, want := f.s.ssoProvisionTenant(unbound, p), p.DefaultTenant(); got != want {
		t.Fatalf("unbound provision tenant = %q, want the OIDC default %q", got, want)
	}
	generic := httptest.NewRequest(http.MethodGet, "http://x/api/auth/sso/callback?code=x", nil)
	if got, want := f.s.ssoProvisionTenant(generic, p), p.DefaultTenant(); got != want {
		t.Fatalf("generic provision tenant = %q, want %q", got, want)
	}
}

// A connection bound to a tenant that no longer exists fails CLOSED: it is
// offered to nobody rather than decaying into the platform realm, which would
// republish a decommissioned customer's IdP on everyone's sign-in page.
func TestDanglingBindingIsOfferedToNobody(t *testing.T) {
	f := newSigninFixture(t)
	f.bind("ghost-idp", "Ghost", "t_deadbeefdeadbeefdeadbeefdeadbeef")
	if f.s.providerVisible(nil, "ghost-idp") {
		t.Error("a dangling binding must not appear on the generic sign-in page")
	}
	acme, _ := tenantlocator.Resolve(f.s.locatorDir(), tenantlocator.KindTenant, f.slugA)
	if f.s.providerVisible(&acme, "ghost-idp") {
		t.Error("a dangling binding must not appear on a tenant's sign-in page")
	}
}
