// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// sso_realm_isolation_test.go — §3a isolation for the per-tenant SSO callback.
//
// THE DEFECT. Per-tenant SSO URLs (tracker 276) validated three things, and all
// three were properties of the CONNECTION: the locator resolves, the connection
// is registered for the realm in the URL, and the browser started the flow in
// that realm. The ACCOUNT the ID token names was never checked. Usernames are a
// GLOBAL key, and UpsertFederated returned an existing account with its ORIGINAL
// tenant, so an administrator of tenant B — who holds administration:admin and
// may therefore register an identity provider of their own — could create a user
// named `alice` in it, sign in at /t/tenant-b/sso/b-idp/login, and be handed a
// session whose tenant was A. The merge on the way through rewrote the victim's
// role and auth source as well. Every account with no user in the attacker's
// IdP was reachable: LDAP-, TACACS- and bearer-provisioned accounts included.
//
// What is proved here, through the REAL router, the REAL code flow and a real
// fake IdP (JWKS + token endpoint):
//   - the attack is refused, no session is minted, and the victim's record is
//     BYTE-FOR-BYTE unchanged (the merge write is itself the damage);
//   - the refusal is byte-identical to the "provider not registered for this
//     realm" refusal, so it is not a cross-tenant username-existence oracle;
//   - an /org/{id} realm still reaches every tenant its org owns;
//   - an UNBOUND (platform-realm) connection still signs in users of every
//     tenant — the regression guard against the easiest wrong fix;
//   - a genuinely new account is still provisioned by a tenant-bound flow;
//   - the elevation door is closed the same way.
//
// The store-side half of the fix (the realm applied inside the lock, beside the
// merge, on BOTH backends) is proved in internal/users/federated_realm_test.go.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/jwks"
	"netops/backend/internal/ssoidp"
)

const realmKID = "realm-kid"

// realmHarness is the per-tenant sign-in fixture (two orgs, two tenants, one
// bound connection each plus one platform-realm connection) wired to a fake IdP
// that speaks both halves of the code flow.
type realmHarness struct {
	f      *signinFixture
	key    *rsa.PrivateKey
	claims map[string]any // what the next token exchange will assert
}

func newRealmHarness(t *testing.T) *realmHarness {
	t.Helper()
	f := newSigninFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	h := &realmHarness{f: f, key: key}

	jwksSrv := fakeIdPEndpoint(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": realmKID, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	})
	tokenSrv := fakeIdPEndpoint(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": h.sign(t, h.claims)})
	})

	// One save, one provider rebuild: every alias this file uses must be in the
	// button list BEFORE the discovery is seeded, because a save swaps the live
	// provider (and with it the JWKS cache).
	cfg := f.s.oidcCfg.effective()
	// A role the merge would visibly rewrite: the victim below is read-only, so
	// a merge that ran leaves fingerprints.
	cfg.DefaultRole = RoleOperator
	cfg.DefaultTenant = TenantGlobal
	cfg.PostLoginURL = "/"
	cfg.Providers = "acme-idp:Acme SSO:oidc,globex-idp:Globex SSO:oidc,shared-idp:Corporate SSO:oidc,globex-elev:Globex Break Glass:oidc:elevation"
	if _, err := f.s.oidcCfg.set(cfg); err != nil {
		t.Fatalf("save oidc config: %v", err)
	}
	// Tenant B's own ELEVATION connection: the second door that mints a session.
	if _, err := f.s.ssoIdPCfg.Set(ssoIdPConfig{
		Alias: "globex-elev", DisplayName: "Globex Break Glass", Protocol: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration", ClientID: "cid",
		TenantID: f.tenantB, Kind: ssoidp.KindElevation,
		Elevation: ssoidp.Elevation{TTLClaim: "access_expires_at", MaxMinutes: 30, ReasonClaim: "change_ticket"},
	}); err != nil {
		t.Fatalf("seed elevation connection: %v", err)
	}

	p := f.s.oidcProvider()
	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.Issuer(),
		AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
		TokenEndpoint: tokenSrv,
		JWKSURI:       jwksSrv,
	})
	if !p.Ready() {
		t.Fatal("the test provider is not ready — the SSO handlers cannot run")
	}
	return h
}

// fakeIdPEndpoint starts one endpoint of the fake IdP and returns its URL.
func fakeIdPEndpoint(t *testing.T, fn http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	return srv.URL
}

func (h *realmHarness) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	b64 := func(v any) string {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(j)
	}
	signing := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": realmKID}) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// roundTrip drives one whole sign-in: the login entry the URL names, the ID
// token the fake IdP mints for that transaction, then the matching callback —
// carrying every cookie the login handed back, exactly as a browser would.
// It returns the callback's redirect fragment.
func (h *realmHarness) roundTrip(t *testing.T, loginPath, callbackPath, subject string, extra map[string]any) url.Values {
	t.Helper()
	resp, b := getWith(t, h.f.srv, loginPath)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login %s: status %d, want 302 (%s)", loginPath, resp.StatusCode, b)
	}
	authURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	state, nonce := authURL.Query().Get("state"), authURL.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("authorize url carried no state/nonce: %s", authURL)
	}
	p := h.f.s.oidcProvider()
	claims := map[string]any{
		"iss": p.Issuer(), "aud": p.ClientID(), "sub": subject, "preferred_username": subject,
		"email": subject + "@attacker.example", "name": "Not The Victim",
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	}
	for k, v := range extra {
		claims[k] = v
	}
	h.claims = claims

	cb, _ := getWith(t, h.f.srv, callbackPath+"?code=abc&state="+url.QueryEscape(state), resp.Cookies()...)
	if cb.StatusCode != http.StatusFound {
		t.Fatalf("callback %s: status %d, want 302", callbackPath, cb.StatusCode)
	}
	return fragmentOf(t, cb)
}

// fragmentOf parses the URL fragment a callback redirect carries — the token on
// success, the sso_error on refusal.
func fragmentOf(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	loc := resp.Header.Get("Location")
	i := strings.IndexByte(loc, '#')
	if i < 0 {
		t.Fatalf("no fragment in redirect %q", loc)
	}
	v, err := url.ParseQuery(loc[i+1:])
	if err != nil {
		t.Fatalf("parse fragment %q: %v", loc, err)
	}
	return v
}

// seedFederated creates the kind of account the attack targets: one an IdP
// provisioned (LDAP here — the unconditional case, since the attacker's own IdP
// has no user of that name), living in a tenant of its own.
func (h *realmHarness) seedFederated(t *testing.T, name, tenant, role, source string) User {
	t.Helper()
	u, err := h.f.s.users.UpsertFederated(name, name+"@victim.example", "Alice Victim", role, source, tenant)
	if err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	return u
}

// ---- 1. the attack ---------------------------------------------------------

// A tenant administrator may register their own identity provider. That must
// buy them their own users and nobody else's.
func TestTenantSSOCannotSignInAnotherTenantsAccount(t *testing.T) {
	h := newRealmHarness(t)
	before := h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly, "ldap")

	// Tenant B's own IdP, tenant B's own URL, a username tenant A owns.
	frag := h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-idp/login", "/t/"+h.f.slugB+"/sso/globex-idp/callback", "alice", nil)

	if frag.Get("token") != "" || frag.Get("refresh") != "" {
		t.Fatal("CROSS-TENANT SESSION MINTED: tenant B's IdP signed in tenant A's account")
	}
	if frag.Get("sso_error") == "" {
		t.Fatal("the callback neither refused nor signed in — no message came back")
	}
	// The merge write is damage of its own: it rewrites role and auth source.
	// Refusing the session is not enough; nothing may have been written.
	after, ok := h.f.s.users.Get("alice")
	if !ok {
		t.Fatal("the victim account vanished")
	}
	if after.TenantID != before.TenantID || after.Role != before.Role || after.AuthSource != before.AuthSource ||
		after.Email != before.Email || after.DisplayName != before.DisplayName {
		t.Fatalf("A REFUSED SIGN-IN STILL REWROTE THE VICTIM: %+v, want %+v", after, before)
	}
}

// The refusal is evidence, and it carries the real reason where only an
// operator can read it (§10 — no silent failures).
func TestTenantSSOForeignAccountRefusalIsAudited(t *testing.T) {
	h := newRealmHarness(t)
	h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly, "ldap")
	h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-idp/login", "/t/"+h.f.slugB+"/sso/globex-idp/callback", "alice", nil)

	events, err := h.f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	for _, e := range events {
		if e.Decision == "deny" && strings.Contains(e.Path, "/sso/globex-idp/callback") {
			if got, _ := e.Detail["reason"].(string); !strings.Contains(got, "realm") {
				t.Errorf("audited reason %q does not name the realm problem", got)
			}
			return
		}
	}
	t.Fatalf("the cross-tenant sign-in was not audited (%d entries)", len(events))
}

// NO EXISTENCE ORACLE. "That account belongs to someone else" and "that provider
// is not registered here" must be the SAME sentence, or a tenant administrator
// can probe for usernames across the whole platform: type a name, read the
// error, learn whether another customer has that user.
func TestTenantSSOForeignAccountRefusalIsIndistinguishable(t *testing.T) {
	h := newRealmHarness(t)
	h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly, "ldap")

	attack := h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-idp/login", "/t/"+h.f.slugB+"/sso/globex-idp/callback", "alice", nil).Get("sso_error")
	if attack == "" {
		t.Fatal("the attack was not refused at all")
	}

	// The same URL, the same alias, the same realm — but now the connection is
	// bound elsewhere, which is the OTHER refusal. The two messages must match
	// byte for byte.
	h.f.bind("globex-idp", "Globex SSO", h.f.tenantA)
	resp, _ := getWith(t, h.f.srv, "/t/"+h.f.slugB+"/sso/globex-idp/callback?code=x&state=y")
	binding := fragmentOf(t, resp).Get("sso_error")

	if attack != binding {
		t.Fatalf("EXISTENCE ORACLE: the foreign-account refusal\n  %q\ndiffers from the binding refusal\n  %q", attack, binding)
	}
	for _, leak := range []string{"alice", "Acme", h.f.tenantA, h.f.slugA} {
		if strings.Contains(attack, leak) {
			t.Errorf("the refusal names %q — it must say nothing about the other realm or the account", leak)
		}
	}
}

// The elevation door mints a session too, and it reads the account by the same
// global username. It is closed the same way — including for an account that
// does not exist, so the pair is not an oracle either.
func TestTenantElevationSSOCannotElevateAnotherTenantsAccount(t *testing.T) {
	h := newRealmHarness(t)
	before := h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly, "ldap")
	grant := map[string]any{
		"access_expires_at": time.Now().Add(5 * time.Minute).Unix(),
		"change_ticket":     "CHG-1",
	}

	frag := h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-elev/login", "/t/"+h.f.slugB+"/sso/globex-elev/callback", "alice", grant)
	if frag.Get("token") != "" {
		t.Fatal("CROSS-TENANT ELEVATION: tenant B's break-glass IdP elevated tenant A's account")
	}
	if _, ok := h.f.s.activeElevation(httptest.NewRequest(http.MethodGet, "http://x/api/x", nil), "alice", ""); ok {
		t.Fatal("a refused elevation login still created a binding")
	}
	if after, _ := h.f.s.users.Get("alice"); after.TenantID != before.TenantID || after.Role != before.Role || after.AuthSource != before.AuthSource {
		t.Fatalf("the elevation path mutated the account: %+v, want %+v", after, before)
	}
	// An account that does not exist must answer identically, or the two answers
	// together are the oracle the refusal above avoids.
	missing := h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-elev/login", "/t/"+h.f.slugB+"/sso/globex-elev/callback", "nobody-at-all", grant)
	if got, want := missing.Get("sso_error"), frag.Get("sso_error"); got != want {
		t.Fatalf("EXISTENCE ORACLE on the elevation door: unknown account says\n  %q\nforeign account says\n  %q", got, want)
	}
}

// ---- 2. everything that must keep working ---------------------------------

// A tenant's own connection still signs its own people in, and still provisions
// the ones it has never seen.
func TestTenantSSOStillSignsInItsOwnAccounts(t *testing.T) {
	h := newRealmHarness(t)
	h.seedFederated(t, "acmeuser", h.f.tenantA, RoleReadOnly, "ldap")

	frag := h.roundTrip(t, "/t/"+h.f.slugA+"/sso/acme-idp/login", "/t/"+h.f.slugA+"/sso/acme-idp/callback", "acmeuser", nil)
	if frag.Get("token") == "" {
		t.Fatalf("a tenant's own account was refused by its own connection: %q", frag.Get("sso_error"))
	}
	// The refresh the IdP is entitled to make on its own users still happens.
	if u, _ := h.f.s.users.Get("acmeuser"); u.Role != RoleOperator || u.AuthSource != "oidc" || u.TenantID != h.f.tenantA {
		t.Errorf("own-realm sign-in did not refresh the account: %+v", u)
	}

	// A brand-new federated account is created in the bound tenant.
	frag = h.roundTrip(t, "/t/"+h.f.slugA+"/sso/acme-idp/login", "/t/"+h.f.slugA+"/sso/acme-idp/callback", "newcomer", nil)
	if frag.Get("token") == "" {
		t.Fatalf("a new account was not provisioned by a tenant-bound flow: %q", frag.Get("sso_error"))
	}
	u, ok := h.f.s.users.Get("newcomer")
	if !ok || u.TenantID != h.f.tenantA {
		t.Fatalf("new account = %+v (ok=%v), want one in the bound tenant %s", u, ok, h.f.tenantA)
	}
}

// An /org/{id} locator is ONE realm over SEVERAL tenants. The check is Reaches,
// never string equality, so an org URL still signs in every tenant its org owns
// — including a sibling of the tenant the connection is bound to.
func TestOrgSSORealmReachesItsMemberTenants(t *testing.T) {
	h := newRealmHarness(t)
	// A second tenant inside org Alpha, and an account that lives in it.
	st, b := do(t, h.f.srv, "POST", "/api/tenants", h.f.admin, map[string]any{"name": "Acme Labs", "org_id": h.f.orgA})
	if st != 201 && st != 200 {
		t.Fatalf("create sibling tenant: %d %s", st, b)
	}
	sibling := idOf(t, b)
	h.seedFederated(t, "sibuser", sibling, RoleReadOnly, "ldap")
	h.seedFederated(t, "acmeuser", h.f.tenantA, RoleReadOnly, "ldap")

	for _, user := range []string{"acmeuser", "sibuser"} {
		frag := h.roundTrip(t, "/org/"+h.f.orgA+"/sso/acme-idp/login", "/org/"+h.f.orgA+"/sso/acme-idp/callback", user, nil)
		if frag.Get("token") == "" {
			t.Fatalf("the org realm refused %s, a member tenant's account: %q", user, frag.Get("sso_error"))
		}
	}
	// It still stops at the org boundary: tenant B is in another org.
	h.seedFederated(t, "globexuser", h.f.tenantB, RoleReadOnly, "ldap")
	frag := h.roundTrip(t, "/org/"+h.f.orgA+"/sso/acme-idp/login", "/org/"+h.f.orgA+"/sso/acme-idp/callback", "globexuser", nil)
	if frag.Get("token") != "" {
		t.Fatal("CROSS-ORG LEAK: org Alpha's URL signed in a tenant of org Beta")
	}
}

// THE EASIEST WRONG FIX. A platform-realm connection keeps the generic callback
// and legitimately signs in users of every tenant. A blanket "flow tenant ==
// account tenant" would break every deployment that predates per-tenant URLs.
func TestPlatformRealmSSOStillSignsInEveryTenant(t *testing.T) {
	h := newRealmHarness(t)
	h.seedFederated(t, "acmeuser", h.f.tenantA, RoleReadOnly, "ldap")
	h.seedFederated(t, "globexuser", h.f.tenantB, RoleReadOnly, "ldap")

	for _, user := range []string{"acmeuser", "globexuser"} {
		frag := h.roundTrip(t, "/api/auth/sso/login?idp=shared-idp", "/api/auth/sso/callback", user, nil)
		if frag.Get("token") == "" {
			t.Fatalf("the platform-realm connection refused %s: %q", user, frag.Get("sso_error"))
		}
		if u, _ := h.f.s.users.Get(user); u.Role != RoleOperator {
			t.Errorf("%s was not refreshed by the unbound flow: %+v", user, u)
		}
	}
	// And it still provisions into the OIDC default tenant, unchanged.
	if frag := h.roundTrip(t, "/api/auth/sso/login?idp=shared-idp", "/api/auth/sso/callback", "platformnew", nil); frag.Get("token") == "" {
		t.Fatalf("the platform-realm connection provisioned nobody: %q", frag.Get("sso_error"))
	}
	if u, ok := h.f.s.users.Get("platformnew"); !ok || u.TenantID != TenantGlobal {
		t.Fatalf("platform-realm provisioning = %+v (ok=%v), want the OIDC default tenant", u, ok)
	}
}
