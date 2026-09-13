// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// sso_realm_isolation_test.go — §3a isolation for the per-tenant SSO callback.
//
// THE DEFECT. Per-tenant SSO URLs (tracker 276) validated three things, and all
// three were properties of the CONNECTION: the locator resolves, the connection
// is registered for the realm in the URL, and the browser started the flow in
// that realm. The ACCOUNT the ID token names was never checked. Usernames were a
// GLOBAL key, and the federated upsert returned an existing account with its
// ORIGINAL tenant, so an administrator of tenant B — who holds
// administration:admin and may therefore register an identity provider of their
// own — could name `alice`, sign in at /t/tenant-b/sso/b-idp/login, and be handed
// a session whose tenant was A. The merge on the way through rewrote the victim's
// role and auth source as well. Every account with no user in the attacker's IdP
// was reachable: LDAP-, TACACS- and bearer-provisioned accounts included.
//
// TRACKER 300 CHANGED WHAT "REACHABLE" MEANS, and this file is updated to say so
// honestly rather than to keep asserting the old shape. An account is now
// addressed by (tenant_id, issuer, subject). A tenant-bound flow derives its
// provisioning tenant from the SAME connection its realm comes from, so the
// tuple it looks up can only ever name its own realm: a subject another tenant
// owns is no longer a reachable account at all — it is simply a subject this
// connection has not seen, and it provisions THIS tenant's own account.
//
// One consequence is recorded deliberately: a cross-tenant ATTEMPT through a
// bound URL is no longer a distinguishable event, so there is no longer a
// refusal to audit there and no existence oracle to prevent. The realm check has
// become defence in depth on that path, and what remains REACHABLE — and is
// still proved below — is the case C3's second half found: a bound connection
// whose tenant stops resolving falls back to the GENERIC callback, so the
// provisioning tenant (the OIDC default) and the realm (the connection's own
// tenant) disagree, and the sign-in is refused with nothing written.
//
// What is proved here, through the REAL router, the REAL code flow and a real
// fake IdP (JWKS + token endpoint):
//   - a tenant-bound connection asserting a subject another tenant owns gets its
//     OWN new account, never a session in the other tenant's, and the victim's
//     record is BYTE-FOR-BYTE unchanged (the merge write is itself the damage);
//   - the generic-callback fallback is refused, writes nothing, and its message
//     names neither the other realm nor the account;
//   - an /org/{id} realm still reaches every tenant its org owns;
//   - an UNBOUND (platform-realm) connection still signs in users of every
//     tenant — the regression guard against the easiest wrong fix;
//   - a genuinely new account is still provisioned by a tenant-bound flow;
//   - the elevation door is closed the same way.
//
// The store-side half (the realm applied inside the lock, beside the merge, on
// BOTH backends, plus the §2.5 realm-scoped resolution) is proved in
// internal/users/identity_contract_test.go and identity_realm_scope_test.go.

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
	"netops/backend/internal/tenant"
	"netops/backend/internal/token"
	"netops/backend/internal/users"
)

const realmKID = "realm-kid"

// realmHarness is the per-tenant sign-in fixture (two orgs, two tenants, one
// bound connection each plus one platform-realm connection) wired to a fake IdP
// that speaks both halves of the code flow.
type realmHarness struct {
	f      *signinFixture
	key    *rsa.PrivateKey
	claims map[string]any // what the next token exchange will assert
	// seeded maps the IdP SUBJECT a test asserts to the account's opaque
	// PRINCIPAL ID (tracker 300): sessions, bindings and elevation grants are all
	// keyed by the id, and a federated account's id is nothing like its subject.
	seeded map[string]string
	// The fake IdP's two endpoints. Kept because ANY save rebuilds the live
	// provider (and with it the JWKS cache), so a test that saves after the
	// harness is built has to seed the discovery again — see seedDiscovery.
	jwksURL, tokenURL string
}

func newRealmHarness(t *testing.T) *realmHarness {
	t.Helper()
	f := newSigninFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	h := &realmHarness{f: f, key: key, seeded: map[string]string{}}

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

	h.jwksURL, h.tokenURL = jwksSrv, tokenSrv
	h.seedDiscovery(t)
	return h
}

// seedDiscovery points the LIVE provider at the fake IdP. Every save of the
// OIDC config swaps that provider, so a test that saves must call this again
// before it signs anyone in.
func (h *realmHarness) seedDiscovery(t *testing.T) {
	t.Helper()
	p := h.f.s.oidcProvider()
	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.Issuer(),
		AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
		TokenEndpoint: h.tokenURL,
		JWKSURI:       h.jwksURL,
	})
	if !p.Ready() {
		t.Fatal("the test provider is not ready — the SSO handlers cannot run")
	}
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

// seedFederated creates the kind of account the attack targets: one the BROKER
// provisioned, living in a tenant of its own, holding the canonical tuple
// (tenant, the broker's issuer, `name`) — which is exactly the tuple a round
// trip asserting subject `name` will look up. Anything else would make these
// tests unreachable rather than passing (an LDAP-tuple account is not
// addressable from an OIDC assertion at all, by design — §5.5).
func (h *realmHarness) seedFederated(t *testing.T, name, tenant, role string) User {
	t.Helper()
	u, err := h.f.s.users.ResolveFederated(users.Assertion{
		Identity: users.Identity{
			TenantID: tenant, Issuer: h.f.s.oidcProvider().Issuer(),
			Subject: name, Protocol: users.ProtocolOIDC,
		},
		Email: name + "@victim.example", DisplayName: "Alice Victim", Role: role,
	}, users.Realm{}, true)
	if err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	if u.ID == name {
		t.Fatalf("fixture rule broken: the account id equals the subject (%q)", u.ID)
	}
	h.seeded[name] = u.ID
	// A standing SSO login mirrors the account into the binding store; the fixture
	// must too, or a test about what an attack does to the mirror has no mirror.
	h.f.s.logBindingSync(u, "oidc")
	return u
}

// principal returns the opaque principal id of a seeded subject.
func (h *realmHarness) principal(t *testing.T, subject string) string {
	t.Helper()
	id, ok := h.seeded[subject]
	if !ok {
		t.Fatalf("subject %q was never seeded", subject)
	}
	return id
}

// accountOf reads the account behind a seeded subject.
func (h *realmHarness) accountOf(t *testing.T, subject string) User {
	t.Helper()
	u, ok := h.f.s.users.Get(h.principal(t, subject))
	if !ok {
		t.Fatalf("the account for subject %q vanished", subject)
	}
	return u
}

// subjectOf resolves the account a round trip's subject ended up in, by the
// canonical tuple the callback would have used. ok=false when no account holds
// it in that tenant.
func (h *realmHarness) accountFor(t *testing.T, tenant, subject string) (User, bool) {
	t.Helper()
	u, err := h.f.s.users.ResolveFederated(users.Assertion{Identity: users.Identity{
		TenantID: tenant, Issuer: h.f.s.oidcProvider().Issuer(),
		Subject: subject, Protocol: users.ProtocolOIDC,
	}}, users.Realm{}, false)
	if err != nil {
		return User{}, false
	}
	return u, true
}

// ---- 1. the attack ---------------------------------------------------------

// A tenant administrator may register their own identity provider. That must
// buy them their own users and nobody else's.
//
// Since tracker 300 the isolation is STRUCTURAL, and the assertion says so: the
// flow's tuple names tenant B, so tenant B's IdP gets tenant B's own account. The
// property that matters — no session in tenant A's account, and not one byte
// written to it — is asserted directly, on the session that WAS issued.
func TestTenantSSOCannotSignInAnotherTenantsAccount(t *testing.T) {
	h := newRealmHarness(t)
	before := h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly)

	// Tenant B's own IdP, tenant B's own URL, a subject tenant A owns.
	frag := h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-idp/login", "/t/"+h.f.slugB+"/sso/globex-idp/callback", "alice", nil)

	if tok := frag.Get("token"); tok != "" {
		// A session exists — it must belong to tenant B's OWN, brand-new account.
		claims, err := token.Verify(tok, jwtSecret())
		if err != nil {
			t.Fatalf("verify the issued token: %v", err)
		}
		if claims.Sub == before.ID {
			t.Fatal("CROSS-TENANT SESSION MINTED: tenant B's IdP signed in tenant A's account")
		}
		if claims.Tenant != h.f.tenantB {
			t.Fatalf("the session's tenant is %q, want tenant B's own %q", claims.Tenant, h.f.tenantB)
		}
		if _, ok := h.accountFor(t, h.f.tenantB, "alice"); !ok {
			t.Fatal("a session was issued but no tenant-B account holds the tuple")
		}
	} else if frag.Get("sso_error") == "" {
		t.Fatal("the callback neither refused nor signed in — no message came back")
	}
	// The merge write is damage of its own: it rewrites role and auth source.
	// Whatever happened to tenant B, tenant A's record may not have moved.
	after := h.accountOf(t, "alice")
	if after.TenantID != before.TenantID || after.Role != before.Role || after.AuthSource != before.AuthSource ||
		after.Email != before.Email || after.DisplayName != before.DisplayName {
		t.Fatalf("ANOTHER REALM'S SIGN-IN REWROTE THE VICTIM: %+v, want %+v", after, before)
	}
	// …and no session of the victim's exists.
	if got := activeSessions(h.f.s, before.ID); len(got) != 0 {
		t.Fatalf("the victim holds %d session(s) after another realm's sign-in, want 0", len(got))
	}
}

// The audit trail must never record ANOTHER TENANT'S account as the actor of a
// sign-in that reached this realm. Before tracker 300 the attempt produced an
// audited deny naming the realm problem; now the attempt is not an attempt at
// all — the tuple names tenant B — so what is asserted is the property that
// outlived the refusal: nothing in the trail, and nothing in the binding mirror,
// attaches tenant B's flow to tenant A's principal.
func TestTenantSSOForeignSubjectNeverAttachesToTheOtherTenantsPrincipal(t *testing.T) {
	h := newRealmHarness(t)
	victim := h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly)
	h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-idp/login", "/t/"+h.f.slugB+"/sso/globex-idp/callback", "alice", nil)

	events, err := h.f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	for _, e := range events {
		if e.Actor == victim.ID && strings.Contains(e.Path, "globex-idp") {
			t.Fatalf("tenant B's flow was recorded as tenant A's principal: %+v", e)
		}
	}
	// The mirror binding of the victim still names tenant A's scope and role.
	found := false
	for _, b := range h.f.s.bindings.ListByPrincipal(victim.ID) {
		found = true
		if b.RoleID != RoleReadOnly {
			t.Errorf("the victim's binding was re-roled to %q by another realm's sign-in", b.RoleID)
		}
	}
	if !found {
		t.Fatal("the victim lost its role binding")
	}
}

// NO EXISTENCE ORACLE. The refusal that is still REACHABLE (the generic-callback
// fallback, C3's second half — see the header) must say nothing about the other
// realm or the account it could not reach, or a tenant administrator can probe
// for accounts across the whole platform: assert a subject, read the error, learn
// whether another customer has that principal.
func TestForeignRealmRefusalNamesNothing(t *testing.T) {
	h := newRealmHarness(t)
	h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly)
	// Tenant B suspended ⇒ its connection's locator stops resolving ⇒ the flow
	// falls back to the generic callback, where the provisioning tenant (the OIDC
	// default) and the realm (tenant B) disagree.
	if _, err := h.f.s.tenants.SetStatus(h.f.tenantB, tenant.StatusSuspended); err != nil {
		t.Fatalf("suspend tenant B: %v", err)
	}
	refusal := h.roundTrip(t, "/api/auth/sso/login?idp=globex-idp", "/api/auth/sso/callback", "alice", nil).Get("sso_error")
	if refusal == "" {
		t.Fatal("the fallback flow was not refused at all")
	}
	for _, leak := range []string{"alice", "Acme", h.f.tenantA, h.f.slugA, h.f.tenantB, h.f.slugB} {
		if strings.Contains(refusal, leak) {
			t.Errorf("the refusal %q names %q — it must say nothing about a realm or an account", refusal, leak)
		}
	}
	// A subject nobody holds is refused with the SAME sentence, so the pair is
	// not an oracle either.
	unknown := h.roundTrip(t, "/api/auth/sso/login?idp=globex-idp", "/api/auth/sso/callback", "nobody-at-all", nil).Get("sso_error")
	if unknown != refusal {
		t.Fatalf("EXISTENCE ORACLE: a known subject says\n  %q\nan unknown one says\n  %q", refusal, unknown)
	}
}

// The elevation door mints a session too, and it reads the account by the same
// global username. It is closed the same way — including for an account that
// does not exist, so the pair is not an oracle either.
func TestTenantElevationSSOCannotElevateAnotherTenantsAccount(t *testing.T) {
	h := newRealmHarness(t)
	before := h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly)
	grant := map[string]any{
		"access_expires_at": time.Now().Add(5 * time.Minute).Unix(),
		"change_ticket":     "CHG-1",
	}

	frag := h.roundTrip(t, "/t/"+h.f.slugB+"/sso/globex-elev/login", "/t/"+h.f.slugB+"/sso/globex-elev/callback", "alice", grant)
	if frag.Get("token") != "" {
		t.Fatal("CROSS-TENANT ELEVATION: tenant B's break-glass IdP elevated tenant A's account")
	}
	if _, ok := h.f.s.activeElevation(httptest.NewRequest(http.MethodGet, "http://x/api/x", nil), before.ID, ""); ok {
		t.Fatal("a refused elevation login still created a binding")
	}
	if after := h.accountOf(t, "alice"); after.TenantID != before.TenantID || after.Role != before.Role || after.AuthSource != before.AuthSource {
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
	h.seedFederated(t, "acmeuser", h.f.tenantA, RoleReadOnly)

	frag := h.roundTrip(t, "/t/"+h.f.slugA+"/sso/acme-idp/login", "/t/"+h.f.slugA+"/sso/acme-idp/callback", "acmeuser", nil)
	if frag.Get("token") == "" {
		t.Fatalf("a tenant's own account was refused by its own connection: %q", frag.Get("sso_error"))
	}
	// The refresh the IdP is entitled to make on its own users still happens.
	if u := h.accountOf(t, "acmeuser"); u.Role != RoleOperator || u.AuthSource != "oidc" || u.TenantID != h.f.tenantA {
		t.Errorf("own-realm sign-in did not refresh the account: %+v", u)
	}

	// A brand-new federated account is created in the bound tenant.
	frag = h.roundTrip(t, "/t/"+h.f.slugA+"/sso/acme-idp/login", "/t/"+h.f.slugA+"/sso/acme-idp/callback", "newcomer", nil)
	if frag.Get("token") == "" {
		t.Fatalf("a new account was not provisioned by a tenant-bound flow: %q", frag.Get("sso_error"))
	}
	u, ok := h.accountFor(t, h.f.tenantA, "newcomer")
	if !ok || u.TenantID != h.f.tenantA {
		t.Fatalf("new account = %+v (ok=%v), want one in the bound tenant %s", u, ok, h.f.tenantA)
	}
	if u.Username != u.ID {
		t.Errorf("a JIT-provisioned account has a login handle %q — a federated account's username IS its opaque id", u.Username)
	}
}

// THE BARE SIGN-IN PAGE AND A TENANT-BOUND CONNECTION (review 3.7-06).
//
// The generic page used to list every configured connection, on the stated
// grounds that it is the platform's front door and existing deployments depend
// on it. That reasoning holds for PLATFORM-REALM connections and does not hold
// for tenant-bound ones, which did not exist before locators and cannot work
// from that page at all: the flow is handed the connection's own /t/{slug}
// callback, and handleTenantSSO's third check refuses any callback whose
// browser is not holding the matching locator cookie — which a browser on the
// bare page is not. The customer was sent to their IdP, made to authenticate,
// and refused on the way back.
//
// This test drives that refusal through the real flow, so the button list is
// narrowed for a reason that is demonstrated rather than asserted.
func TestGenericEntryCannotUseABoundConnection(t *testing.T) {
	h := newRealmHarness(t)
	h.seedFederated(t, "acmeuser", h.f.tenantA, RoleReadOnly)

	// The flow a bare-page button would start: no locator cookie anywhere.
	frag := h.roundTrip(t, "/api/auth/sso/login?idp=acme-idp",
		"/t/"+h.f.slugA+"/sso/acme-idp/callback", "acmeuser", nil)
	if frag.Get("token") != "" {
		t.Fatalf("a bound connection signed in from the generic entry — if this now WORKS, " +
			"the button belongs back on the bare page and providerVisible should be reverted")
	}
	if frag.Get("sso_error") == "" {
		t.Fatalf("no token and no error: %v", frag)
	}
	// The account is untouched by the refused round trip.
	if u := h.accountOf(t, "acmeuser"); u.Role != RoleReadOnly || u.TenantID != h.f.tenantA {
		t.Fatalf("the refused flow still rewrote the account: %+v", u)
	}

	// Which is why the bare page must not offer it. The SAME connection is
	// still offered at its own locator, so nothing legitimate is lost.
	if h.f.s.providerVisible(nil, "acme-idp") {
		t.Errorf("acme-idp is offered on the bare sign-in page, where clicking it can only fail")
	}
	acme := locatorFor(t, h.f.srv, "/t/"+h.f.slugA)
	if got := ssoButtons(t, h.f.srv, acme); len(got) == 0 {
		t.Errorf("acme-idp must still be offered at Acme's own sign-in URL, got %v", got)
	}

	// An UNBOUND connection is the front door's own button and still works from
	// the generic entry — the regression guard against over-narrowing.
	if !h.f.s.providerVisible(nil, "shared-idp") {
		t.Fatalf("the unbound platform-realm connection was hidden from the bare sign-in page")
	}
	h.seedFederated(t, "corpuser", h.f.tenantB, RoleReadOnly)
	frag = h.roundTrip(t, "/api/auth/sso/login?idp=shared-idp", "/api/auth/sso/callback", "corpuser", nil)
	if frag.Get("token") == "" {
		t.Fatalf("the platform-realm button stopped working from the bare page: %q", frag.Get("sso_error"))
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
	h.seedFederated(t, "sibuser", sibling, RoleReadOnly)
	h.seedFederated(t, "acmeuser", h.f.tenantA, RoleReadOnly)

	for _, user := range []string{"acmeuser", "sibuser"} {
		frag := h.roundTrip(t, "/org/"+h.f.orgA+"/sso/acme-idp/login", "/org/"+h.f.orgA+"/sso/acme-idp/callback", user, nil)
		if frag.Get("token") == "" {
			t.Fatalf("the org realm refused %s, a member tenant's account: %q", user, frag.Get("sso_error"))
		}
	}
	// It still stops at the org boundary. Since tracker 300 the boundary is in the
	// KEY: org Alpha's URL derives its provisioning tenant from a connection org
	// Alpha owns, so the tuple it looks up names org Alpha and the realm-scoped
	// fallback (§2.5 Amendment) reaches only org Alpha's tenants. Org Beta's
	// account is therefore not reachable at all — the sign-in provisions org
	// Alpha's OWN account instead, and must not be a session in org Beta's.
	victim := h.seedFederated(t, "globexuser", h.f.tenantB, RoleReadOnly)
	frag := h.roundTrip(t, "/org/"+h.f.orgA+"/sso/acme-idp/login", "/org/"+h.f.orgA+"/sso/acme-idp/callback", "globexuser", nil)
	if tok := frag.Get("token"); tok != "" {
		claims, err := token.Verify(tok, jwtSecret())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if claims.Sub == victim.ID {
			t.Fatal("CROSS-ORG LEAK: org Alpha's URL signed in a tenant of org Beta")
		}
		if claims.Tenant == h.f.tenantB {
			t.Fatalf("org Alpha's URL minted a session in org Beta's tenant %q", claims.Tenant)
		}
	}
	if after := h.accountOf(t, "globexuser"); after.Role != victim.Role || after.TenantID != victim.TenantID {
		t.Fatalf("org Alpha's sign-in rewrote org Beta's account: %+v, want %+v", after, victim)
	}
}

// THE EASIEST WRONG FIX. A platform-realm connection keeps the generic callback
// and legitimately signs in users of every tenant. A blanket "flow tenant ==
// account tenant" would break every deployment that predates per-tenant URLs.
func TestPlatformRealmSSOStillSignsInEveryTenant(t *testing.T) {
	h := newRealmHarness(t)
	h.seedFederated(t, "acmeuser", h.f.tenantA, RoleReadOnly)
	h.seedFederated(t, "globexuser", h.f.tenantB, RoleReadOnly)

	for _, user := range []string{"acmeuser", "globexuser"} {
		frag := h.roundTrip(t, "/api/auth/sso/login?idp=shared-idp", "/api/auth/sso/callback", user, nil)
		if frag.Get("token") == "" {
			t.Fatalf("the platform-realm connection refused %s: %q", user, frag.Get("sso_error"))
		}
		if u := h.accountOf(t, user); u.Role != RoleOperator {
			t.Errorf("%s was not refreshed by the unbound flow: %+v", user, u)
		}
	}
	// And it still provisions into the OIDC default tenant, unchanged.
	if frag := h.roundTrip(t, "/api/auth/sso/login?idp=shared-idp", "/api/auth/sso/callback", "platformnew", nil); frag.Get("token") == "" {
		t.Fatalf("the platform-realm connection provisioned nobody: %q", frag.Get("sso_error"))
	}
	if u, ok := h.accountFor(t, TenantGlobal, "platformnew"); !ok || u.TenantID != TenantGlobal {
		t.Fatalf("platform-realm provisioning = %+v (ok=%v), want the OIDC default tenant", u, ok)
	}
}

// ---- 3. the realm must not evaporate when the URL stops naming one ---------

// THE SECOND HALF OF C3. The account check above reads the realm out of the
// CALLBACK URL, and ssoLoginRedirectURI normally guarantees a tenant-bound
// connection is sent back to its own /t/{slug}/… callback. That guarantee ends
// the moment the connection's tenant stops RESOLVING: tenantlocator.ResolveID
// only resolves ACTIVE tenants, so a SUSPENDED tenant makes connectionLocator
// fail, the flow falls back to the generic /api/auth/sso/callback, and
// ssoCallbackRealm hands back an unconstrained users.Realm{}.
//
// Tenant B's own connection then signed in tenant A's `alice` and the merge
// rewrote her role, e-mail, display name and auth source — the whole C3 attack,
// through a door the first fix left open. Suspension must take privileges away,
// never hand out a platform-wide skeleton key.
func TestTenantSSOCannotSignInAnotherTenantsAccountWhenItsOwnLocatorStopsResolving(t *testing.T) {
	h := newRealmHarness(t)
	before := h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly)
	if _, err := h.f.s.tenants.SetStatus(h.f.tenantB, tenant.StatusSuspended); err != nil {
		t.Fatalf("suspend tenant B: %v", err)
	}
	if _, ok := h.f.s.connectionLocator("globex-idp"); ok {
		t.Fatal("precondition gone: tenant B's connection still resolves, so this test is not exercising the fallback")
	}

	frag := h.roundTrip(t, "/api/auth/sso/login?idp=globex-idp", "/api/auth/sso/callback", "alice", nil)
	if frag.Get("token") != "" || frag.Get("refresh") != "" {
		t.Fatalf("CROSS-TENANT SIGN-IN: tenant B's connection minted a session for %s of tenant %s", before.Username, before.TenantID)
	}
	after := h.accountOf(t, "alice")
	// The merge write IS the damage: it rewrites role, e-mail, display name and
	// auth source. Refusing the session is not enough; nothing may have been
	// written.
	if after.TenantID != before.TenantID || after.Role != before.Role || after.AuthSource != before.AuthSource ||
		after.Email != before.Email || after.DisplayName != before.DisplayName {
		t.Fatalf("A REFUSED SIGN-IN STILL REWROTE THE VICTIM: %+v, want %+v", after, before)
	}
}

// The elevation door mints a session too, and it read the same realm. It is
// closed by the same helper.
func TestTenantElevationSSOCannotElevateAnotherTenantsAccountWhenItsLocatorStopsResolving(t *testing.T) {
	h := newRealmHarness(t)
	before := h.seedFederated(t, "alice", h.f.tenantA, RoleReadOnly)
	if _, err := h.f.s.tenants.SetStatus(h.f.tenantB, tenant.StatusSuspended); err != nil {
		t.Fatalf("suspend tenant B: %v", err)
	}

	frag := h.roundTrip(t, "/api/auth/sso/login?idp=globex-elev", "/api/auth/sso/callback", "alice",
		map[string]any{"access_expires_at": time.Now().Add(20 * time.Minute).Format(time.RFC3339), "change_ticket": "CHG-1"})
	if frag.Get("token") != "" {
		t.Fatalf("CROSS-TENANT ELEVATION: tenant B's elevation connection signed in %s of tenant %s", before.Username, before.TenantID)
	}
}

// A platform-realm connection whose registration names no tenant is unaffected:
// ssoConnectionRealm returns no constraint, so the generic front door still
// signs in every tenant. This is the same regression guard as
// TestPlatformRealmSSOStillSignsInEveryTenant, re-stated against the new helper
// so a future edit cannot tighten it by accident.
func TestConnectionRealmLeavesTheUnboundFrontDoorAlone(t *testing.T) {
	h := newRealmHarness(t)
	if rl := h.f.s.ssoConnectionRealm("shared-idp"); rl.Reaches != nil {
		t.Fatal("the unbound connection grew a realm constraint; every pre-locator deployment signs in through it")
	}
	rl := h.f.s.ssoConnectionRealm("globex-idp")
	if rl.Reaches == nil {
		t.Fatal("a TENANT-BOUND connection must carry a realm constraint")
	}
	if !rl.Permits(h.f.tenantB) {
		t.Error("tenant B's connection must still reach tenant B's own accounts")
	}
	if rl.Permits(h.f.tenantA) {
		t.Error("tenant B's connection must not reach tenant A's accounts")
	}
}
