// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// identity_doors_test.go — design §5 at the DOOR level: the HTTP-visible half of
// tracker 300. The store-side halves are in internal/users (identity_contract,
// identity_realm_scope, identity_guard_contract).
//
// What is proved here, through the real handlers:
//   §5.6  local auth is its own namespace — two tenants both own an `admin`, a
//         per-tenant sign-in URL resolves to the right one, and an ambiguous
//         name on the generic page is refused with the SAME generic 401 an
//         unknown name gets, audited as login.ambiguous_local_identity;
//   §5.9  the legacy lazy bind is bounded AND observable at the door: the audit
//         event and the counter fire exactly once;
//   §4    the fan-out: the JWT `sub`, the session, the refresh token, the
//         binding mirror, the audit actor and the /api/users handle are ALL the
//         principal id — and a login name no longer addresses any of them;
//   §3    the boot gate refuses to start a store whose invariants do not hold.
//
// §5.7 (bearer keyed by the tuple) is bearer_identity_key_test.go and §5.8 (the
// C3 realm rule, including the suspended-tenant realm source) is
// sso_realm_isolation_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/token"
	"netops/backend/internal/users"
)

// ---------------------------------------------------------------------------
// §5.6 — local auth is its own namespace
// ---------------------------------------------------------------------------

func TestLocalLoginIsPerTenantNamespace(t *testing.T) {
	f := newSigninFixture(t)

	// The SAME login name in two tenants. Before tracker 300 the second create
	// failed with `user "opsadmin" already exists`.
	for _, tenant := range []string{f.tenantA, f.tenantB} {
		st, b := do(t, f.srv, "POST", "/api/users", f.admin, map[string]any{
			"username": "opsadmin", "password": "Passw0rd!2345", "role": RoleReadOnly, "tenant_id": tenant,
		})
		if st != 201 && st != 200 {
			t.Fatalf("create opsadmin in %s: %d %s", tenant, st, b)
		}
	}
	idA := principalIDIn(t, f.s, f.tenantA, "opsadmin")
	idB := principalIDIn(t, f.s, f.tenantB, "opsadmin")
	if idA == idB {
		t.Fatalf("the two tenants' opsadmin share a principal id (%q)", idA)
	}
	// FIXTURE RULE (design §5): the id is not the login name, so any path still
	// keying on the name fails loudly.
	for _, id := range []string{idA, idB} {
		if id == "opsadmin" {
			t.Fatalf("fixture rule broken: id %q equals the login name", id)
		}
		if !strings.HasPrefix(id, userIDPrefix) {
			t.Fatalf("a new local account got id %q, want the opaque %q form", id, userIDPrefix)
		}
	}

	// THE PER-TENANT SIGN-IN URL IS THE DISAMBIGUATOR. Tenant A's entry URL arms
	// a candidate cookie; the login then resolves inside tenant A and nowhere
	// else.
	for _, tc := range []struct{ slug, wantID, wantTenant string }{
		{f.slugA, idA, f.tenantA},
		{f.slugB, idB, f.tenantB},
	} {
		ck := locatorFor(t, f.srv, "/t/"+tc.slug)
		lr := loginWithCookies(t, f.srv, "opsadmin", "Passw0rd!2345", ck)
		claims, err := token.Verify(lr.Token, jwtSecret())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if claims.Sub != tc.wantID {
			t.Fatalf("sign-in at /t/%s reached %q, want %q", tc.slug, claims.Sub, tc.wantID)
		}
		if claims.Tenant != tc.wantTenant {
			t.Fatalf("sign-in at /t/%s acted as tenant %q, want %q", tc.slug, claims.Tenant, tc.wantTenant)
		}
		if lr.User.ID != tc.wantID {
			t.Errorf("login response id = %q, want %q", lr.User.ID, tc.wantID)
		}
	}
}

func TestAmbiguousLocalLoginIsRefusedGenericallyAndAudited(t *testing.T) {
	f := newSigninFixture(t)
	for _, tenant := range []string{f.tenantA, f.tenantB} {
		if st, b := do(t, f.srv, "POST", "/api/users", f.admin, map[string]any{
			"username": "shared", "password": "Passw0rd!2345", "role": RoleReadOnly, "tenant_id": tenant,
		}); st != 201 && st != 200 {
			t.Fatalf("create shared in %s: %d %s", tenant, st, b)
		}
	}

	// The GENERIC sign-in page: no locator, so the name names two accounts.
	st, body := do(t, f.srv, "POST", "/api/auth/login", "", map[string]string{
		"username": "shared", "password": "Passw0rd!2345",
	})
	if st != http.StatusUnauthorized {
		t.Fatalf("ambiguous local login: status %d (%s), want 401", st, body)
	}
	if strings.Contains(string(body), `"token"`) {
		t.Fatalf("the refusal carried a token: %s", body)
	}
	// NO ORACLE: an unknown name gets the identical answer, byte for byte.
	unknown, unknownBody := do(t, f.srv, "POST", "/api/auth/login", "", map[string]string{
		"username": "nobody-at-all", "password": "Passw0rd!2345",
	})
	if unknown != st || string(unknownBody) != string(body) {
		t.Fatalf("EXISTENCE ORACLE: ambiguous says %d %s, unknown says %d %s", st, body, unknown, unknownBody)
	}
	// …and the refusal names no tenant.
	for _, leak := range []string{f.tenantA, f.tenantB, f.slugA, f.slugB} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the refusal names %q", leak)
		}
	}

	// It IS audited, with the count and nothing else.
	events, err := f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	found := false
	for _, e := range events {
		if action, _ := e.Detail["action"].(string); action != "login.ambiguous_local_identity" {
			continue
		}
		found = true
		if e.Decision != "deny" {
			t.Errorf("decision = %q, want deny", e.Decision)
		}
		// The in-memory trail keeps Go values; a JSON round trip makes them
		// float64. Accept either rather than pinning the transport.
		switch n := e.Detail["tenants"].(type) {
		case int:
			if n != 2 {
				t.Errorf("audited tenant count = %d, want 2", n)
			}
		case float64:
			if int(n) != 2 {
				t.Errorf("audited tenant count = %v, want 2", n)
			}
		default:
			t.Errorf("audited tenant count has type %T (%v)", n, n)
		}
		for k, v := range e.Detail {
			if s, ok := v.(string); ok && (s == f.tenantA || s == f.tenantB) {
				t.Errorf("the audit detail names a tenant in %q: %v", k, v)
			}
		}
	}
	if !found {
		t.Fatalf("the ambiguous sign-in was not audited (%d entries)", len(events))
	}

	// And the per-tenant URL still works, which is the whole point of the
	// message the user is given.
	ck := locatorFor(t, f.srv, "/t/"+f.slugA)
	if lr := loginWithCookies(t, f.srv, "shared", "Passw0rd!2345", ck); lr.Token == "" {
		t.Fatal("the per-tenant sign-in URL did not resolve the ambiguity")
	}
}

// ---------------------------------------------------------------------------
// §5.9 — the legacy lazy bind is observable at the door
// ---------------------------------------------------------------------------

func TestLegacyLazyBindIsAuditedAndCounted(t *testing.T) {
	_, s := newTestServerState(t)
	seeder, ok := s.users.(users.LegacySeeder)
	if !ok {
		t.Fatalf("%T cannot seed a legacy row", s.users)
	}
	// A PRE-TRACKER-300 row: id == lower(username), auth_source ldap, no identity.
	// CreatedAt is well before the marker the store wrote when this store opened.
	legacy := User{
		Username: "legacy-ldap", Role: RoleReadOnly, Status: "active",
		AuthSource: users.ProtocolLDAP, Email: "legacy@old.example",
		// Old enough to be PRE-MARKER (the marker is stamped when this store
		// opens), young enough that account_validity_days does not refuse it —
		// this test is about the bind, not about the lifecycle gates.
		CreatedAt: time.Now().UTC().Add(-time.Hour),
	}
	if err := seeder.SeedLegacyForTest(legacy); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	before := s.identityLegacyBinds.Load()

	// The LDAP door signs that person in for the first time since the migration.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/ldap/login", nil)
	s.completeFederatedLogin(rec, r, ldapAssertion(
		ldapConfig{Host: "dir.example.com", DefaultTenant: TenantGlobal},
		&ldapIdentity{DN: "cn=legacy-ldap,ou=people,dc=example,dc=com", Email: "legacy@dir.example"},
		"legacy-ldap", RoleReadOnly))
	if rec.Code != http.StatusOK {
		t.Fatalf("the legacy account's own door was refused: %d (%s)", rec.Code, rec.Body.String())
	}
	// It was ADOPTED, not duplicated: the same row, now holding its tuple.
	adopted, found := s.users.Get("legacy-ldap")
	if !found {
		t.Fatal("the legacy row vanished")
	}
	if adopted.IdentityPending() {
		t.Fatal("the account was not bound to its canonical identity")
	}
	if got := adopted.Identity.Provenance; got != users.ProvenanceLegacyLazyBound {
		t.Fatalf("provenance = %q, want %q", got, users.ProvenanceLegacyLazyBound)
	}
	// COUNTED — the exception is flagged for the owner's veto, so it has to be
	// measurable.
	if after := s.identityLegacyBinds.Load(); after != before+1 {
		t.Fatalf("netops_identity_legacy_bound_total went %d → %d, want +1", before, after)
	}
	// …and AUDITED, with the ACCOUNT as the actor and the issuer/protocol beside it.
	events, err := s.audit.List("", true, auditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	seen := 0
	for _, e := range events {
		if action, _ := e.Detail["action"].(string); action != "identity.legacy_bound" {
			continue
		}
		seen++
		if e.Actor != adopted.ID {
			t.Errorf("audit actor = %q, want the adopted account %q", e.Actor, adopted.ID)
		}
		if iss, _ := e.Detail["issuer"].(string); !strings.HasPrefix(iss, "ldap:") {
			t.Errorf("audited issuer = %q, want the ldap namespace", iss)
		}
		if p, _ := e.Detail["protocol"].(string); p != users.ProtocolLDAP {
			t.Errorf("audited protocol = %q, want %q", p, users.ProtocolLDAP)
		}
		if prov, _ := e.Detail["provenance"].(string); prov != users.ProvenanceLegacyLazyBound {
			t.Errorf("audited provenance = %q", prov)
		}
	}
	if seen != 1 {
		t.Fatalf("identity.legacy_bound audited %d times, want exactly 1", seen)
	}

	// A SECOND, DIFFERENT subject presenting the same legacy name gets a FRESH
	// account, and nothing is bound again.
	rec2 := httptest.NewRecorder()
	s.completeFederatedLogin(rec2, r, ldapAssertion(
		ldapConfig{Host: "dir.example.com", DefaultTenant: TenantGlobal},
		&ldapIdentity{DN: "cn=impostor,ou=people,dc=example,dc=com"},
		"legacy-ldap", RoleReadOnly))
	if rec2.Code != http.StatusOK {
		t.Fatalf("the second subject: %d (%s)", rec2.Code, rec2.Body.String())
	}
	if after := s.identityLegacyBinds.Load(); after != before+1 {
		t.Fatalf("a second subject bound again: counter %d, want %d", after, before+1)
	}
}

// ---------------------------------------------------------------------------
// §4 — the fan-out
// ---------------------------------------------------------------------------

func TestSessionsAndBindingsAreKeyedByPrincipalID(t *testing.T) {
	srv, s := newTestServerState(t)
	st, b := do(t, srv, "POST", "/api/users", adminToken(t, srv), map[string]any{
		"username": "fanout", "password": "Passw0rd!2345", "role": RoleReadOnly,
	})
	if st != 201 && st != 200 {
		t.Fatalf("create: %d %s", st, b)
	}
	var created publicUser
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatal(err)
	}
	id := created.ID
	if id == "" || id == "fanout" {
		t.Fatalf("publicUser.id = %q, want an opaque principal id", id)
	}
	if created.IdentityStatus != "bound" {
		t.Errorf("identity_status = %q, want bound (a local account is backfilled at create)", created.IdentityStatus)
	}

	lr := login(t, srv, "fanout", "Passw0rd!2345")

	// 1. the JWT subject IS the id.
	claims, err := token.Verify(lr.Token, jwtSecret())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Sub != id {
		t.Fatalf("JWT sub = %q, want the principal id %q", claims.Sub, id)
	}

	// 2. the SESSION is keyed by the id, and revoking BY THE ID kills it.
	if got := activeSessions(s, id); len(got) != 1 {
		t.Fatalf("sessions for the id: %d, want 1", len(got))
	}
	if got := activeSessions(s, "fanout"); len(got) != 0 {
		t.Fatalf("the login name still addresses %d session(s) — it is not a key any more", len(got))
	}
	n, err := s.sessions.RevokeAllForUser(id)
	if err != nil || n != 1 {
		t.Fatalf("RevokeAllForUser(id) = %d, %v; want 1, nil", n, err)
	}
	if got := activeSessions(s, id); len(got) != 0 {
		t.Fatalf("%d session(s) survived a revoke by id", len(got))
	}

	// 3. the REFRESH token resolves the id.
	if _, principal, _, err := s.refresh.RotateSession(lr.RefreshToken); err != nil {
		t.Fatalf("rotate: %v", err)
	} else if principal != id {
		t.Fatalf("refresh token names %q, want the principal id %q", principal, id)
	}

	// 4. the BINDING MIRROR is keyed by the id.
	if bs := s.bindings.ListByPrincipal(id); len(bs) != 1 {
		t.Fatalf("bindings for the id: %d, want the one mirror binding", len(bs))
	}
	if bs := s.bindings.ListByPrincipal("fanout"); len(bs) != 0 {
		t.Fatalf("%d binding(s) are still keyed by the login name", len(bs))
	}

	// 5. the /api/users HANDLE is the id, and the login name is not found.
	tok := adminToken(t, srv)
	if st, b := do(t, srv, "PATCH", "/api/users/"+id, tok, map[string]any{"display_name": "Fan Out"}); st != 200 {
		t.Fatalf("PATCH by id: %d %s", st, b)
	}
	if st, _ := do(t, srv, "PATCH", "/api/users/fanout", tok, map[string]any{"display_name": "x"}); st != 404 {
		t.Errorf("PATCH by login name: status %d, want 404 — a name does not address an account", st)
	}

	// 6. the AUDIT ACTOR is the id. A fresh sign-in, because the session above was
	// deliberately revoked.
	again := login(t, srv, "fanout", "Passw0rd!2345")
	if st, b := do(t, srv, "GET", "/api/devices", again.Token, nil); st != 200 {
		t.Fatalf("authed request: %d %s", st, b)
	}
	events, err := s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	for _, e := range events {
		if e.Actor == "fanout" {
			t.Fatalf("the audit trail records the LOGIN NAME as an actor: %+v", e)
		}
	}

	// 7. DELETE by id removes the bindings with it.
	if st, b := do(t, srv, "DELETE", "/api/users/"+id, tok, nil); st != 204 {
		t.Fatalf("DELETE by id: %d %s", st, b)
	}
	if bs := s.bindings.ListByPrincipal(id); len(bs) != 0 {
		t.Fatalf("%d binding(s) survived the delete", len(bs))
	}
}

func TestPerTenantUsernameCollisionIs409(t *testing.T) {
	srv, _ := newTestServerState(t)
	tok := adminToken(t, srv)
	body := map[string]any{"username": "dup", "password": "Passw0rd!2345", "role": RoleReadOnly}
	if st, b := do(t, srv, "POST", "/api/users", tok, body); st != 201 && st != 200 {
		t.Fatalf("first create: %d %s", st, b)
	}
	st, b := do(t, srv, "POST", "/api/users", tok, body)
	if st != http.StatusConflict {
		t.Fatalf("duplicate login name in one tenant: status %d (%s), want 409", st, b)
	}
}

func TestPendingIdentityIsVisibleToTheAdmin(t *testing.T) {
	srv, s := newTestServerState(t)
	seeder, ok := s.users.(users.LegacySeeder)
	if !ok {
		t.Fatalf("%T cannot seed a legacy row", s.users)
	}
	if err := seeder.SeedLegacyForTest(User{
		Username: "pending-fed", Role: RoleReadOnly, Status: "active",
		AuthSource: users.ProtocolOIDC, CreatedAt: time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tok := adminToken(t, srv)

	st, b := do(t, srv, "GET", "/api/users?identity=pending", tok, nil)
	if st != 200 {
		t.Fatalf("list pending: %d %s", st, b)
	}
	var pending []publicUser
	if err := json.Unmarshal(b, &pending); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != "pending-fed" {
		t.Fatalf("?identity=pending returned %+v, want only the unbound legacy row", pending)
	}
	if pending[0].IdentityStatus != "pending" {
		t.Errorf("identity_status = %q, want pending", pending[0].IdentityStatus)
	}
	// The unfiltered list holds both it and the bootstrap admin, and the admin is
	// BOUND — the local backfill ran.
	st, b = do(t, srv, "GET", "/api/users", tok, nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var all []publicUser
	if err := json.Unmarshal(b, &all); err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Fatalf("the unfiltered list dropped rows: %+v", all)
	}
	for _, u := range all {
		if u.Username == "admin" && u.IdentityStatus != "bound" {
			t.Errorf("the local admin is %q, want bound", u.IdentityStatus)
		}
	}
}

// The §2.6 counter must actually reach /metrics. A counter nothing scrapes is not
// a signal — and this one is the evidence the owner judges the lazy-bind
// exception on.
func TestLegacyBindCounterIsExposedOnMetrics(t *testing.T) {
	_, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)
	w := httptest.NewRecorder()
	s.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := w.Body.String()
	for _, want := range []string{
		"# TYPE netops_identity_legacy_bound_total counter",
		"netops_identity_legacy_bound_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %q — the §2.6 exception stays unmeasurable without it", want)
		}
	}
}

// §3a rule 5 — the isolation test the new ?identity=pending surface owes. The
// filter narrows an already tenant-scoped list; this proves it never widens one.
func TestPendingIdentityListIsTenantScoped(t *testing.T) {
	f := newSigninFixture(t)
	seeder, ok := f.s.users.(users.LegacySeeder)
	if !ok {
		t.Fatalf("%T cannot seed a legacy row", f.s.users)
	}
	// One pending legacy account in each tenant.
	for name, tenant := range map[string]string{"pending-a": f.tenantA, "pending-b": f.tenantB} {
		if err := seeder.SeedLegacyForTest(User{
			Username: name, Role: RoleReadOnly, Status: "active", TenantID: tenant,
			AuthSource: users.ProtocolOIDC, CreatedAt: time.Now().UTC().Add(-time.Hour),
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	// A tenant-A administrator.
	if _, err := f.s.users.CreateFull(User{Username: "a-admin", Role: RoleSuperAdmin, TenantID: f.tenantA}, "Passw0rd!2345"); err != nil {
		t.Fatalf("create tenant admin: %v", err)
	}
	tokA := login(t, f.srv, "a-admin", "Passw0rd!2345").Token

	st, b := do(t, f.srv, "GET", "/api/users?identity=pending", tokA, nil)
	if st != 200 {
		t.Fatalf("tenant admin list pending: %d %s", st, b)
	}
	var got []publicUser
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "pending-a" {
		t.Fatalf("?identity=pending returned %+v, want only tenant A's pending row", got)
	}
	// The platform owner still sees both — the filter narrows, it does not scope.
	st, b = do(t, f.srv, "GET", "/api/users?identity=pending", f.admin, nil)
	if st != 200 {
		t.Fatalf("platform list pending: %d %s", st, b)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("platform owner saw %d pending rows, want 2", len(got))
	}
	// An unrecognised filter value narrows nothing and widens nothing.
	st, b = do(t, f.srv, "GET", "/api/users?identity=bogus", tokA, nil)
	if st != 200 {
		t.Fatalf("bogus filter: %d %s", st, b)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, u := range got {
		if u.TenantID != f.tenantA {
			t.Fatalf("an unrecognised filter widened the tenant scope: %+v", u)
		}
	}
}

// ---------------------------------------------------------------------------
// §3 Enforce — the boot gate
// ---------------------------------------------------------------------------

func TestBootRefusesAStoreWhoseIdentityInvariantsFail(t *testing.T) {
	dir := t.TempDir()
	store, err := users.NewFileStore(dir+"/users.json", userDeps())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// A converged store passes.
	if _, err := store.Create("admin", "Passw0rd!2345", RoleSuperAdmin); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := verifyIdentityInvariantsAtBoot(store); err != nil {
		t.Fatalf("a store built through the new API failed the boot gate: %v", err)
	}
	// A LOCAL account with no identity does not: the boot gate refuses, and says
	// plainly that it repaired nothing.
	if err := store.SeedLegacyForTest(User{
		Username: "unbackfilled", Role: RoleReadOnly, AuthSource: users.ProtocolLocal,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err = verifyIdentityInvariantsAtBoot(store)
	if err == nil {
		t.Fatal("the boot gate accepted a store with an unbackfilled LOCAL account")
	}
	for _, want := range []string{"identity invariants", "nothing was repaired or deleted", "unbackfilled"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q", err, want)
		}
	}
	// It REFUSED; it did not repair.
	if u, ok := store.Get("unbackfilled"); !ok || !u.IdentityPending() {
		t.Fatalf("the boot gate mutated the estate: %+v (ok=%v)", u, ok)
	}
	// A nil store is a refusal too, never a silent pass.
	if verifyIdentityInvariantsAtBoot(nil) == nil {
		t.Error("a nil user store passed the boot gate")
	}
}

// loginWithCookies posts a local sign-in carrying the supplied cookies — which is
// how a per-tenant sign-in URL names the tenant the name is resolved in.
func loginWithCookies(t *testing.T, srv *httptest.Server, user, pass string, cookies ...*http.Cookie) loginResponse {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": user, "password": pass})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/login", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatalf("decode login response (status %d): %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || lr.Token == "" {
		t.Fatalf("login %s: status %d, body %+v", user, resp.StatusCode, lr)
	}
	return lr
}
