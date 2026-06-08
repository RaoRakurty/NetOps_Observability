package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// seedOrgTenants creates an org with two tenants for reachability tests.
func seedOrgTenants(t *testing.T, s *server) {
	t.Helper()
	if _, err := s.orgs.Create("Acme Corp", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tenants.Create("Acme Prod", "", "", "acme-corp"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tenants.Create("Acme Dev", "", "", "acme-corp"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tenants.Create("Globex", "", "", ""); err != nil { // global org
		t.Fatal(err)
	}
}

// TestReachMultiTenant: a principal bound to two tenants reaches both, no more.
func TestReachMultiTenant(t *testing.T) {
	s := newPBACTestServer(t)
	seedOrgTenants(t, s)
	if _, err := s.users.CreateFull(User{Username: "sre", Role: "operator", TenantID: "acme-prod"}, "password123"); err != nil {
		t.Fatal(err)
	}
	s.backfillBindings() // gives sre its home binding at tenant:acme-prod
	// Grant a second tenant.
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "sre", RoleID: "operator", ScopeID: scopeTenant("globex"), Effect: EffectAllow}); err != nil {
		t.Fatal(err)
	}
	if !s.reachesTenant("sre", "acme-prod") || !s.reachesTenant("sre", "globex") {
		t.Error("sre should reach both bound tenants")
	}
	if s.reachesTenant("sre", "acme-dev") {
		t.Error("sre must NOT reach acme-dev (no binding)")
	}
	got, all := s.accessibleTenants("sre")
	if all || len(got) != 2 {
		t.Fatalf("accessibleTenants=%v all=%v, want 2 tenants", got, all)
	}
}

// TestOrgAdminReach: an org-admin bound at org scope reaches every tenant in the
// org but nothing outside it, and is reported by orgAdminOrgs.
func TestOrgAdminReach(t *testing.T) {
	s := newPBACTestServer(t)
	seedOrgTenants(t, s)
	if _, err := s.users.CreateFull(User{Username: "acme-boss", Role: "org-admin", TenantID: "acme-prod"}, "password123"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "acme-boss", RoleID: "org-admin", ScopeID: scopeOrg("acme-corp"), Effect: EffectAllow}); err != nil {
		t.Fatal(err)
	}
	if !s.reachesTenant("acme-boss", "acme-prod") || !s.reachesTenant("acme-boss", "acme-dev") {
		t.Error("org-admin should reach all tenants in its org")
	}
	if s.reachesTenant("acme-boss", "globex") {
		t.Error("org-admin must NOT reach a tenant outside its org")
	}
	if !s.isOrgAdminOf("acme-boss", "acme-corp") {
		t.Error("acme-boss should be org-admin of acme-corp")
	}
	got, all := s.accessibleTenants("acme-boss")
	if all || len(got) != 2 {
		t.Fatalf("org-admin accessibleTenants=%v all=%v, want acme-prod+acme-dev", got, all)
	}
}

// TestDenyWins: a deny at tenant scope blocks even with a covering org allow.
func TestDenyWins(t *testing.T) {
	s := newPBACTestServer(t)
	seedOrgTenants(t, s)
	if _, err := s.users.CreateFull(User{Username: "boss", Role: "org-admin", TenantID: "acme-prod"}, "password123"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "boss", RoleID: "org-admin", ScopeID: scopeOrg("acme-corp")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "boss", RoleID: "org-admin", ScopeID: scopeTenant("acme-dev"), Effect: EffectDeny}); err != nil {
		t.Fatal(err)
	}
	if s.reachesTenant("boss", "acme-dev") {
		t.Error("deny at tenant:acme-dev must override the org allow")
	}
	if !s.reachesTenant("boss", "acme-prod") {
		t.Error("acme-prod still reachable via org allow")
	}
}

// TestSwitcherNonOwner: the generalized switcher honors a non-owner's selection
// only for a tenant it reaches; behaviour-preserving for single-tenant users.
func TestSwitcherNonOwner(t *testing.T) {
	s := newPBACTestServer(t)
	seedOrgTenants(t, s)
	if _, err := s.users.CreateFull(User{Username: "sre", Role: "operator", TenantID: "acme-prod"}, "password123"); err != nil {
		t.Fatal(err)
	}
	s.backfillBindings()
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "sre", RoleID: "operator", ScopeID: scopeTenant("globex")}); err != nil {
		t.Fatal(err)
	}
	c := jwtClaims{Sub: "sre", Role: "operator", Tenant: "acme-prod"}

	// Switch to a reachable tenant → effective tenant rewritten, resolved scope is
	// that tenant (still scoped, never cross).
	r := httptest.NewRequest("GET", "/x?as_tenant=globex", nil)
	got := s.withActingTenant(r, c)
	if tn, cross := principalTenant(got); tn != "globex" || cross {
		t.Errorf("switch to reachable tenant: scope=(%q,%v), want (globex,false)", tn, cross)
	}
	// Switch to an unreachable tenant → ignored (stays home).
	r2 := httptest.NewRequest("GET", "/x?as_tenant=acme-dev", nil)
	if got := s.withActingTenant(r2, c); got.Tenant != "acme-prod" {
		t.Errorf("switch to unreachable tenant should be ignored, got %q", got.Tenant)
	}
	// Resolved scope of the home claim (no override) is the home tenant, not cross.
	if tn, cross := principalTenant(c); tn != "acme-prod" || cross {
		t.Errorf("home scope = (%q,%v), want (acme-prod,false)", tn, cross)
	}
}

// TestBindingsAPINoEscalation: an org-admin can grant within its org but cannot
// grant super-admin, platform scope, or into another org. The platform owner can.
func TestBindingsAPINoEscalation(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "password123").Token

	// platform owner builds an org + tenant + an org-admin user, and grants the
	// org-admin its org binding.
	if st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Acme Corp"}); st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	if st, _ := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"}); st != 201 {
		t.Fatal("create tenant")
	}
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "boss", "password": "password123", "role": "org-admin", "tenant_id": "acme-prod",
	}); st != 201 {
		t.Fatalf("create boss: %d %s", st, b)
	}
	if st, b := do(t, srv, "POST", "/api/bindings", admin, map[string]any{
		"principal_id": "boss", "role_id": "org-admin", "scope_id": "org:acme-corp",
	}); st != 201 {
		t.Fatalf("grant org-admin binding: %d %s", st, b)
	}
	// a target user to receive grants
	if st, _ := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "alice", "password": "password123", "role": "operator", "tenant_id": "acme-prod",
	}); st != 201 {
		t.Fatal("create alice")
	}

	boss := login(t, srv, "boss", "password123").Token

	// org-admin grants operator within its org → allowed.
	if st, b := do(t, srv, "POST", "/api/bindings", boss, map[string]any{
		"principal_id": "alice", "role_id": "operator", "scope_id": "tenant:acme-prod",
	}); st != 201 {
		t.Errorf("org-admin grant within org: got %d, want 201: %s", st, b)
	}
	// org-admin tries to grant super-admin → forbidden (no escalation).
	if st, _ := do(t, srv, "POST", "/api/bindings", boss, map[string]any{
		"principal_id": "alice", "role_id": "super-admin", "scope_id": "tenant:acme-prod",
	}); st != 403 {
		t.Errorf("org-admin grant super-admin: got %d, want 403", st)
	}
	// org-admin tries platform scope → forbidden.
	if st, _ := do(t, srv, "POST", "/api/bindings", boss, map[string]any{
		"principal_id": "alice", "role_id": "operator", "scope_id": "platform",
	}); st != 403 {
		t.Errorf("org-admin grant at platform: got %d, want 403", st)
	}
	// org-admin tries another org's tenant (global org's globex) → forbidden/bad.
	if st, _ := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Globex"}); st != 201 {
		t.Fatal("create globex")
	}
	if st, _ := do(t, srv, "POST", "/api/bindings", boss, map[string]any{
		"principal_id": "alice", "role_id": "operator", "scope_id": "tenant:globex",
	}); st != 403 {
		t.Errorf("org-admin grant into another org: got %d, want 403", st)
	}

	// /api/me for alice now shows acme-prod accessible (home), not all.
	alice := login(t, srv, "alice", "password123").Token
	_, b := do(t, srv, "GET", "/api/auth/me", alice, nil)
	var me struct {
		AccessibleTenants []string `json:"accessible_tenants"`
		AllTenants        bool     `json:"all_tenants"`
	}
	_ = json.Unmarshal(b, &me)
	if me.AllTenants || len(me.AccessibleTenants) == 0 {
		t.Errorf("alice /me accessible=%v all=%v, want a bounded set", me.AccessibleTenants, me.AllTenants)
	}
}
