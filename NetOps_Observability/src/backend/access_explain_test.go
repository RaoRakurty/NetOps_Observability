package main

import "testing"

// TestExplainAccess: the explanation names, per reachable tenant, the binding
// that grants it — and reflects deny-wins.
func TestExplainAccess(t *testing.T) {
	s := newPBACTestServer(t)
	seed := seedOrgTenants(t, s) // org acme-corp{acme-prod,acme-dev} + globex
	if _, err := s.users.CreateFull(User{Username: "sre", Role: "operator", TenantID: "acme-prod"}, "Passw0rd!2345"); err != nil {
		t.Fatal(err)
	}
	s.backfillBindings()
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "sre", RoleID: "operator", ScopeID: scopeTenant("globex")}); err != nil {
		t.Fatal(err)
	}

	exp := s.explainAccess("sre")
	if exp.AllTenants {
		t.Error("sre is not the platform owner")
	}
	// Reaches are keyed by the OPAQUE tenant id; the granting binding's ScopeID is
	// the raw (slug) scope it was created with.
	reach := map[string][]GrantReason{}
	for _, r := range exp.Reaches {
		reach[r.TenantID] = r.GrantedBy
	}
	if len(reach[seed.acmeProd]) == 0 || reach[seed.acmeProd][0].ScopeID != scopeTenant("acme-prod") {
		t.Errorf("acme-prod should be granted by its tenant binding, got %+v", reach[seed.acmeProd])
	}
	if len(reach[seed.globex]) == 0 {
		t.Error("globex reach should be explained by a binding")
	}
	if _, ok := reach[seed.acmeDev]; ok {
		t.Error("sre must not reach acme-dev")
	}
}

// TestExplainAuthz: owner explains anyone; org-admin only principals in its org;
// a plain user only itself.
func TestExplainAuthz(t *testing.T) {
	s := newPBACTestServer(t)
	seedOrgTenants(t, s)
	for _, u := range []struct{ name, role, tenant string }{
		{"boss", "org-admin", "acme-prod"},
		{"alice", "operator", "acme-prod"},
		{"carol", "operator", "globex"},
	} {
		if _, err := s.users.CreateFull(User{Username: u.name, Role: u.role, TenantID: u.tenant}, "Passw0rd!2345"); err != nil {
			t.Fatal(err)
		}
	}
	s.backfillBindings()
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "boss", RoleID: "org-admin", ScopeID: scopeOrg("acme-corp")}); err != nil {
		t.Fatal(err)
	}

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	bossC := jwtClaims{Sub: "boss", Role: RoleOrgAdmin, Tenant: "acme-prod"}
	aliceC := jwtClaims{Sub: "alice", Role: RoleOperator, Tenant: "acme-prod"}

	if !s.canExplainPrincipal(owner, "carol") {
		t.Error("owner should explain anyone")
	}
	if !s.canExplainPrincipal(bossC, "alice") {
		t.Error("org-admin should explain a principal in its org")
	}
	if s.canExplainPrincipal(bossC, "carol") {
		t.Error("org-admin must NOT explain a principal outside its org")
	}
	if !s.canExplainPrincipal(aliceC, "alice") {
		t.Error("a user should explain itself")
	}
	if s.canExplainPrincipal(aliceC, "carol") {
		t.Error("a plain user must not explain others")
	}
}
