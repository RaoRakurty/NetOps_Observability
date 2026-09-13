// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import "testing"

// TestExplainAccess: the explanation names, per reachable tenant, the binding
// that grants it — and reflects deny-wins.
func TestExplainAccess(t *testing.T) {
	s := newPBACTestServer(t)
	seed := seedOrgTenants(t, s) // org acme-corp{acme-prod,acme-dev} + globex
	// Tracker 300: a binding names the PRINCIPAL ID, not the login handle.
	sre, err := s.users.CreateFull(User{Username: "sre", Role: "operator", TenantID: "acme-prod"}, "Passw0rd!2345")
	if err != nil {
		t.Fatal(err)
	}
	s.backfillBindings()
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: sre.ID, RoleID: "operator", ScopeID: scopeTenant("globex")}); err != nil {
		t.Fatal(err)
	}

	exp := s.explainAccess(sre.ID)
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
	// Tracker 300: a claim's `sub` and a principal reference are both the
	// PRINCIPAL ID, so the fixture records the ids it minted.
	id := map[string]string{}
	for _, u := range []struct{ name, role, tenant string }{
		{"boss", "org-admin", "acme-prod"},
		{"alice", "operator", "acme-prod"},
		{"carol", "operator", "globex"},
	} {
		created, err := s.users.CreateFull(User{Username: u.name, Role: u.role, TenantID: u.tenant}, "Passw0rd!2345")
		if err != nil {
			t.Fatal(err)
		}
		id[u.name] = created.ID
	}
	s.backfillBindings()
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: id["boss"], RoleID: "org-admin", ScopeID: scopeOrg("acme-corp")}); err != nil {
		t.Fatal(err)
	}

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	bossC := jwtClaims{Sub: id["boss"], Role: RoleOrgAdmin, Tenant: "acme-prod"}
	aliceC := jwtClaims{Sub: id["alice"], Role: RoleOperator, Tenant: "acme-prod"}

	if !s.canExplainPrincipal(owner, id["carol"]) {
		t.Error("owner should explain anyone")
	}
	if !s.canExplainPrincipal(bossC, id["alice"]) {
		t.Error("org-admin should explain a principal in its org")
	}
	if s.canExplainPrincipal(bossC, id["carol"]) {
		t.Error("org-admin must NOT explain a principal outside its org")
	}
	if !s.canExplainPrincipal(aliceC, id["alice"]) {
		t.Error("a user should explain itself")
	}
	if s.canExplainPrincipal(aliceC, id["carol"]) {
		t.Error("a plain user must not explain others")
	}
}
