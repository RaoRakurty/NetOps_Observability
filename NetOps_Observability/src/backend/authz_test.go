package main

import "testing"

// Authorize is the single policy chokepoint, so its decision matrix is pinned
// exhaustively here. Every other tenancy guarantee reduces to these rules.
func TestAuthorizeMatrix(t *testing.T) {
	owner := Principal{Subject: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal, cross: true}
	acme := Principal{Subject: "a@acme", Role: RoleSuperAdmin, Tenant: "acme"} // tenant super-admin = scoped

	cases := []struct {
		name string
		p    Principal
		a    Action
		r    Resource
		want bool
	}{
		// Platform owner: unrestricted across every type/action.
		{"owner views other tenant device", owner, ActionView, Resource{ResDevice, "globex"}, true},
		{"owner mutates tenant registry", owner, ActionCreate, Resource{ResTenant, ""}, true},
		{"owner mutates roles", owner, ActionUpdate, Resource{ResRole, ""}, true},
		{"owner views infra stack", owner, ActionView, Resource{ResInfraStack, ""}, true},

		// Scoped principal: own-tenant resources allowed.
		{"acme views own device", acme, ActionView, Resource{ResDevice, "acme"}, true},
		{"acme updates own saved", acme, ActionUpdate, Resource{ResSaved, "acme"}, true},
		{"acme views own api key", acme, ActionView, Resource{ResAPIKey, "acme"}, true},
		{"acme views own snmp cred", acme, ActionView, Resource{ResSNMPCred, "acme"}, true},

		// Scoped principal: other tenants' resources denied.
		{"acme views globex device", acme, ActionView, Resource{ResDevice, "globex"}, false},
		{"acme deletes globex saved", acme, ActionDelete, Resource{ResSaved, "globex"}, false},

		// Scoped principal: global/untagged resources are platform-owned → denied.
		{"acme views untagged device", acme, ActionView, Resource{ResDevice, ""}, false},
		{"acme views global snmp cred", acme, ActionView, Resource{ResSNMPCred, "global"}, false},

		// Infra stack: never for a scoped principal.
		{"acme views infra stack", acme, ActionView, Resource{ResInfraStack, ""}, false},

		// Roles: readable by a tenant admin, not mutable.
		{"acme views roles", acme, ActionView, Resource{ResRole, ""}, true},
		{"acme creates role", acme, ActionCreate, Resource{ResRole, ""}, false},
		{"acme updates role", acme, ActionUpdate, Resource{ResRole, ""}, false},

		// Tenant registry: a tenant admin sees its own, can't see others, can't mutate.
		{"acme views own tenant", acme, ActionView, Resource{ResTenant, "acme"}, true},
		{"acme views other tenant", acme, ActionView, Resource{ResTenant, "globex"}, false},
		{"acme creates tenant", acme, ActionCreate, Resource{ResTenant, ""}, false},
		{"acme deletes own tenant", acme, ActionDelete, Resource{ResTenant, "acme"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Authorize(tc.p, tc.a, tc.r).Allow; got != tc.want {
				t.Errorf("Authorize(%s, %s, %s/%s) = %v, want %v",
					tc.p.Subject, tc.a, tc.r.Type, tc.r.Tenant, got, tc.want)
			}
		})
	}
}

// The leaf adapters must agree with Authorize (they now delegate to it).
func TestLeafAdaptersDelegate(t *testing.T) {
	// sameTenant: cross sees all; scoped exact-match only.
	if !sameTenant("anything", "acme", true) {
		t.Error("cross-tenant sameTenant should allow")
	}
	if !sameTenant("acme", "acme", false) {
		t.Error("same-tenant should allow")
	}
	if sameTenant("globex", "acme", false) {
		t.Error("cross-tenant scoped sameTenant should deny")
	}
	if sameTenant("", "acme", false) {
		t.Error("global/untagged must not be visible to a scoped tenant")
	}
}

// principalFrom resolves cross-tenant exactly like principalTenant: only a
// super-admin in the global/empty tenant is the platform owner.
func TestPrincipalFromCrossTenant(t *testing.T) {
	cases := []struct {
		claims jwtClaims
		cross  bool
	}{
		{jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal}, true},
		{jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, true},
		{jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, false}, // tenant super-admin is scoped
		{jwtClaims{Role: RoleOperator, Tenant: ""}, false},
		{jwtClaims{Role: RoleOperator, Tenant: "acme"}, false},
	}
	for _, tc := range cases {
		if got := principalFrom(tc.claims).cross; got != tc.cross {
			t.Errorf("principalFrom(%s/%s).cross = %v, want %v", tc.claims.Role, tc.claims.Tenant, got, tc.cross)
		}
	}
}
