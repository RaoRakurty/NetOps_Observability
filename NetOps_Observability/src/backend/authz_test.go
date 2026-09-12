// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import "testing"

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
		if got := principalFrom(tc.claims).Cross; got != tc.cross {
			t.Errorf("principalFrom(%s/%s).Cross = %v, want %v", tc.claims.Role, tc.claims.Tenant, got, tc.cross)
		}
	}
}
