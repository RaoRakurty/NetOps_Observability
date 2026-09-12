// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/models"
)

func devs() []models.Device {
	return []models.Device{
		{ID: "a", TenantID: "acme"},
		{ID: "b", TenantID: "globex"},
		{ID: "s"}, // unassigned (no tenant) — platform-owned
		{ID: "g", TenantID: TenantGlobal},
	}
}

func ids(ds []models.Device) map[string]bool {
	m := map[string]bool{}
	for _, d := range ds {
		m[d.ID] = true
	}
	return m
}

// The platform owner — a super-admin in the global/empty tenant — is the only
// cross-tenant principal and sees every device.
func TestVisibleDevicesPlatformOwnerSeesAll(t *testing.T) {
	for _, c := range []jwtClaims{
		{Role: RoleSuperAdmin, Tenant: TenantGlobal},
		{Role: RoleSuperAdmin, Tenant: ""},
	} {
		if got := visibleDevices(devs(), c); len(got) != 4 {
			t.Fatalf("platform owner (%+v) should see all 4, got %d", c, len(got))
		}
	}
}

// REGRESSION (the reported bug): a tenant-bound super-admin is NOT cross-tenant;
// it sees ONLY its own tenant — not other tenants, not global/unassigned.
func TestVisibleDevicesTenantSuperAdminIsScoped(t *testing.T) {
	got := ids(visibleDevices(devs(), jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}))
	if !got["a"] || got["b"] || got["s"] || got["g"] {
		t.Fatalf("tenant super-admin must see ONLY its own tenant (a), got %v", got)
	}
}

// An unbound, non-super-admin principal is scoped to the empty tenant — it does
// NOT see everything.
func TestVisibleDevicesUnboundNonAdminScoped(t *testing.T) {
	got := ids(visibleDevices(devs(), jwtClaims{Role: RoleReadOnly}))
	if got["a"] || got["b"] || got["g"] {
		t.Fatalf("unbound non-admin must not see tenant/global devices, got %v", got)
	}
}

func TestVisibleDevicesTenantIsolation(t *testing.T) {
	got := ids(visibleDevices(devs(), jwtClaims{Role: RoleOperator, Tenant: "acme"}))
	if !got["a"] {
		t.Error("acme operator should see its own device a")
	}
	if got["b"] {
		t.Error("TENANT LEAK: acme operator must NOT see globex device b")
	}
	// Strict isolation: global/unassigned devices are platform-owned and must NOT
	// leak into a scoped tenant.
	if got["s"] || got["g"] {
		t.Error("TENANT LEAK: global/unassigned devices must NOT be visible to a scoped tenant")
	}
}

func TestVisibleDevicesGlobexIsolation(t *testing.T) {
	got := ids(visibleDevices(devs(), jwtClaims{Role: RoleReadOnly, Tenant: "globex"}))
	if got["a"] {
		t.Error("TENANT LEAK: globex must NOT see acme device a")
	}
	if !got["b"] {
		t.Error("globex should see its own device b")
	}
}

func TestCanSeeDeviceMatrix(t *testing.T) {
	cases := []struct {
		dev    string
		tenant string
		want   bool
	}{
		{"acme", "acme", true},
		{"globex", "acme", false},
		{"", "acme", false},           // unassigned: platform-only, not shared
		{TenantGlobal, "acme", false}, // global: platform-only, not shared
	}
	for _, c := range cases {
		got := canSeeDevice(models.Device{TenantID: c.dev}, c.tenant, false)
		if got != c.want {
			t.Errorf("canSeeDevice(dev=%q, tenant=%q)=%v want %v", c.dev, c.tenant, got, c.want)
		}
	}
}

// principalTenant: cross-tenant ONLY for a super-admin in the global/empty tenant.
func TestPrincipalTenantCrossOnlyForPlatformOwner(t *testing.T) {
	cases := []struct {
		c     jwtClaims
		cross bool
	}{
		{jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal}, true},
		{jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, true},
		{jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, false}, // tenant super-admin: scoped
		{jwtClaims{Role: RoleOperator, Tenant: "acme"}, false},
		{jwtClaims{Role: RoleReadOnly, Tenant: ""}, false},
	}
	for _, tc := range cases {
		if _, cross := principalTenant(tc.c); cross != tc.cross {
			t.Errorf("principalTenant(%+v) cross=%v want %v", tc.c, cross, tc.cross)
		}
	}
}
