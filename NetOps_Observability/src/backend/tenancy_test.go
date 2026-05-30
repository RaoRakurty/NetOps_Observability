package main

import (
	"testing"

	"netops/backend/models"
)

func devs() []models.Device {
	return []models.Device{
		{ID: "a", TenantID: "acme"},
		{ID: "b", TenantID: "globex"},
		{ID: "s"}, // shared / global (no tenant)
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

func TestVisibleDevicesSuperAdminSeesAll(t *testing.T) {
	got := visibleDevices(devs(), jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"})
	if len(got) != 4 {
		t.Fatalf("super-admin should see all 4, got %d", len(got))
	}
}

func TestVisibleDevicesUnboundSeesAll(t *testing.T) {
	// Legacy/back-compat: a principal with no tenant is treated as cross-tenant.
	got := visibleDevices(devs(), jwtClaims{Role: RoleReadOnly})
	if len(got) != 4 {
		t.Fatalf("unbound principal should see all 4, got %d", len(got))
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
	// Shared/global devices remain visible to everyone.
	if !got["s"] || !got["g"] {
		t.Error("shared/global devices should be visible to a scoped tenant")
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
		{"", "acme", true},           // shared
		{TenantGlobal, "acme", true}, // global
	}
	for _, c := range cases {
		got := canSeeDevice(models.Device{TenantID: c.dev}, c.tenant, false)
		if got != c.want {
			t.Errorf("canSeeDevice(dev=%q, tenant=%q)=%v want %v", c.dev, c.tenant, got, c.want)
		}
	}
}
