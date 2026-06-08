package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// principalTenant must honor the platform owner's "view as tenant" override and
// must IGNORE it for everyone else — the override can only narrow, never widen.
func TestPrincipalTenantOverride(t *testing.T) {
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// No override → full cross-tenant (all tenants) view.
	if tn, cross := principalTenant(owner); !cross || tn != TenantGlobal {
		t.Errorf("owner no-override = (%q,%v), want (global,true)", tn, cross)
	}
	// Narrowed to a specific tenant → that tenant, not cross.
	scoped := owner
	scoped.actingTenant = "acme"
	if tn, cross := principalTenant(scoped); cross || tn != "acme" {
		t.Errorf("owner→acme = (%q,%v), want (acme,false)", tn, cross)
	}
	// A tenant's own super-admin can NOT widen via the override.
	tenantAdmin := jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: "acme", actingTenant: "globex"}
	if tn, cross := principalTenant(tenantAdmin); cross || tn != "acme" {
		t.Errorf("tenant-admin override = (%q,%v), want (acme,false) — must be ignored", tn, cross)
	}
}

// withActingTenant only stamps the override for the platform owner and only for a
// real tenant; everything else leaves the claims untouched (fail-safe).
func TestWithActingTenant(t *testing.T) {
	dir := t.TempDir()
	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	if _, err := ts.Create("Acme", "", "", ""); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	s := &server{tenants: ts}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	req := func(hdr string) jwtClaims {
		r := httptest.NewRequest("GET", "/api/logs", nil)
		if hdr != "" {
			r.Header.Set("X-Acting-Tenant", hdr)
		}
		return s.withActingTenant(r, owner)
	}

	if c := req("acme"); c.actingTenant != "acme" {
		t.Errorf("owner→acme: actingTenant=%q, want acme", c.actingTenant)
	}
	// "global" means the default Global (cross-tenant) view — NOT a narrowing.
	if c := req("global"); c.actingTenant != "" {
		t.Errorf("owner→global: actingTenant=%q, want empty (Global = cross-tenant)", c.actingTenant)
	}
	if c := req("all"); c.actingTenant != "" {
		t.Errorf("owner→all: actingTenant=%q, want empty", c.actingTenant)
	}
	if c := req("nope"); c.actingTenant != "" {
		t.Errorf("owner→unknown tenant: actingTenant=%q, want empty (ignored)", c.actingTenant)
	}
	if c := req(""); c.actingTenant != "" {
		t.Errorf("owner→no header: actingTenant=%q, want empty", c.actingTenant)
	}

	// A non-owner principal can never set the override, even naming a real tenant.
	tenantAdmin := jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: "acme"}
	r := httptest.NewRequest("GET", "/api/logs", nil)
	r.Header.Set("X-Acting-Tenant", "acme")
	if c := s.withActingTenant(r, tenantAdmin); c.actingTenant != "" {
		t.Errorf("non-owner override: actingTenant=%q, want empty (refused)", c.actingTenant)
	}
}
