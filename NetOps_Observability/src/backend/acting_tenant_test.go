// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	scoped.ActingTenant = "acme"
	if tn, cross := principalTenant(scoped); cross || tn != "acme" {
		t.Errorf("owner→acme = (%q,%v), want (acme,false)", tn, cross)
	}
	// A tenant's own super-admin can NOT widen via the override.
	tenantAdmin := jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: "acme", ActingTenant: "globex"}
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
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
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

	// A slug in the header resolves to the opaque tenant id (the override is keyed
	// on the id, never the slug).
	if c := req("acme"); c.ActingTenant != acme.ID {
		t.Errorf("owner→acme: ActingTenant=%q, want %s", c.ActingTenant, acme.ID)
	}
	// "global" is the Provider tenant: a real, NON-cross narrowing to the
	// platform's own rows (tracker 365) — it used to mean cross-tenant, which
	// is how an operator deleted another tenant's integration from "Provider".
	if c := req("global"); c.ActingTenant != TenantGlobal {
		t.Errorf("owner→global: ActingTenant=%q, want %q (Provider narrows)", c.ActingTenant, TenantGlobal)
	} else if tn, cross := principalTenant(c); cross || tn != TenantGlobal {
		t.Errorf("owner→global: principalTenant = (%q,%v), want (global,false)", tn, cross)
	}
	if c := req(" Global "); c.ActingTenant != TenantGlobal {
		t.Errorf("owner→' Global ': ActingTenant=%q, want %q (trimmed, case-insensitive)", c.ActingTenant, TenantGlobal)
	}
	// Only "" and "all" are the All-tenants (cross) view.
	if c := req("all"); c.ActingTenant != "" {
		t.Errorf("owner→all: ActingTenant=%q, want empty", c.ActingTenant)
	}
	if c := req("nope"); c.ActingTenant != "" {
		t.Errorf("owner→unknown tenant: ActingTenant=%q, want empty (ignored)", c.ActingTenant)
	}
	if c := req(""); c.ActingTenant != "" {
		t.Errorf("owner→no header: ActingTenant=%q, want empty", c.ActingTenant)
	}

	// A non-owner principal can never set the override, even naming a real tenant.
	tenantAdmin := jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: "acme"}
	r := httptest.NewRequest("GET", "/api/logs", nil)
	r.Header.Set("X-Acting-Tenant", "acme")
	if c := s.withActingTenant(r, tenantAdmin); c.ActingTenant != "" {
		t.Errorf("non-owner override: ActingTenant=%q, want empty (refused)", c.ActingTenant)
	}
	// A non-owner naming "global" (Provider) with no binding reaching it is
	// ignored — it stays in its own tenant, never widens into the platform's.
	r = httptest.NewRequest("GET", "/api/logs", nil)
	r.Header.Set("X-Acting-Tenant", TenantGlobal)
	if c := s.withActingTenant(r, tenantAdmin); c.ActingTenant != "" || c.Tenant != "acme" {
		t.Errorf("non-owner→global: (ActingTenant=%q, Tenant=%q), want (\"\", acme)", c.ActingTenant, c.Tenant)
	}
	// No tenant registry: every override is ignored (fail closed), including global.
	bare := &server{}
	if c := bare.withActingTenant(r, owner); c.ActingTenant != "" {
		t.Errorf("no registry: ActingTenant=%q, want empty", c.ActingTenant)
	}
}
