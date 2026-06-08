package main

import (
	"path/filepath"
	"testing"
)

// The per-tenant operator-visibility restriction (compliance) must:
//   - exclude a restricted tenant from the operator's Global (cross) view,
//   - DENY the operator when it scopes into a restricted tenant,
//   - NEVER restrict a tenant's own users from their own data,
//   - be a no-op when nothing is restricted (default).
func TestOperatorTelemetryRestriction(t *testing.T) {
	dir := t.TempDir()
	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	if _, err := ts.Create("Acme", "", ""); err != nil {
		t.Fatalf("create acme: %v", err)
	}
	if _, err := ts.Create("Globex", "", ""); err != nil {
		t.Fatalf("create globex: %v", err)
	}
	s := &server{tenants: ts}

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// No tenant restricted yet → never any restriction.
	if ex, deny := s.operatorTelemetryRestriction(owner, TenantGlobal, true); deny || len(ex) != 0 {
		t.Fatalf("no restrictions: got exclude=%v deny=%v, want none", ex, deny)
	}

	// Restrict acme.
	if _, err := ts.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// Operator Global (cross) view → acme excluded, not denied.
	ex, deny := s.operatorTelemetryRestriction(owner, TenantGlobal, true)
	if deny || len(ex) != 1 || ex[0] != "acme" {
		t.Errorf("global view: exclude=%v deny=%v, want exclude=[acme] deny=false", ex, deny)
	}

	// Operator scoped INTO acme → denied entirely.
	if _, deny := s.operatorTelemetryRestriction(ownerActing(owner, "acme"), "acme", false); !deny {
		t.Error("operator scoped into restricted acme must be denied")
	}
	// Operator scoped into globex (not restricted) → allowed.
	if ex, deny := s.operatorTelemetryRestriction(ownerActing(owner, "globex"), "globex", false); deny || len(ex) != 0 {
		t.Errorf("operator→globex: exclude=%v deny=%v, want allowed", ex, deny)
	}

	// Acme's OWN admin is never restricted from acme's data.
	acmeAdmin := jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: "acme"}
	if ex, deny := s.operatorTelemetryRestriction(acmeAdmin, "acme", false); deny || len(ex) != 0 {
		t.Errorf("acme admin: exclude=%v deny=%v, want unrestricted on own data", ex, deny)
	}

	// The global tenant can never be restricted.
	if _, err := ts.SetOperatorRestricted(TenantGlobal, true); err == nil {
		t.Error("restricting the global tenant must error")
	}
}

// ownerActing returns owner claims with a view-as-tenant override set (as the
// middleware would), to exercise the scoped-operator path.
func ownerActing(owner jwtClaims, tenant string) jwtClaims {
	owner.actingTenant = tenant
	return owner
}
