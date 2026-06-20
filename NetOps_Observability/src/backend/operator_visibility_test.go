package main

import (
	"path/filepath"
	"testing"

	"netops/backend/models"
)

// The per-tenant operator-visibility restriction (compliance) must:
//   - exclude a restricted tenant from the operator's Global (cross) view,
//   - DENY the operator when it scopes into a restricted tenant,
//   - NEVER restrict a tenant's own users from their own data,
//   - be a no-op when nothing is restricted (default).
//
// Identity is the OPAQUE tenant id (claims/devices/restriction lists all key on
// it); the slug is only a human handle. The fixtures therefore capture the minted
// ids and assert on them — never on the slug.
func TestOperatorTelemetryRestriction(t *testing.T) {
	dir := t.TempDir()
	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	s := &server{tenants: ts}

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// No tenant restricted yet → never any restriction.
	if ex, deny := s.operatorTelemetryRestriction(owner, TenantGlobal, true); deny || len(ex) != 0 {
		t.Fatalf("no restrictions: got exclude=%v deny=%v, want none", ex, deny)
	}

	// Restrict acme (by slug — the store resolves it to the opaque id).
	if _, err := ts.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// Operator Global (cross) view → acme excluded (by OPAQUE id), not denied.
	ex, deny := s.operatorTelemetryRestriction(owner, TenantGlobal, true)
	if deny || len(ex) != 1 || ex[0] != acme.ID {
		t.Errorf("global view: exclude=%v deny=%v, want exclude=[%s] deny=false", ex, deny, acme.ID)
	}

	// Operator scoped INTO acme → denied entirely.
	if _, deny := s.operatorTelemetryRestriction(ownerActing(owner, acme.ID), acme.ID, false); !deny {
		t.Error("operator scoped into restricted acme must be denied")
	}
	// Operator scoped into globex (not restricted) → allowed.
	if ex, deny := s.operatorTelemetryRestriction(ownerActing(owner, globex.ID), globex.ID, false); deny || len(ex) != 0 {
		t.Errorf("operator→globex: exclude=%v deny=%v, want allowed", ex, deny)
	}

	// Acme's OWN admin is never restricted from acme's data.
	acmeAdmin := jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: acme.ID}
	if ex, deny := s.operatorTelemetryRestriction(acmeAdmin, acme.ID, false); deny || len(ex) != 0 {
		t.Errorf("acme admin: exclude=%v deny=%v, want unrestricted on own data", ex, deny)
	}

	// The global tenant can never be restricted.
	if _, err := ts.SetOperatorRestricted(TenantGlobal, true); err == nil {
		t.Error("restricting the global tenant must error")
	}
}

// ownerActing returns owner claims with a view-as-tenant override set (as the
// middleware would), to exercise the scoped-operator path. The override is the
// opaque tenant id (what withActingTenant resolves a slug to).
func ownerActing(owner jwtClaims, tenantID string) jwtClaims {
	owner.actingTenant = tenantID
	return owner
}

// The device-keyed restriction (flows/findings/metrics) must exclude a restricted
// tenant's device identifiers from the operator's Global view, deny when scoped
// into one, and be a no-op for non-operators / when nothing is restricted.
func TestRestrictedTelemetryDeviceKeyed(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, _ := ts.Create("Acme", "acme", "", "", "")
	globex, _ := ts.Create("Globex", "globex", "", "", "")

	// Devices are tagged with the OPAQUE tenant id (as the device-create boundary
	// stamps them from the principal's resolved tenant).
	d := NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID})
	s := &server{discovery: d, tenants: ts}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	if rt := s.restrictedTelemetry(owner); rt.deny || len(rt.addrs) != 0 || len(rt.keys) != 0 {
		t.Fatalf("nothing restricted → want no-op, got %+v", rt)
	}
	if _, err := ts.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	rt := s.restrictedTelemetry(owner) // operator Global view
	if rt.deny {
		t.Fatal("Global view must not deny")
	}
	if !containsStr(rt.addrs, "10.1.0.1") || !containsStr(rt.keys, "acme-core") || !containsStr(rt.ids, "acme-core") {
		t.Errorf("acme device not excluded: %+v", rt)
	}
	if containsStr(rt.addrs, "10.2.0.1") || containsStr(rt.keys, "globex-core") {
		t.Errorf("globex (not restricted) must NOT be excluded: %+v", rt)
	}
	if rt := s.restrictedTelemetry(ownerActing(owner, acme.ID)); !rt.deny {
		t.Error("operator scoped into restricted acme must deny")
	}
	if rt := s.restrictedTelemetry(ownerActing(owner, globex.ID)); rt.deny {
		t.Error("operator scoped into globex must not deny")
	}
	if rt := s.restrictedTelemetry(jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: acme.ID}); rt.deny || len(rt.addrs) != 0 {
		t.Error("a tenant's own admin must never be restricted from its data")
	}
}
