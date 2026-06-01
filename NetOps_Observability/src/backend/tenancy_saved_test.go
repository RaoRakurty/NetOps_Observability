package main

import "testing"

func savedSet() []SavedObject {
	return []SavedObject{
		{ID: "a", TenantID: "acme"},
		{ID: "b", TenantID: "globex"},
		{ID: "s"}, // unassigned (no tenant) — platform-owned
		{ID: "g", TenantID: TenantGlobal},
	}
}

func savedIDs(os []SavedObject) map[string]bool {
	m := map[string]bool{}
	for _, o := range os {
		m[o.ID] = true
	}
	return m
}

// The platform owner (super-admin in the global tenant) sees every saved object.
func TestVisibleSavedPlatformOwnerSeesAll(t *testing.T) {
	got := visibleSaved(savedSet(), jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if len(got) != 4 {
		t.Fatalf("platform owner should see all 4 saved objects, got %d", len(got))
	}
}

// A tenant-bound super-admin is scoped to its own tenant's objects only.
func TestVisibleSavedTenantSuperAdminScoped(t *testing.T) {
	got := savedIDs(visibleSaved(savedSet(), jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}))
	if !got["a"] || got["b"] || got["s"] || got["g"] {
		t.Fatalf("tenant super-admin must see ONLY its own saved object (a), got %v", got)
	}
}

func TestVisibleSavedTenantIsolation(t *testing.T) {
	got := savedIDs(visibleSaved(savedSet(), jwtClaims{Role: RoleOperator, Tenant: "acme"}))
	if !got["a"] {
		t.Error("acme should see its own saved object a")
	}
	if got["b"] {
		t.Error("TENANT LEAK: acme must NOT see globex saved object b")
	}
	// Strict isolation: global/unassigned saved objects are platform-owned and
	// must NOT leak into a scoped tenant's view.
	if got["s"] || got["g"] {
		t.Error("TENANT LEAK: global/unassigned saved objects must NOT be visible to a scoped tenant")
	}
}

// Strict view + mutate contract for a scoped tenant.
func TestCanSeeAndMutateSavedStrict(t *testing.T) {
	shared := SavedObject{ID: "s"} // no tenant → platform-owned
	if canSeeSaved(shared, "acme", false) {
		t.Error("LEAK: a scoped tenant must NOT see a global/unassigned object")
	}
	if !canSeeSaved(SavedObject{TenantID: "acme"}, "acme", false) {
		t.Error("scoped tenant should see its own object")
	}
	if canMutateSaved(shared, "acme", false) {
		t.Error("LEAK: scoped tenant must NOT mutate a global/unassigned object")
	}
	if !canMutateSaved(SavedObject{ID: "a", TenantID: "acme"}, "acme", false) {
		t.Error("scoped tenant should mutate its own object")
	}
	if canMutateSaved(SavedObject{TenantID: "globex"}, "acme", false) {
		t.Error("TENANT LEAK: acme must NOT mutate a globex object")
	}
}

func TestCanMutateSavedCrossTenant(t *testing.T) {
	// The platform owner may mutate anything.
	if !canMutateSaved(SavedObject{TenantID: "globex"}, "", true) {
		t.Error("platform owner should mutate any object")
	}
}
