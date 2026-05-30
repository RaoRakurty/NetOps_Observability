package main

import "testing"

func savedSet() []SavedObject {
	return []SavedObject{
		{ID: "a", TenantID: "acme"},
		{ID: "b", TenantID: "globex"},
		{ID: "s"}, // shared / global (no tenant)
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

func TestVisibleSavedSuperAdminSeesAll(t *testing.T) {
	got := visibleSaved(savedSet(), jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"})
	if len(got) != 4 {
		t.Fatalf("super-admin should see all 4 saved objects, got %d", len(got))
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
	if !got["s"] || !got["g"] {
		t.Error("shared/global saved objects should be visible to a scoped tenant")
	}
}

// canMutateSaved must be stricter than canSeeSaved: a scoped tenant can VIEW a
// shared/global object but must not be able to mutate or delete it (it belongs
// to no single tenant), mirroring the device contract.
func TestCanMutateSavedSharedIsReadOnlyForScoped(t *testing.T) {
	shared := SavedObject{ID: "s"} // no tenant
	if !canSeeSaved(shared, "acme", false) {
		t.Error("scoped tenant should be able to VIEW a shared object")
	}
	if canMutateSaved(shared, "acme", false) {
		t.Error("LEAK: scoped tenant must NOT mutate a shared/global object")
	}
	owned := SavedObject{ID: "a", TenantID: "acme"}
	if !canMutateSaved(owned, "acme", false) {
		t.Error("scoped tenant should be able to mutate its own object")
	}
	if canMutateSaved(SavedObject{TenantID: "globex"}, "acme", false) {
		t.Error("TENANT LEAK: acme must NOT mutate a globex object")
	}
}

func TestCanMutateSavedCrossTenant(t *testing.T) {
	// A cross-tenant principal may mutate anything, including shared objects.
	if !canMutateSaved(SavedObject{TenantID: "globex"}, "", true) {
		t.Error("cross-tenant principal should mutate any object")
	}
}
