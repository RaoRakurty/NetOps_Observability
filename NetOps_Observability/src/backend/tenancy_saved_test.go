// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/internal/saved"
)

func savedSet() []saved.Object {
	return []saved.Object{
		{ID: "a", TenantID: "acme"},
		{ID: "b", TenantID: "globex"},
		{ID: "s"}, // unassigned (no tenant) — platform-owned
		{ID: "g", TenantID: TenantGlobal},
	}
}

// savedFilterForTest applies the RESOLVED saved-object rule to the fixture set.
// A bare &server{} carries no tenant store, so the operator-visibility
// restriction resolves empty and what is asserted below is the TENANCY half on
// its own — which is what these three cases are about. The restriction half is
// proved end-to-end in saved_objects_restriction_test.go.
func savedFilterForTest(c jwtClaims) []saved.Object {
	return (&server{}).savedVisibilityFor(c).filter(savedSet())
}

func savedIDs(os []saved.Object) map[string]bool {
	m := map[string]bool{}
	for _, o := range os {
		m[o.ID] = true
	}
	return m
}

// The platform owner (super-admin in the global tenant) sees every saved object.
func TestVisibleSavedPlatformOwnerSeesAll(t *testing.T) {
	got := savedFilterForTest(jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if len(got) != 4 {
		t.Fatalf("platform owner should see all 4 saved objects, got %d", len(got))
	}
}

// A tenant-bound super-admin is scoped to its own tenant's objects only.
func TestVisibleSavedTenantSuperAdminScoped(t *testing.T) {
	got := savedIDs(savedFilterForTest(jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}))
	if !got["a"] || got["b"] || got["s"] || got["g"] {
		t.Fatalf("tenant super-admin must see ONLY its own saved object (a), got %v", got)
	}
}

func TestVisibleSavedTenantIsolation(t *testing.T) {
	got := savedIDs(savedFilterForTest(jwtClaims{Role: RoleOperator, Tenant: "acme"}))
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
	shared := saved.Object{ID: "s"} // no tenant → platform-owned
	if canSeeSavedTenantOnly(shared, "acme", false) {
		t.Error("LEAK: a scoped tenant must NOT see a global/unassigned object")
	}
	if !canSeeSavedTenantOnly(saved.Object{TenantID: "acme"}, "acme", false) {
		t.Error("scoped tenant should see its own object")
	}
	if canMutateSavedTenantOnly(shared, "acme", false) {
		t.Error("LEAK: scoped tenant must NOT mutate a global/unassigned object")
	}
	if !canMutateSavedTenantOnly(saved.Object{ID: "a", TenantID: "acme"}, "acme", false) {
		t.Error("scoped tenant should mutate its own object")
	}
	if canMutateSavedTenantOnly(saved.Object{TenantID: "globex"}, "acme", false) {
		t.Error("TENANT LEAK: acme must NOT mutate a globex object")
	}
}

func TestCanMutateSavedCrossTenant(t *testing.T) {
	// The platform owner may mutate anything.
	if !canMutateSavedTenantOnly(saved.Object{TenantID: "globex"}, "", true) {
		t.Error("platform owner should mutate any object")
	}
}
