// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"path/filepath"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// The Overview dashboard tiles must be tenant-scoped: a scoped principal's
// "Devices" / "Sites" counts reflect ONLY its own devices, never the global
// fleet (the reported leak).
//
// The platform owner sees the whole fleet HERE because no tenant in this estate
// has switched the operator-visibility restriction on. That precondition is now
// load-bearing, so this test builds a real tenant store and leaves both tenants
// unrestricted, rather than leaving the store nil and getting 4 by accident.
// What the owner sees when a tenant IS restricted is the subject of
// TestDashboardInventoryTilesHonourTheOperatorVisibilityRestriction: the
// restricted tenant's devices and sites drop out of the operator's counts.
func TestMetricTilesTenantScoped(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
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

	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-1", Name: "acme-1", TenantID: acme.ID, Labels: map[string]string{"site": "nyc"}},
		{ID: "acme-2", Name: "acme-2", TenantID: acme.ID, Labels: map[string]string{"site": "sfo"}},
		{ID: "globex-1", Name: "globex-1", TenantID: globex.ID, Labels: map[string]string{"site": "lon"}},
		{ID: "shared-1", Name: "shared-1", Labels: map[string]string{"site": "ams"}}, // global/untagged
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("upsert %s: %v", dev.ID, err)
		}
	}
	s := &server{discovery: d, tenants: ts}

	tile := func(tiles []MetricTile, title string) string {
		for _, t := range tiles {
			if t.Title == title {
				return t.Value
			}
		}
		return "<missing>"
	}

	// acme (scoped): only its 2 devices and 2 sites.
	acmeTiles := s.currentMetricTiles(jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: acme.ID})
	if got := tile(acmeTiles, "Devices"); got != "2" {
		t.Errorf("acme Devices tile = %s, want 2 (leak if higher)", got)
	}
	if got := tile(acmeTiles, "Sites"); got != "2" {
		t.Errorf("acme Sites tile = %s, want 2", got)
	}

	// Platform owner (cross-tenant), NOTHING restricted: the whole fleet of 4
	// devices, 4 sites. The restriction is a no-op when no tenant has switched
	// it on, which is every default deployment.
	ownerTiles := s.currentMetricTiles(jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if got := tile(ownerTiles, "Devices"); got != "4" {
		t.Errorf("platform owner Devices tile = %s, want 4 (no tenant is restricted here)", got)
	}
	if got := tile(ownerTiles, "Sites"); got != "4" {
		t.Errorf("platform owner Sites tile = %s, want 4 (no tenant is restricted here)", got)
	}
}
