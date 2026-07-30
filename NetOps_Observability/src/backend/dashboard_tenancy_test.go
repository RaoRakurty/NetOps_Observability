package backend

import (
	"netops/backend/internal/discovery"
	"testing"

	"netops/backend/models"
)

// The Overview dashboard tiles must be tenant-scoped: a scoped principal's
// "Devices" / "Sites" counts reflect ONLY its own devices, never the global
// fleet (the reported leak). The platform owner still sees the whole fleet.
func TestMetricTilesTenantScoped(t *testing.T) {
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-1", Name: "acme-1", TenantID: "acme", Labels: map[string]string{"site": "nyc"}})
	d.Upsert(models.Device{ID: "acme-2", Name: "acme-2", TenantID: "acme", Labels: map[string]string{"site": "sfo"}})
	d.Upsert(models.Device{ID: "globex-1", Name: "globex-1", TenantID: "globex", Labels: map[string]string{"site": "lon"}})
	d.Upsert(models.Device{ID: "shared-1", Name: "shared-1", Labels: map[string]string{"site": "ams"}}) // global/untagged
	s := &server{discovery: d}

	tile := func(tiles []MetricTile, title string) string {
		for _, t := range tiles {
			if t.Title == title {
				return t.Value
			}
		}
		return "<missing>"
	}

	// acme (scoped): only its 2 devices and 2 sites.
	acmeTiles := s.currentMetricTiles(jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: "acme"})
	if got := tile(acmeTiles, "Devices"); got != "2" {
		t.Errorf("acme Devices tile = %s, want 2 (leak if higher)", got)
	}
	if got := tile(acmeTiles, "Sites"); got != "2" {
		t.Errorf("acme Sites tile = %s, want 2", got)
	}

	// Platform owner (cross-tenant): the whole fleet of 4 devices, 4 sites.
	ownerTiles := s.currentMetricTiles(jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if got := tile(ownerTiles, "Devices"); got != "4" {
		t.Errorf("platform owner Devices tile = %s, want 4", got)
	}
	if got := tile(ownerTiles, "Sites"); got != "4" {
		t.Errorf("platform owner Sites tile = %s, want 4", got)
	}
}
