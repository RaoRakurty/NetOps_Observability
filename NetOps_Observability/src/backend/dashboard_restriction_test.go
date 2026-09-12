// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// dashboard_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the operator-visibility restriction (Tenant.OperatorRestricted) on the
// dashboard's CRITICAL THREATS tile, GET /api/metrics.
//
// The alert lane itself was closed by folding the restriction into
// alertVisibility. The tile counted through the older, restriction-blind
// alertVisible, so the alerts themselves were gone from the operator's feed
// while the headline still said how many of them there were.
//
// A COUNT IS A DISCLOSURE. The security plane proved it when
// coverage.total_assets reported 3 instead of 1 and gave away a restricted
// tenant's fleet size. "Critical Threats: 3" on a Global dashboard that lists
// only one critical alert says the same thing about the tenant that is hidden:
// that it exists, and that it is on fire.
//
// The DEVICES and SITES tiles were left alone at the time, on the grounds that
// they count inventory and the restriction had never covered the device
// registry. The owner has since decided what the restriction means here:
// devices and sites are counted per tenant, so a restricted tenant's inventory
// is not part of the platform operator's count either. That is the subject of
// the second test in this file.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/models"
)

// metricTiles drives the real GET /api/metrics handler and returns the tiles.
func metricTiles(t *testing.T, s *server, claims jwtClaims) []MetricTile {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleMetricTiles(w, req(http.MethodGet, "/api/metrics", "", claims))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/metrics = %d (%s)", w.Code, w.Body.String())
	}
	var tiles []MetricTile
	if err := json.Unmarshal(w.Body.Bytes(), &tiles); err != nil {
		t.Fatalf("decode tiles: %v (%s)", err, w.Body.String())
	}
	return tiles
}

// TestDashboardTilesHonourTheOperatorVisibilityRestriction asserts BOTH halves:
// the restricted tenant's critical alerts are not counted in the platform
// owner's Global tile, and an as_tenant view into that tenant counts nothing.
func TestDashboardTilesHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedAlertFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Baseline: three critical alerts are active — acme's device alert, acme's
	// device-less experience alert and globex's device alert. The fourth is a
	// warning and is never counted. Without this the assertions below could pass
	// on a tile that always reads zero.
	if got := criticalThreatTile(t, metricTiles(t, f.s, owner)); got != "3" {
		t.Fatalf("baseline Critical Threats = %q, want \"3\" — the fixture does not reach the tile", got)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the Global view. acme's two critical alerts stop counting;
	//    globex's still does.
	if got := criticalThreatTile(t, metricTiles(t, f.s, owner)); got != "1" {
		t.Errorf("RESTRICTION LEAK: the Global Critical Threats tile = %q, want \"1\". "+
			"It is still counting the restricted tenant's critical alerts (%q on acme-core and the experience alert on %s), "+
			"so the headline discloses that acme exists and is in trouble while the alert feed hides it.",
			got, acmeAlertID, acmeExpTarget)
	}

	// ── half 2: the owner walks in with as_tenant=acme. It counts nothing.
	if got := criticalThreatTile(t, metricTiles(t, f.s, ownerActing(owner, f.acme))); got != "0" {
		t.Errorf("RESTRICTION LEAK: the as_tenant=acme Critical Threats tile = %q, want \"0\" — "+
			"it is counting %q and the experience alert on %s for an operator that may read neither.",
			got, acmeAlertID, acmeExpTarget)
	}

	// ── the owner scoped into the UNRESTRICTED tenant still counts it.
	if got := criticalThreatTile(t, metricTiles(t, f.s, ownerActing(owner, f.globex))); got != "1" {
		t.Errorf("as_tenant=globex Critical Threats = %q, want \"1\" — restricting acme must not change globex", got)
	}

	// ── acme's OWN operator still counts acme's own critical alerts. The switch
	//    hides a tenant from the PLATFORM, never from itself.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	if got := criticalThreatTile(t, metricTiles(t, f.s, acmeUser)); got != "2" {
		t.Fatalf("acme's own operator's Critical Threats = %q, want \"2\" (its device alert + its experience alert)", got)
	}
}

// metricTileValue reads one tile out of the dashboard payload by title.
func metricTileValue(t *testing.T, tiles []MetricTile, title string) string {
	t.Helper()
	for _, tile := range tiles {
		if tile.Title == title {
			return tile.Value
		}
	}
	t.Fatalf("no %q tile: %+v", title, tiles)
	return ""
}

// inventoryTiles returns the Devices and Sites tile values for one principal.
func inventoryTiles(t *testing.T, s *server, claims jwtClaims) (devices, sites string) {
	t.Helper()
	tiles := metricTiles(t, s, claims)
	return metricTileValue(t, tiles, "Devices"), metricTileValue(t, tiles, "Sites")
}

// TestDashboardInventoryTilesHonourTheOperatorVisibilityRestriction is the
// CLAUDE.md §3a rule-5 isolation test for the DEVICES and SITES tiles.
//
// This is an owner decision about what the restriction means, not a defect. The
// restriction began as a telemetry rule and the device registry sat outside it.
// The owner has ruled that devices and sites are counted PER TENANT, so a
// restricted tenant's devices and sites leave the platform operator's counts.
//
// Both halves are asserted, and so is the half that must NOT move: a tenant
// still counts its own fleet exactly as before. The switch hides a tenant from
// the PLATFORM, never from itself.
func TestDashboardInventoryTilesHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedAlertFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}

	// The alert fixture's two devices carry no site label. Give the estate sites
	// and a second device per tenant, so the Sites tile has something to hide and
	// the Devices tile counts more than one row per owner. stack-jump is
	// platform-owned (no tenant) and must survive every filter below — a fix that
	// passes by counting nothing is not a fix.
	for _, d := range []models.Device{
		{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.2", TenantID: f.acme, Labels: map[string]string{"site": "nyc"}},
		{ID: "acme-branch", Name: "acme-branch", Address: "10.1.0.3", TenantID: f.acme, Labels: map[string]string{"site": "sfo"}},
		{ID: "globex-edge", Name: "globex-edge", Address: "10.2.0.2", TenantID: f.globex, Labels: map[string]string{"site": "lon"}},
		{ID: "stack-jump", Name: "stack-jump", Address: "10.9.0.1", Labels: map[string]string{"site": "ams"}},
	} {
		if err := f.s.discovery.Upsert(d); err != nil {
			t.Fatalf("upsert %s: %v", d.ID, err)
		}
	}

	// Baseline: six devices (two acme + the acme-core the fixture seeded, two
	// globex, one platform) across four sites. Without this the assertions below
	// could pass on tiles that always read zero.
	if devices, sites := inventoryTiles(t, f.s, owner); devices != "6" || sites != "4" {
		t.Fatalf("baseline Global tiles = Devices %q / Sites %q, want \"6\" / \"4\" — the fixture does not reach the tiles", devices, sites)
	}
	// And acme's own counts BEFORE the switch, so the guard below compares
	// against a number this test measured rather than one it assumed.
	beforeDevices, beforeSites := inventoryTiles(t, f.s, acmeUser)
	if beforeDevices != "3" || beforeSites != "2" {
		t.Fatalf("acme's own tiles = Devices %q / Sites %q, want \"3\" / \"2\"", beforeDevices, beforeSites)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the Global view. acme's three devices and its two sites stop
	//    counting; globex's two devices, its site and the platform's stay.
	devices, sites := inventoryTiles(t, f.s, owner)
	if devices != "3" {
		t.Errorf("RESTRICTION LEAK: the Global Devices tile = %q, want \"3\". "+
			"It is still counting the restricted tenant's acme-core, acme-edge and acme-branch, "+
			"so the headline discloses acme's fleet size to an operator that may not read it.", devices)
	}
	if sites != "2" {
		t.Errorf("RESTRICTION LEAK: the Global Sites tile = %q, want \"2\". "+
			"It is still counting acme's nyc and sfo, which names where the restricted tenant operates.", sites)
	}

	// ── half 2: the owner walks in with as_tenant=acme. It counts nothing.
	if devices, sites := inventoryTiles(t, f.s, ownerActing(owner, f.acme)); devices != "0" || sites != "0" {
		t.Errorf("RESTRICTION LEAK: the as_tenant=acme tiles = Devices %q / Sites %q, want \"0\" / \"0\" — "+
			"an operator scoped into a restricted tenant may read none of its inventory.", devices, sites)
	}

	// ── the owner scoped into the UNRESTRICTED tenant still counts it.
	if devices, sites := inventoryTiles(t, f.s, ownerActing(owner, f.globex)); devices != "2" || sites != "1" {
		t.Errorf("as_tenant=globex tiles = Devices %q / Sites %q, want \"2\" / \"1\" — restricting acme must not change globex", devices, sites)
	}

	// ── acme's OWN view is unchanged. This is the guard on the decision: the
	//    counts move for the PLATFORM operator only.
	afterDevices, afterSites := inventoryTiles(t, f.s, acmeUser)
	if afterDevices != beforeDevices || afterSites != beforeSites {
		t.Errorf("acme's own tiles changed when acme restricted itself: Devices %q→%q, Sites %q→%q — "+
			"the switch hides a tenant from the platform, never from itself.",
			beforeDevices, afterDevices, beforeSites, afterSites)
	}
}
