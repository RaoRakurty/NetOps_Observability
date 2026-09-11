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

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
