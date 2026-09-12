// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// dem_experience_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the operator-visibility restriction (Tenant.OperatorRestricted) on the Digital
// Experience lane, exercised through the REAL router, the REAL auth middleware and
// the REAL s.demAuthz gate mapping.
//
// Experience data is the customer's own end users and the customer's own revenue:
// RUM beacons, journeys, incidents, business events, the synthetic catalogue that
// names its hosts. A tenant that has switched the restriction on is invisible to
// the platform owner in logs, flows, metrics, igpmon and the BMP feed. It must be
// invisible here too.
//
// This lane has ONE half. The module refuses a cross-tenant caller outright, so
// there is no Global view a restricted tenant could appear in — the reachable half
// is the platform owner walking in with ?as_tenant, and that is what this closes.
// The Global refusal is asserted below so the claim stays true if it ever changes.
//
// The route templates covered, written literally so the isolation COVERAGE guard
// (route_isolation_coverage_test.go) can see them:
//
//	/api/dem/targets
//	/api/dem/targets/
//	/api/dem/experience
//	/api/dem/overview
//	/api/dem/incidents
//	/api/dem/journeys
//	/api/dem/journeys/
//	/api/dem/synthetics/coverage
//	/api/dem/changes
//	/api/dem/data-health

import (
	"net/http"
	"strings"
	"testing"
)

// demReadRoutes are every experience READ route the lane registers.
var demReadRoutes = []string{
	"/api/dem/targets",
	"/api/dem/experience",
	"/api/dem/overview",
	"/api/dem/incidents",
	"/api/dem/journeys",
	"/api/dem/synthetics/coverage",
	"/api/dem/changes",
	"/api/dem/data-health",
}

// TestDEMExperienceHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test.
func TestDEMExperienceHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	srv, s, a, b := experienceFixtures(t)
	owner := login(t, srv, "admin", "Passw0rd!2345").Token

	// Tenant A's own operator seeds its own experience data. Every marker below
	// is a byte the platform owner must stop seeing.
	targetA := demCreate(t, srv, a.token, "acme-pay-probe", "pay.acme.example")
	journeyA := expCreateJourney(t, srv, a.token, "acme-pay-journey", targetA.ID)
	expCreateChange(t, srv, a.token, "acme-cart-service")
	markers := []string{"acme-pay-probe", "pay.acme.example", "acme-pay-journey", "acme-cart-service"}

	// Tenant B seeds its own, so the test can prove the restriction is aimed at
	// one tenant rather than switching the lane off.
	targetB := demCreate(t, srv, b.token, "globex-pay-probe", "pay.globex.example")
	expCreateJourney(t, srv, b.token, "globex-pay-journey", targetB.ID)

	// The platform owner in the GLOBAL view is refused on every route — this is
	// why the lane has no Global half to filter.
	for _, route := range demReadRoutes {
		if code, body := do(t, srv, "GET", route, owner, nil); code != http.StatusBadRequest {
			t.Fatalf("GET %s (owner, Global) = %d, want the cross-tenant refusal: %s", route, code, body)
		}
	}

	// Baseline: with nothing restricted, the owner scoped into A reads A's data,
	// so this test cannot pass by serving nothing.
	seen := map[string]bool{}
	for _, route := range demReadRoutes {
		code, body := do(t, srv, "GET", route+"?as_tenant="+a.tenantID, owner, nil)
		if code != http.StatusOK {
			t.Fatalf("baseline GET %s (owner→A) = %d %s", route, code, body)
		}
		for _, m := range markers {
			if strings.Contains(string(body), m) {
				seen[m] = true
			}
		}
	}
	for _, m := range markers {
		if !seen[m] {
			t.Fatalf("baseline: the owner scoped into A never saw %q — the fixture proves nothing", m)
		}
	}
	if code, body := do(t, srv, "GET", "/api/dem/journeys/"+journeyA.ID+"?as_tenant="+a.tenantID, owner, nil); code != http.StatusOK {
		t.Fatalf("baseline owner→A journey get = %d %s", code, body)
	}
	if code, body := do(t, srv, "GET", "/api/dem/targets/"+targetA.ID+"?as_tenant="+a.tenantID, owner, nil); code != http.StatusOK {
		t.Fatalf("baseline owner→A target get = %d %s", code, body)
	}

	if _, err := s.tenants.SetOperatorRestricted(a.tenantID, true); err != nil {
		t.Fatalf("restrict tenant A: %v", err)
	}

	// ── the reachable half: ?as_tenant into the restricted tenant reads nothing.
	// A 200 with an empty view, never a 403 — a refusal would confirm the tenant
	// has experience data at all.
	for _, route := range demReadRoutes {
		code, body := do(t, srv, "GET", route+"?as_tenant="+a.tenantID, owner, nil)
		if code != http.StatusOK {
			t.Errorf("GET %s (owner→restricted A) = %d, want 200 with an empty view: %s", route, code, body)
			continue
		}
		for _, m := range markers {
			if strings.Contains(string(body), m) {
				t.Errorf("RESTRICTION LEAK on %s — the platform owner saw %q: %s", route, m, body)
			}
		}
	}

	// A foreign id under the restricted scope is a 404, the same answer another
	// tenant's id gets — the resource is not merely filtered out of a list.
	if code, body := do(t, srv, "GET", "/api/dem/journeys/"+journeyA.ID+"?as_tenant="+a.tenantID, owner, nil); code != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: owner→restricted A read journey %s: %d %s", journeyA.ID, code, body)
	}
	if code, body := do(t, srv, "GET", "/api/dem/targets/"+targetA.ID+"?as_tenant="+a.tenantID, owner, nil); code != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: owner→restricted A read target %s: %d %s", targetA.ID, code, body)
	}

	// The owner scoped into the UNRESTRICTED tenant still reads it.
	code, body := do(t, srv, "GET", "/api/dem/journeys?as_tenant="+b.tenantID, owner, nil)
	if code != http.StatusOK || !strings.Contains(string(body), "globex-pay-journey") {
		t.Errorf("owner→B journeys = %d %s, want globex's own journey", code, body)
	}

	// And tenant A's OWN operator is never restricted from its own experience —
	// the switch hides a tenant from the PLATFORM, never from itself.
	code, body = do(t, srv, "GET", "/api/dem/journeys", a.token, nil)
	if code != http.StatusOK || !strings.Contains(string(body), "acme-pay-journey") {
		t.Fatalf("tenant A lost its own journeys: %d %s", code, body)
	}
	code, body = do(t, srv, "GET", "/api/dem/targets", a.token, nil)
	if code != http.StatusOK || !strings.Contains(string(body), "acme-pay-probe") {
		t.Fatalf("tenant A lost its own targets: %d %s", code, body)
	}
}
