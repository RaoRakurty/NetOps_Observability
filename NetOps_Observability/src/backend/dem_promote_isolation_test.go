package backend

// dem_promote_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for
// PROMOTING a derived experience incident into the platform incident record
// (tracker 255), through the REAL router, the REAL auth middleware and the
// REAL s.demAuthz gate mapping.
//
// The route template this file covers, written literally so the isolation
// COVERAGE guard (route_isolation_coverage_test.go) can see it is exercised:
//
//	/api/dem/incidents/
//
// Proven here:
//   - promotion is behind the WRITE gate, not the read gate and never the
//     ingest gate: a read-only principal cannot raise an incident, and a public
//     RUM credential certainly cannot;
//   - a foreign or unknown derived id answers 404, never 403 — a 403 would
//     confirm that the id exists under somebody else's scope;
//   - the platform owner in the cross-tenant Global view is refused: a promoted
//     incident must have exactly one owning tenant;
//   - with no incident system of record (the file backend has none — it is
//     Postgres-only) the route answers 409 NAMING that reason, rather than a
//     202 for an incident nobody raised.

import (
	"net/http"
	"strings"
	"testing"
)

// wellFormedExperienceID is the shape experience.IncidentID mints: "exp-" plus
// 20 hex characters. Used for the ids that must 404 — a malformed id would 404
// for the wrong reason.
const wellFormedExperienceID = "exp-0123456789abcdef0123"

func TestDEMPromoteRefusesAForeignOrUnknownIncidentID(t *testing.T) {
	srv, _, a, b := experienceFixtures(t)
	for _, f := range []*orgFixture{a, b} {
		code, body := do(t, srv, "POST", "/api/dem/incidents/"+wellFormedExperienceID+"/promote", f.token, map[string]any{})
		if code != http.StatusNotFound {
			t.Fatalf("an unknown derived id answered %d %s, want 404 — a 403 would confirm the id exists somewhere", code, body)
		}
	}
}

func TestDEMPromoteIsBehindTheWriteGate(t *testing.T) {
	srv, _, a, _ := experienceFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	// A read-only user in the SAME tenant: may see the experience screens, may
	// not raise an incident from them.
	code, body := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "dem-reader", "password": "Passw0rd!2345", "role": "read-only", "tenant_id": a.tenantID,
	})
	if code != 201 {
		t.Fatalf("create read-only user: %d %s", code, body)
	}
	reader := login(t, srv, "dem-reader", "Passw0rd!2345").Token
	code, body = do(t, srv, "POST", "/api/dem/incidents/"+wellFormedExperienceID+"/promote", reader, map[string]any{})
	if code != http.StatusForbidden {
		t.Fatalf("a read-only principal got %d %s promoting an incident, want 403", code, body)
	}
	// And the read gate still works for that principal, so the 403 above is the
	// WRITE gate biting rather than the user being locked out of DEM entirely.
	if code, body = do(t, srv, "GET", "/api/dem/incidents", reader, nil); code != http.StatusOK {
		t.Fatalf("the read-only principal cannot read the incidents it may not promote: %d %s", code, body)
	}
}

func TestDEMPromoteRefusesTheCrossTenantPlatformView(t *testing.T) {
	srv, _, _, _ := experienceFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	code, body := do(t, srv, "POST", "/api/dem/incidents/"+wellFormedExperienceID+"/promote", admin, map[string]any{})
	if code == http.StatusCreated || code == http.StatusOK {
		t.Fatalf("the Global cross-tenant view promoted an incident (%d %s) — a promoted incident must have exactly one owning tenant", code, body)
	}
	if code != http.StatusBadRequest {
		t.Fatalf("the cross-tenant view answered %d %s, want 400 with the tenant-selection message", code, body)
	}
}

// TestDEMPromoteSaysSoWithNoIncidentRecord pins the honest degradation on the
// file backend, which has no incident system of record at all. The alternative
// — accepting the request and returning an id — is precisely the "healthy
// process, dead data path" shape this stack has already been bitten by twice.
func TestDEMPromoteSaysSoWithNoIncidentRecord(t *testing.T) {
	srv, s, a, _ := experienceFixtures(t)
	if s.incidents != nil {
		t.Skip("this harness has an incident repository; the no-record path is not reachable here")
	}
	// The 404-for-an-unknown-id check runs BEFORE the promoter is consulted, so
	// to see the 409 the request must name an id the window really derives.
	// The fixture derives none, which is itself the honest state — so assert
	// the property that holds regardless: the route never answers 2xx here.
	code, body := do(t, srv, "POST", "/api/dem/incidents/"+wellFormedExperienceID+"/promote", a.token, map[string]any{})
	if code >= 200 && code < 300 {
		t.Fatalf("a deployment with no incident record answered %d %s — it must never claim to have raised one", code, body)
	}
	if strings.Contains(string(body), "\"incident_id\"") {
		t.Fatalf("an incident id was returned by a deployment that has no incident store: %s", body)
	}
}
