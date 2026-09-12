// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// dem_experience_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for
// the Digital Experience CAUSALITY surfaces, exercised through the REAL router,
// the REAL auth middleware and the REAL s.demAuthz gate mapping
// (org_isolation_test.go / dem_isolation_test.go template), because the gate
// CHOICE is half of what §3a rule 3 is about.
//
// The route templates this file covers, written literally so the isolation
// COVERAGE guard (route_isolation_coverage_test.go) can see that each scoped
// route is actually exercised:
//
//	/api/dem/overview
//	/api/dem/incidents
//	/api/dem/incidents/
//	/api/dem/journeys
//	/api/dem/journeys/
//	/api/dem/synthetics/coverage
//	/api/dem/changes
//	/api/dem/data-health
//
// Proven here:
//   - own-only list: org A never sees org B's journeys or changes, and vice versa;
//   - the owner is stamped from the TOKEN — a tenant_id in a body is refused
//     outright rather than silently re-owned;
//   - cross-tenant GET / PUT / DELETE of a foreign journey id → 404, and the
//     victim's row survives;
//   - a foreign INCIDENT id → 404 (an incident id is derived from the tenant, so
//     it must never resolve under another tenant's scope);
//   - an `as_tenant` selector into another org is ignored (it can only NARROW);
//   - the platform owner in the Global view is REFUSED rather than served every
//     tenant's rows, on EVERY route;
//   - the derived views are HONEST when nothing was measured — never an empty
//     table that reads as "all well", and never a fabricated score.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/dem"
	"netops/backend/internal/dem/experience"
)

// experienceFixtures builds the real server with both DEM surfaces wired and
// two orgs, each with one tenant and one operator.
func experienceFixtures(t *testing.T) (srv *httptest.Server, s *server, a, b *orgFixture) {
	t.Helper()
	hs, st, fa, fb := demFixtures(t)
	st.demExperienceMetrics = experience.NewCounters()
	st.experienceStore = experience.NewFileStore(filepath.Join(t.TempDir(), "dem_experience.json"))
	api, err := st.buildExperienceAPI(st.experienceStore, st.demTargets)
	if err != nil {
		t.Fatalf("buildExperienceAPI: %v", err)
	}
	st.experienceAPI = api
	return hs, st, fa, fb
}

func expCreateJourney(t *testing.T, srv *httptest.Server, token, name, targetID string) experience.JourneyDefinition {
	t.Helper()
	code, body := do(t, srv, "POST", "/api/dem/journeys", token, map[string]any{
		"name": name, "app": "checkout", "business_importance": "critical",
		"entry_step_id": "browse",
		"slo":           map[string]any{"success_pct": 99.0},
		"steps": []map[string]any{
			{"id": "browse", "label": "Browse", "next": []string{"pay"}, "target_id": targetID},
			{"id": "pay", "label": "Pay", "terminal_success": true, "target_id": targetID},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("create journey %s: %d %s", name, code, body)
	}
	var out experience.JourneyDefinition
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode journey: %v (%s)", err, body)
	}
	return out
}

func expCreateChange(t *testing.T, srv *httptest.Server, token, object string) experience.ChangeEvent {
	t.Helper()
	code, body := do(t, srv, "POST", "/api/dem/changes", token, map[string]any{
		"type": "APPLICATION_DEPLOY", "object": object, "object_kind": "service",
		"summary": "deployed " + object, "app": "checkout",
	})
	if code != http.StatusCreated {
		t.Fatalf("record change %s: %d %s", object, code, body)
	}
	var out experience.ChangeEvent
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode change: %v (%s)", err, body)
	}
	return out
}

func expJourneyIDs(t *testing.T, srv *httptest.Server, token, path string) []string {
	t.Helper()
	code, body := do(t, srv, "GET", path, token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, code, body)
	}
	var resp struct {
		Journeys []experience.JourneyDefinition `json:"journeys"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	out := make([]string, 0, len(resp.Journeys))
	for _, j := range resp.Journeys {
		out = append(out, j.ID)
	}
	return out
}

func TestDEMExperienceJourneysCrossOrgIsolation(t *testing.T) {
	srv, s, a, b := experienceFixtures(t)

	ta := demCreate(t, srv, a.token, "A checkout", "10.70.245.11")
	tb := demCreate(t, srv, b.token, "B checkout", "10.70.245.12")
	ja := expCreateJourney(t, srv, a.token, "A checkout journey", ta.ID)
	jb := expCreateJourney(t, srv, b.token, "B checkout journey", tb.ID)

	// §3a rule 2: the owner comes from the token.
	if ja.TenantID != a.tenantID || jb.TenantID != b.tenantID {
		t.Fatalf("owner not stamped from the token: %q %q", ja.TenantID, jb.TenantID)
	}

	// Own-only list.
	if got := expJourneyIDs(t, srv, a.token, "/api/dem/journeys"); len(got) != 1 || got[0] != ja.ID {
		t.Fatalf("org A sees %v", got)
	}
	if got := expJourneyIDs(t, srv, b.token, "/api/dem/journeys"); len(got) != 1 || got[0] != jb.ID {
		t.Fatalf("org B sees %v", got)
	}

	// Cross-tenant get / put / delete → 404, and B's row survives.
	if code, body := do(t, srv, "GET", "/api/dem/journeys/"+jb.ID, a.token, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET → %d %s (an id must never be confirmed to exist)", code, body)
	}
	if code, _ := do(t, srv, "PUT", "/api/dem/journeys/"+jb.ID, a.token, map[string]any{
		"name": "hijacked", "entry_step_id": "browse",
		"steps": []map[string]any{{"id": "browse", "label": "Browse", "terminal_success": true}},
	}); code != http.StatusNotFound {
		t.Fatalf("cross-tenant PUT → %d", code)
	}
	if code, _ := do(t, srv, "DELETE", "/api/dem/journeys/"+jb.ID, a.token, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant DELETE → %d", code)
	}
	if got := expJourneyIDs(t, srv, b.token, "/api/dem/journeys"); len(got) != 1 || got[0] != jb.ID {
		t.Fatalf("org B's journey was mutated by org A: %v", got)
	}

	// as_tenant can only NARROW.
	if got := expJourneyIDs(t, srv, a.token, "/api/dem/journeys?as_tenant="+b.tenantID); len(got) != 1 || got[0] != ja.ID {
		t.Fatalf("as_tenant into another org widened the view: %v", got)
	}
	if s.reachesTenant(a.user, b.tenantID) {
		t.Fatal("org A's operator reaches org B's tenant")
	}

	// A tenant in the CREATE body cannot be expressed: the wire type has no such
	// field and unknown fields are refused outright.
	if code, _ := do(t, srv, "POST", "/api/dem/journeys", a.token, map[string]any{
		"name": "sneaky", "tenant_id": b.tenantID, "entry_step_id": "s",
		"steps": []map[string]any{{"id": "s", "terminal_success": true}},
	}); code != http.StatusBadRequest {
		t.Fatalf("a tenant claim in the body returned %d", code)
	}

	// The platform owner in the Global (cross-tenant) view is REFUSED…
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if code, body := do(t, srv, "GET", "/api/dem/journeys", admin, nil); code != http.StatusBadRequest {
		t.Fatalf("cross-tenant principal was served the journeys: %d %s", code, body)
	}
	// …and scoping in with the switcher works.
	if got := expJourneyIDs(t, srv, admin, "/api/dem/journeys?as_tenant="+b.tenantID); len(got) != 1 || got[0] != jb.ID {
		t.Fatalf("platform owner scoped into org B saw %v", got)
	}
}

func TestDEMExperienceChangesCrossOrgIsolation(t *testing.T) {
	srv, _, a, b := experienceFixtures(t)
	expCreateChange(t, srv, a.token, "checkout-api-a")
	expCreateChange(t, srv, b.token, "checkout-api-b")

	read := func(token string) []experience.ChangeEvent {
		t.Helper()
		code, body := do(t, srv, "GET", "/api/dem/changes", token, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /api/dem/changes: %d %s", code, body)
		}
		var resp struct {
			Changes []experience.ChangeEvent `json:"changes"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode: %v (%s)", err, body)
		}
		return resp.Changes
	}
	ca, cb := read(a.token), read(b.token)
	if len(ca) != 1 || ca[0].Object != "checkout-api-a" {
		t.Fatalf("org A sees %+v", ca)
	}
	if len(cb) != 1 || cb[0].Object != "checkout-api-b" {
		t.Fatalf("org B sees %+v", cb)
	}
	if ca[0].TenantID != a.tenantID {
		t.Fatalf("change owner not stamped from the token: %q", ca[0].TenantID)
	}

	// A tenant on the wire cannot be expressed.
	if code, _ := do(t, srv, "POST", "/api/dem/changes", a.token, map[string]any{
		"type": "CONFIG_CHANGE", "object": "x", "summary": "y", "tenant_id": b.tenantID,
	}); code != http.StatusBadRequest {
		t.Fatalf("a tenant claim in the change body returned %d", code)
	}
	// A cross-tenant principal is refused.
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if code, _ := do(t, srv, "GET", "/api/dem/changes", admin, nil); code != http.StatusBadRequest {
		t.Fatalf("cross-tenant principal was served the change feed: %d", code)
	}
}

// The derived surfaces are per tenant AND honest: with nothing measured they
// must say so rather than render an empty table that reads as "all well".
func TestDEMExperienceDerivedViewsAreScopedAndHonest(t *testing.T) {
	srv, _, a, b := experienceFixtures(t)
	ta := demCreate(t, srv, a.token, "A checkout", "10.70.245.11")
	expCreateJourney(t, srv, a.token, "A checkout journey", ta.ID)
	tb := demCreate(t, srv, b.token, "B checkout", "10.70.245.12")
	expCreateJourney(t, srv, b.token, "B checkout journey", tb.ID)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Overview: no metrics backend is wired in the test server, so nothing was
	// measured — and the response must SAY so, with no score.
	code, body := do(t, srv, "GET", "/api/dem/overview", a.token, nil)
	if code != http.StatusOK {
		t.Fatalf("overview: %d %s", code, body)
	}
	var ov experience.OverviewResponse
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("decode overview: %v (%s)", err, body)
	}
	if ov.Measured {
		t.Fatalf("an unmeasured window reported measured=true: %+v", ov.Score)
	}
	if ov.Score.Score != nil {
		t.Fatalf("an unmeasured window carried a score: %v", *ov.Score.Score)
	}
	if ov.Score.Reason == "" || ov.Score.Detail == "" {
		t.Fatalf("an unpublished score gave no reason: %+v", ov.Score)
	}
	if ov.Score.PolicyVersion == 0 {
		t.Fatal("the score carried no policy version — a score whose weights cannot be reconstructed is not auditable")
	}
	if len(ov.Journeys) != 1 {
		t.Fatalf("org A's overview holds %d journeys", len(ov.Journeys))
	}
	if ov.Journeys[0].Measured {
		t.Fatalf("an unmeasured journey reported measured=true: %+v", ov.Journeys[0])
	}
	// Data health must never render an absent source as healthy.
	if ov.DataHealth.CanConfirm {
		t.Fatal("a deployment with no flowing anchor source claimed it could confirm a cause")
	}
	for _, src := range ov.DataHealth.Sources {
		if src.State == "flowing" && src.EventsInWindow == 0 && src.Source != "synthetic" {
			t.Fatalf("source %q reported flowing with nothing in the window", src.Source)
		}
	}

	// Every derived route refuses a cross-tenant principal.
	for _, path := range []string{
		"/api/dem/overview",
		"/api/dem/incidents",
		"/api/dem/journeys",
		"/api/dem/synthetics/coverage",
		"/api/dem/changes",
		"/api/dem/data-health",
	} {
		if code, body := do(t, srv, "GET", path, admin, nil); code != http.StatusBadRequest {
			t.Fatalf("cross-tenant principal was served %s: %d %s", path, code, body)
		}
	}

	// An incident id derived under ANOTHER tenant's scope must never resolve
	// here: the id is a function of the tenant, so a foreign one is simply
	// absent — 404, not 403, so its existence is never confirmed.
	foreign := experience.IncidentID(b.tenantID, "journey", "checkout", time.Now().UTC().Truncate(time.Hour))
	if code, body := do(t, srv, "GET", "/api/dem/incidents/"+foreign, a.token, nil); code != http.StatusNotFound {
		t.Fatalf("an incident id derived for another tenant resolved: %d %s", code, body)
	}
}

// A well-formed but unknown incident id answers 404, and so does an
// unparseable one — the shapes are indistinguishable from the outside.
func TestDEMExperienceIncidentIDsAreNeverConfirmed(t *testing.T) {
	srv, _, a, _ := experienceFixtures(t)
	for _, id := range []string{
		"exp-00000000000000000000", // well formed, does not exist
		"../../etc/passwd",         // traversal-shaped
		"exp-zzzzzzzzzzzzzzzzzzzz", // right length, not hex
	} {
		if code, body := do(t, srv, "GET", "/api/dem/incidents/"+id, a.token, nil); code != http.StatusNotFound {
			t.Fatalf("GET /api/dem/incidents/%s → %d %s (must be 404)", id, code, body)
		}
	}
	for _, id := range []string{"jny-0000000000000000000000000000000f", "nope"} {
		if code, _ := do(t, srv, "GET", "/api/dem/journeys/"+id, a.token, nil); code != http.StatusNotFound {
			t.Fatalf("GET /api/dem/journeys/%s → %d (must be 404)", id, code)
		}
	}
}

// The route registrations in main.go are LITERALS so the isolation ledger's
// scanner can see them; this pins that they still match the module's constants.
func TestDEMExperienceRouteLiteralsMatchTheModuleConstants(t *testing.T) {
	pairs := [][2]string{
		{experience.OverviewPath, "/api/dem/overview"},
		{experience.IncidentsPath, "/api/dem/incidents"},
		{experience.IncidentItemPath, "/api/dem/incidents/"},
		{experience.JourneysPath, "/api/dem/journeys"},
		{experience.JourneyItemPath, "/api/dem/journeys/"},
		{experience.CoveragePath, "/api/dem/synthetics/coverage"},
		{experience.ChangesPath, "/api/dem/changes"},
		{experience.DataHealthPath, "/api/dem/data-health"},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			t.Fatalf("route constant drifted from the registered literal: %q != %q", p[0], p[1])
		}
	}
	// The gate mapping is shared with the catalogue surface on purpose: an
	// experience view is per-tenant operator data about the tenant's own
	// services, exactly like the targets it is computed from.
	if dem.GateRead == dem.GateWrite {
		t.Fatal("the module's read and write gates collapsed into one")
	}
}
