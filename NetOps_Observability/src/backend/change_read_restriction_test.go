// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// change_read_restriction_test.go — the CLAUDE.md §3a rule-5 test for the
// per-tenant operator-visibility restriction (Tenant.OperatorRestricted) on every
// change-ledger read outside the DEM routes, through the REAL router, the REAL
// auth middleware and withActingTenant (which is what honours as_tenant):
//
//	/api/changes
//	/api/changes/{id}
//	/api/changes/{id}/diff
//	the Iris NL change read (nlqScope.Changes)
//	the Iris NL application seeds (nlqScope.appSeeds)
//
// The DEM change routes already hid a restricted tenant from the platform owner
// (dem_experience_restriction_test.go); these did not (INVARIANTS §25). One
// helper, changeLedgerReadTenant, now decides for all five, and
// TestNLQScopeMethodsCallTheirChokepoints pins that they call it.
//
// The NL reads have no route of their own to aim a change question at without a
// compiled query, so their claims are produced by the real auth middleware
// (s.withAuth → withActingTenant) from the real login token, and the scope is
// built from exactly the request and claims a handler would receive.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/plan"
)

// claimsThroughAuth runs a request carrying token through the real auth
// middleware and returns the request and the EFFECTIVE claims a handler sees.
func claimsThroughAuth(t *testing.T, s *server, token, path string, header map[string]string) (*http.Request, jwtClaims) {
	t.Helper()
	var (
		gotReq    *http.Request
		gotClaims jwtClaims
		got       bool
	)
	h := s.withAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotReq = r
		gotClaims, got = userFrom(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !got {
		t.Fatalf("auth middleware refused %s: %d %s", path, w.Code, w.Body.String())
	}
	return gotReq, gotClaims
}

// nlChangesAndSeeds is what the two NL ledger reads return for one caller.
func nlChangesAndSeeds(t *testing.T, s *server, token, path string, header map[string]string) (string, string) {
	t.Helper()
	r, c := claimsThroughAuth(t, s, token, path, header)
	ctx := context.Background()
	rows, _, err := s.nlqScopeFor(r, c).Changes(ctx, plan.ChangeQuery{From: time.Now().Add(-time.Hour), Limit: 50})
	if err != nil {
		t.Fatalf("NL change read %s: %v", path, err)
	}
	seeds, err := s.nlqScopeFor(r, c).appSeeds(ctx)
	if err != nil {
		t.Fatalf("NL application seeds %s: %v", path, err)
	}
	return nlqJSON(map[string]any{"rows": rows}), nlqJSON(map[string]any{"seeds": seeds})
}

// aMarkers are every byte of tenant A's ledger and journeys the restricted
// platform owner must stop seeing: its device change, its cloud change, the
// cloud change's application and its journey's application.
var aMarkers = []string{"dev-own", "own-cloud", "own-app", "acme-checkout"}

func leakedMarker(body string) string {
	for _, m := range aMarkers {
		if strings.Contains(body, m) {
			return m
		}
	}
	return ""
}

func TestChangeReadsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	srv, s, a, b := experienceFixtures(t)
	if s.nlqCatalog == nil {
		s.nlqCatalog = catalog.MustLoad()
	}
	seedProviderChanges(t, s.experienceStore, a.tenantID)
	// A journey names an application too, and the NL seeds read journeys.
	target := demCreate(t, srv, a.token, "acme-pay-probe", "pay.acme.example")
	code, jbody := do(t, srv, "POST", "/api/dem/journeys", a.token, map[string]any{
		"name": "acme-pay-journey", "app": "acme-checkout", "business_importance": "critical",
		"entry_step_id": "browse", "slo": map[string]any{"success_pct": 99.0},
		"steps": []map[string]any{
			{"id": "browse", "label": "Browse", "next": []string{"pay"}, "target_id": target.ID},
			{"id": "pay", "label": "Pay", "terminal_success": true, "target_id": target.ID},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("create A's journey: %d %s", code, jbody)
	}
	// Tenant B's own change, so the restriction is shown aimed at one tenant.
	now := time.Now().UTC().Add(-time.Minute)
	if _, err := s.experienceStore.RecordChange(context.Background(), experience.ChangeEvent{
		TenantID: b.tenantID, ID: "chg-b-own", Type: experience.ChangeCloud, Object: "globex-cloud", App: "globex-app",
		Summary: "b's cloud change", Provenance: experience.Provenance{Source: experience.SourceCloud, EventAt: now,
			Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata},
	}); err != nil {
		t.Fatal(err)
	}
	owner := login(t, srv, "admin", "Passw0rd!2345").Token
	get := func(token, path string) (int, map[string]any, string) {
		t.Helper()
		code, body := do(t, srv, "GET", path, token, nil)
		var out map[string]any
		_ = json.Unmarshal(body, &out) // best-effort: a refusal is asserted by status and body
		return code, out, string(body)
	}
	intoA := "?as_tenant=" + a.tenantID

	// ── Baseline, nothing restricted: the owner scoped into A reads every marker
	// on every path, so the assertions below cannot pass by serving nothing.
	code, out, body := get(owner, "/api/changes"+intoA)
	objects := changeRowsByObject(out)
	devOwn, ownCloud := objects["dev-own"], objects["own-cloud"]
	if code != http.StatusOK || devOwn == "" || ownCloud == "" {
		t.Fatalf("baseline owner→A list: %d %s", code, body)
	}
	for _, id := range []string{devOwn, ownCloud} {
		for _, sub := range []string{"", "/diff"} {
			if code, _, body := get(owner, "/api/changes/"+id+sub+intoA); code != http.StatusOK {
				t.Fatalf("baseline owner→A /api/changes/%s%s: %d %s", id, sub, code, body)
			}
		}
	}
	rows, seeds := nlChangesAndSeeds(t, s, owner, "/api/ai/query/execute"+intoA, nil)
	if !strings.Contains(rows, "dev-own") || !strings.Contains(rows, "own-cloud") {
		t.Fatalf("baseline owner→A NL change read: %s", rows)
	}
	if !strings.Contains(seeds, "own-app") || !strings.Contains(seeds, "acme-checkout") {
		t.Fatalf("baseline owner→A NL application seeds: %s", seeds)
	}

	if _, err := s.tenants.SetOperatorRestricted(a.tenantID, true); err != nil {
		t.Fatalf("restrict tenant A: %v", err)
	}

	// ── The owner scoped INTO restricted A, by query and by header: an empty
	// 200 list and 404 by id — never a 403, which would confirm A has changes.
	for _, walk := range []struct {
		name, query string
		header      map[string]string
	}{
		{"as_tenant", intoA, nil},
		{"X-Acting-Tenant", "", map[string]string{"X-Acting-Tenant": a.tenantID}},
	} {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/changes"+walk.query, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+owner)
		for k, v := range walk.header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var listed map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&listed) // asserted by status and content
		_ = resp.Body.Close()                          // test client: nothing to recover
		if lb := nlqJSON(listed); resp.StatusCode != http.StatusOK || len(changeRowsByObject(listed)) != 0 || leakedMarker(lb) != "" {
			t.Errorf("RESTRICTION LEAK: owner→restricted A list (%s): %d %s", walk.name, resp.StatusCode, lb)
		}
		rows, seeds := nlChangesAndSeeds(t, s, owner, "/api/ai/query/execute"+walk.query, walk.header)
		if m := leakedMarker(rows); m != "" {
			t.Errorf("RESTRICTION LEAK: owner→restricted A NL change read (%s) shows %q: %s", walk.name, m, rows)
		}
		if m := leakedMarker(seeds); m != "" {
			t.Errorf("RESTRICTION LEAK: owner→restricted A NL application seeds (%s) show %q: %s", walk.name, m, seeds)
		}
	}
	for _, id := range []string{devOwn, ownCloud} {
		for _, sub := range []string{"", "/diff"} {
			if code, _, body := get(owner, "/api/changes/"+id+sub+intoA); code != http.StatusNotFound {
				t.Errorf("RESTRICTION LEAK: owner→restricted A /api/changes/%s%s: %d, want 404: %s", id, sub, code, body)
			}
		}
	}

	// ── The Global view while A is restricted: the Provider's ledger, and
	// nothing of A on any path.
	code, out, body = get(owner, "/api/changes")
	if objects := changeRowsByObject(out); code != http.StatusOK || objects["core-global"] == "" || leakedMarker(body) != "" {
		t.Errorf("Global view with A restricted: %d %s", code, body)
	}
	for _, id := range []string{devOwn, ownCloud} {
		for _, sub := range []string{"", "/diff"} {
			if code, _, body := get(owner, "/api/changes/"+id+sub); code != http.StatusNotFound {
				t.Errorf("RESTRICTION LEAK: Global view /api/changes/%s%s: %d, want 404: %s", id, sub, code, body)
			}
		}
	}
	rows, seeds = nlChangesAndSeeds(t, s, owner, "/api/ai/query/execute", nil)
	if !strings.Contains(rows, "core-global") || leakedMarker(rows) != "" {
		t.Errorf("Global view NL change read with A restricted: %s", rows)
	}
	if !strings.Contains(seeds, "provider-app") || leakedMarker(seeds) != "" {
		t.Errorf("Global view NL application seeds with A restricted: %s", seeds)
	}

	// ── The owner scoped into UNRESTRICTED B still reads B.
	intoB := "?as_tenant=" + b.tenantID
	if code, out, body := get(owner, "/api/changes"+intoB); code != http.StatusOK || changeRowsByObject(out)["globex-cloud"] != "chg-b-own" {
		t.Errorf("owner→B list: %d %s", code, body)
	}
	if code, _, body := get(owner, "/api/changes/chg-b-own"+intoB); code != http.StatusOK {
		t.Errorf("owner→B by id: %d %s", code, body)
	}
	rows, seeds = nlChangesAndSeeds(t, s, owner, "/api/ai/query/execute"+intoB, nil)
	if !strings.Contains(rows, "globex-cloud") || !strings.Contains(seeds, "globex-app") {
		t.Errorf("owner→B NL reads: %s %s", rows, seeds)
	}

	// ── Restricted A's OWN users keep their own ledger on every path: the
	// switch hides a tenant from the platform, never from itself.
	code, out, body = get(a.token, "/api/changes")
	if objects := changeRowsByObject(out); code != http.StatusOK || objects["dev-own"] != devOwn || objects["own-cloud"] != ownCloud {
		t.Fatalf("restricted A lost its own list: %d %s", code, body)
	}
	for _, sub := range []string{"", "/diff"} {
		if code, _, body := get(a.token, "/api/changes/"+devOwn+sub); code != http.StatusOK {
			t.Errorf("restricted A lost its own /api/changes/%s%s: %d %s", devOwn, sub, code, body)
		}
	}
	rows, seeds = nlChangesAndSeeds(t, s, a.token, "/api/ai/query/execute", nil)
	if !strings.Contains(rows, "dev-own") || !strings.Contains(seeds, "own-app") || !strings.Contains(seeds, "acme-checkout") {
		t.Errorf("restricted A lost its own NL reads: %s %s", rows, seeds)
	}
	// And B, scoped normally, never reads A — with or without an as_tenant walk.
	for _, walk := range []string{"", intoA} {
		if code, _, body := get(b.token, "/api/changes"+walk); code != http.StatusOK || leakedMarker(body) != "" {
			t.Errorf("CROSS-TENANT LEAK: B /api/changes%s: %d %s", walk, code, body)
		}
		if code, _, _ := get(b.token, "/api/changes/"+devOwn+walk); code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT LEAK: B by id%s: %d, want 404", walk, code)
		}
	}
}
