// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/internal/saved"
)

// tenant_overview_default_test.go — the team-default Overview dashboard
// (2026-11-22). §3a: the default is keyed by the caller's tenant in the store,
// stamped from the token; only a tenant admin sets it; it can only name the
// tenant's OWN dashboard; another tenant never sees it; a deleted or unreadable
// default falls back to the built-in Overview.

func overviewDefaultServer(t *testing.T) *server {
	t.Helper()
	s := tenantServer(t)
	s.displayPrefs = newTenantDisplayStore("")
	return s
}

func tenantAdmin(tenant string) jwtClaims {
	return jwtClaims{Sub: "adm@" + tenant, Role: "admin", Tenant: tenant}
}

func putOverviewDefault(s *server, path, body string, c jwtClaims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleOverviewDefault(w, req(http.MethodPut, path, body, c))
	return w
}

func getOverviewDefault(t *testing.T, s *server, c jwtClaims) overviewDefaultView {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleOverviewDefault(w, req(http.MethodGet, "/api/settings/overview-default", "", c))
	if w.Code != http.StatusOK {
		t.Fatalf("GET as %s: %d %s", c.Sub, w.Code, w.Body.String())
	}
	var v overviewDefaultView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func seedDashboardAs(t *testing.T, s *server, c jwtClaims, typ string) saved.Object {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSaved(w, req(http.MethodPost, "/api/saved", `{"type":"`+typ+`","name":"board","body":{"v":1,"cells":[]}}`, c))
	if w.Code != http.StatusCreated {
		t.Fatalf("seed %s as %s: %d %s", typ, c.Sub, w.Code, w.Body.String())
	}
	var o saved.Object
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestOverviewDefaultCrossTenantIsolation(t *testing.T) {
	s := overviewDefaultServer(t)
	dAcme := seedDashboardAs(t, s, acme(), "dashboard")
	dGlobex := seedDashboardAs(t, s, globex(), "dashboard")
	const path = "/api/settings/overview-default"

	// The acme admin promotes acme's own dashboard.
	if w := putOverviewDefault(s, path, `{"dashboard_id":"`+dAcme.ID+`"}`, tenantAdmin("acme")); w.Code != http.StatusOK {
		t.Fatalf("acme admin promote own dashboard: %d %s", w.Code, w.Body.String())
	}
	// Every acme user opens it…
	if v := getOverviewDefault(t, s, acme()); v.Dashboard == nil || v.Dashboard.ID != dAcme.ID || v.Unavailable {
		t.Fatalf("acme operator must open acme's team default, got %+v", v)
	}
	// …and globex sees nothing of it: not the id, not the dashboard.
	if v := getOverviewDefault(t, s, globex()); v.DashboardID != "" || v.Dashboard != nil || v.Unavailable {
		t.Fatalf("globex saw acme's team default: %+v", v)
	}

	// The acme admin cannot promote another tenant's dashboard: 404, never a hint.
	if w := putOverviewDefault(s, path, `{"dashboard_id":"`+dGlobex.ID+`"}`, tenantAdmin("acme")); w.Code != http.StatusNotFound {
		t.Fatalf("acme admin promoted globex's dashboard: %d, want 404", w.Code)
	}
	// ?as_tenant does not move a scoped admin into another tenant.
	if w := putOverviewDefault(s, path+"?as_tenant=globex", `{"dashboard_id":"`+dGlobex.ID+`"}`, tenantAdmin("acme")); w.Code != http.StatusNotFound {
		t.Fatalf("as_tenant=globex let acme's admin promote globex's dashboard: %d", w.Code)
	}
	// A tenant in the body is refused, never applied.
	if w := putOverviewDefault(s, path, `{"dashboard_id":"`+dGlobex.ID+`","tenant_id":"globex"}`, tenantAdmin("acme")); w.Code != http.StatusBadRequest {
		t.Fatalf("a body tenant_id must be refused: %d", w.Code)
	}
	if v := getOverviewDefault(t, s, globex()); v.DashboardID != "" {
		t.Fatalf("globex's default was written by acme: %+v", v)
	}
	if v := getOverviewDefault(t, s, acme()); v.DashboardID != dAcme.ID {
		t.Fatalf("acme's default moved after refused writes: %+v", v)
	}

	// Globex's own admin sets globex's default independently.
	if w := putOverviewDefault(s, path, `{"dashboard_id":"`+dGlobex.ID+`"}`, tenantAdmin("globex")); w.Code != http.StatusOK {
		t.Fatalf("globex admin promote own dashboard: %d %s", w.Code, w.Body.String())
	}
	if v := getOverviewDefault(t, s, acme()); v.DashboardID != dAcme.ID {
		t.Fatalf("globex's write changed acme's default: %+v", v)
	}
}

func TestOverviewDefaultNeedsTenantAdmin(t *testing.T) {
	s := overviewDefaultServer(t)
	d := seedDashboardAs(t, s, acme(), "dashboard")
	for _, c := range []jwtClaims{acme(), {Sub: "ro@acme", Role: RoleReadOnly, Tenant: "acme"}, savedAs(RoleIngest)} {
		if w := putOverviewDefault(s, "/api/settings/overview-default", `{"dashboard_id":"`+d.ID+`"}`, c); w.Code != http.StatusForbidden {
			t.Fatalf("%s (%s) set the team default: %d, want 403", c.Sub, c.Role, w.Code)
		}
	}
	if v := getOverviewDefault(t, s, acme()); v.DashboardID != "" {
		t.Fatalf("a refused write landed: %+v", v)
	}
}

func TestOverviewDefaultOnlyNamesTheTenantsOwnDashboard(t *testing.T) {
	s := overviewDefaultServer(t)
	search := seedDashboardAs(t, s, acme(), "saved_search")
	shared := seedDashboardAs(t, s, superA(), "dashboard") // platform-owned, no tenant
	for name, id := range map[string]string{"saved search": search.ID, "shared dashboard": shared.ID, "unknown id": "nope"} {
		if w := putOverviewDefault(s, "/api/settings/overview-default", `{"dashboard_id":"`+id+`"}`, tenantAdmin("acme")); w.Code != http.StatusNotFound {
			t.Fatalf("%s accepted as acme's team default: %d, want 404", name, w.Code)
		}
	}
	for _, body := range []string{`{}`, `{"dashboard_id":""}`, `{"reset":true,"dashboard_id":"x"}`} {
		if w := putOverviewDefault(s, "/api/settings/overview-default", body, tenantAdmin("acme")); w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: %d, want 400", body, w.Code)
		}
	}
}

func TestOverviewDefaultFallsBackAndResets(t *testing.T) {
	s := overviewDefaultServer(t)
	d := seedDashboardAs(t, s, acme(), "dashboard")
	const path = "/api/settings/overview-default"
	if w := putOverviewDefault(s, path, `{"dashboard_id":"`+d.ID+`"}`, tenantAdmin("acme")); w.Code != http.StatusOK {
		t.Fatalf("promote: %d", w.Code)
	}

	// A caller without read on dashboards gets the built-in, flagged — never the board.
	if v := getOverviewDefault(t, s, savedAs(RoleIngest)); v.Dashboard != nil || !v.Unavailable {
		t.Fatalf("an ingest key was handed the team dashboard: %+v", v)
	}

	// The dashboard is deleted: every reader falls back to the built-in Overview.
	if err := s.saved.Delete(d.ID); err != nil {
		t.Fatal(err)
	}
	if v := getOverviewDefault(t, s, acme()); v.Dashboard != nil || !v.Unavailable || v.DashboardID != d.ID {
		t.Fatalf("a deleted default must read unavailable, got %+v", v)
	}

	// Reset returns the tenant to the built-in Overview.
	if w := putOverviewDefault(s, path, `{"reset":true}`, tenantAdmin("acme")); w.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}
	if v := getOverviewDefault(t, s, acme()); v.DashboardID != "" || v.Dashboard != nil || v.Unavailable {
		t.Fatalf("after reset the built-in must show, got %+v", v)
	}
}

func TestOverviewDefaultStoreKeyedByTenant(t *testing.T) {
	st := newTenantDisplayStore("")
	if _, err := st.setOverviewDashboard("t-a", "d1"); err != nil {
		t.Fatal(err)
	}
	if got := st.get("t-b").OverviewDashboardID; got != "" {
		t.Fatalf("t-b read t-a's default %q (cross-tenant bleed)", got)
	}
	// Setting the dashboard keeps the tenant's other display preference.
	if _, err := st.setTimeDisplay("t-a", "utc"); err != nil {
		t.Fatal(err)
	}
	if c := st.get("t-a"); c.OverviewDashboardID != "d1" || c.TimeDisplay != "utc" {
		t.Fatalf("one preference overwrote the other: %+v", c)
	}
}
