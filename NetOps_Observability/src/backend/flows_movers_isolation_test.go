// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// "What changed" on one link — GET /api/flows/links/movers (tracker 400 (c)) —
// and the link filter on /api/flows/apps and /api/flows/services (tracker 400
// (e)), §3a.5: the stricter link clause and the caller's scope on every
// statement, no query for a tenant with no devices, ?as_tenant ignored, hostile
// parameters answered 400 before any query, and the step-change numbers exact.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/servicecat"
	"netops/backend/models"
)

// The services scan renders the exact window and carries the link filter and
// the tenant clause; the handler itself needs the Postgres catalog store, so
// the end-to-end isolation of /api/flows/services stays in the pgintegration
// corpus (svc_catalog_isolation_pg_test.go).
func TestServicesScanTakesTheWindowAndTheLinkFilter(t *testing.T) {
	sel := []string{"sumIf(bytes, dst_port = 443) AS b0"}
	sql := servicecat.FlowScanWindowSQL(sel, "ts >= toDateTime64(1794546000, 3, 'UTC') AND ts < toDateTime64(1794549600, 3, 'UTC')",
		" AND (tenant_id = 'acme' OR src_addr IN ('10.1.0.1')) AND sampler_address = '10.1.0.1' AND (in_if = 7 OR out_if = 7)")
	want := "SELECT sumIf(bytes, dst_port = 443) AS b0 FROM netops.flows WHERE ts >= toDateTime64(1794546000, 3, 'UTC') AND ts < toDateTime64(1794549600, 3, 'UTC')" +
		" AND (tenant_id = 'acme' OR src_addr IN ('10.1.0.1')) AND sampler_address = '10.1.0.1' AND (in_if = 7 OR out_if = 7) FORMAT JSON"
	if sql != want {
		t.Fatalf("services scan:\n got %s\nwant %s", sql, want)
	}
	if got := servicecat.FlowScanSQL(sel, 3600, ""); !strings.Contains(got, "ts >= now() - INTERVAL 3600 SECOND FORMAT JSON") {
		t.Fatalf("FlowScanSQL keeps its shape: %s", got)
	}
}

func TestFlowsLinkMoversScopedClauseAndExactStepChange(t *testing.T) {
	// The fake answers every statement with the same body: the totals row reads
	// cur_b/prev_b, the movers rows read k/cur_b/prev_b.
	calls := fakeCHScoped(t, `{"meta":[],"data":[
	  {"k":"198.51.100.1","cur_b":"400","prev_b":"100","fl":"10","fl_rr":"0"},
	  {"k":"198.51.100.2","cur_b":"0","prev_b":"250","fl":"0","fl_rr":"0"}],"rows":2}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsLinkMovers(w, req(http.MethodGet, "/api/flows/links/movers?device=10.1.0.1&if=7&dir=in&by=talker&since=1h", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(*calls) != 2 {
		t.Fatalf("want the totals and the movers statement, got %d", len(*calls))
	}
	for i, c := range *calls {
		if c.scope != "acme" || !strings.Contains(c.sql, acmeLinkClause) {
			t.Errorf("statement %d: scope %q, link clause missing:\n%s", i, c.scope, c.sql)
		}
		if !strings.Contains(c.sql, "sampler_address = '10.1.0.1' AND in_if = 7") {
			t.Errorf("statement %d is not bounded to the link and direction:\n%s", i, c.sql)
		}
		if strings.Contains(c.sql, "globex") || strings.Contains(c.sql, "src_addr IN (") {
			t.Errorf("statement %d: TENANT LEAK or endpoint-only clause:\n%s", i, c.sql)
		}
	}
	var body struct {
		By     string `json:"by"`
		Dir    string `json:"dir"`
		Totals struct {
			Bytes     float64  `json:"bytes"`
			PrevBytes *float64 `json:"prev_bytes"`
		} `json:"totals"`
		Movers []struct {
			Key       string   `json:"key"`
			Bytes     float64  `json:"bytes"`
			PrevBytes *float64 `json:"prev_bytes"`
			Change    *float64 `json:"change"`
			Status    string   `json:"status"`
		} `json:"movers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.By != "talker" || body.Dir != "in" || body.Totals.Bytes != 400 || body.Totals.PrevBytes == nil || *body.Totals.PrevBytes != 100 {
		t.Fatalf("envelope = %+v", body)
	}
	if len(body.Movers) != 2 || body.Movers[0].Key != "198.51.100.1" || body.Movers[0].Status != "up" || *body.Movers[0].Change != 3 ||
		body.Movers[1].Status != "gone" || *body.Movers[1].PrevBytes != 250 {
		t.Fatalf("movers = %+v", body.Movers)
	}
}

func TestFlowsLinkMoversPortsAreNamedAndAppsResolved(t *testing.T) {
	fakeCHScoped(t, `{"meta":[],"data":[{"k":"6/443","cur_b":"10","prev_b":"0"}],"rows":1}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsLinkMovers(w, req(http.MethodGet, "/api/flows/links/movers?device=10.1.0.1&if=7&by=port", "", acme()))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"label":"https"`) || !strings.Contains(w.Body.String(), `"status":"new"`) {
		t.Fatalf("port movers: %d %s", w.Code, w.Body.String())
	}
	calls := fakeCHScoped(t, `{"meta":[],"data":[{"d":"198.51.100.9","s":"10.1.0.5","xi":"","xn":"","cur_b":"900","prev_b":"300"}],"rows":1}`)
	s = flowsAppsTestServer(t)
	w = httptest.NewRecorder()
	s.handleFlowsLinkMovers(w, req(http.MethodGet, "/api/flows/links/movers?device=10.1.0.1&if=7&by=app", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("app movers: %d %s", w.Code, w.Body.String())
	}
	if len(*calls) != 2 || !strings.Contains((*calls)[1].sql, "GROUP BY d, s, xi, xn") {
		t.Fatalf("app movers statements: %v", *calls)
	}
	var body struct {
		Movers []struct {
			Key       string  `json:"key"`
			Bytes     float64 `json:"bytes"`
			PrevBytes float64 `json:"prev_bytes"`
		} `json:"movers"`
		Coverage map[string]any `json:"coverage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Movers) != 1 || body.Movers[0].Bytes != 900 || body.Movers[0].PrevBytes != 300 || body.Coverage["top_pairs"] != float64(1000) {
		t.Fatalf("app movers body = %s", w.Body.String())
	}
}

func TestFlowsLinkMoversNoDeviceNeverQueriesAndHostileIs400(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	nobody := jwtClaims{Sub: "n@nobody", Role: RoleOperator, Tenant: "nobody"}
	w := httptest.NewRecorder()
	s.handleFlowsLinkMovers(w, req(http.MethodGet, "/api/flows/links/movers?device=10.1.0.1&if=7", "", nobody))
	if w.Code != http.StatusOK || len(*calls) != 0 {
		t.Fatalf("default-closed: status %d, %d statements", w.Code, len(*calls))
	}
	for _, path := range []string{
		"/api/flows/links/movers",
		"/api/flows/links/movers?device=10.1.0.1",
		"/api/flows/links/movers?device=10.1.0.1&if=7&by=host",
		"/api/flows/links/movers?device=10.1.0.1&if=7&dir=sideways",
		"/api/flows/links/movers?device=10.1.0.1&if=7&limit=51",
		"/api/flows/links/movers?device=10.1.0.1&if=7&since=31d",
		"/api/flows/links/movers?device=10.1.0.1&if=7&traffic=some",
		"/api/flows/links/movers?device=10.1.0.1'--&if=7",
	} {
		w := httptest.NewRecorder()
		s.handleFlowsLinkMovers(w, req(http.MethodGet, path, "", acme()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", path, w.Code)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("a rejected request queried ClickHouse %d times", len(*calls))
	}
}

func TestFlowsLinkMoversAsTenantIgnored(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	ids := map[string]string{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": idOf(t, b)})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		ids[name] = idOf(t, b)
	}
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "user-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": ids["A"],
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	s.discovery.Upsert(models.Device{ID: "a-core", Name: "a-core", Address: "10.1.0.1", TenantID: ids["A"]})
	s.discovery.Upsert(models.Device{ID: "b-core", Name: "b-core", Address: "10.2.0.1", TenantID: ids["B"]})
	// newServer builds these; the test server state does not.
	s.appCatalog = newAppCatalogHolder()
	s.ngfw = newNgfwAppResolver()
	tok := login(t, srv, "user-a", "Passw0rd!2345").Token
	for _, path := range []string{
		"/api/flows/links/movers?device=10.2.0.1&if=3&as_tenant=" + ids["B"],
		"/api/flows/apps?device=10.2.0.1&if=3&as_tenant=" + ids["B"],
	} {
		*calls = nil
		st, body := do(t, srv, "GET", path, tok, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		for _, c := range *calls {
			if c.scope != ids["A"] || strings.Contains(c.sql, ids["B"]) || strings.Contains(c.sql, "OR sampler_address IN ('10.2.0.1')") || strings.Contains(c.sql, "src_addr IN ('10.2.0.1')") {
				t.Errorf("%s: as_tenant widened the read (scope %q):\n%s", path, c.scope, c.sql)
			}
		}
	}
}

// Tracker 400 (e): the link (device + interface) narrows applications and
// services; services adopts the platform-traffic exclusion (owner decision
// 2026-11-13 (c)); both take an exact window and reject a bad one.
func TestFlowsAppsAndServicesHonourTheLinkAndWindow(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	t.Setenv("CX_PLATFORM_ADDRESSES", "10.70.0.5")
	s := flowsAppsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsApps(w, req(http.MethodGet, "/api/flows/apps?device=10.1.0.1&if=7&from=1794546000&to=1794549600", "", acme()))
	if w.Code != http.StatusOK || len(*calls) != 1 {
		t.Fatalf("apps: %d, %d statements (%s)", w.Code, len(*calls), w.Body.String())
	}
	sql := (*calls)[0].sql
	for _, want := range []string{
		"ts >= toDateTime64(1794546000, 3, 'UTC') AND ts < toDateTime64(1794549600, 3, 'UTC')",
		"sampler_address = '10.1.0.1'",
		"(in_if = 7 OR out_if = 7)",
		"AND NOT ",
		"10.70.0.5",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("apps SQL missing %q:\n%s", want, sql)
		}
	}
	if !strings.Contains(w.Body.String(), `"explicit":true`) {
		t.Errorf("apps must echo the window: %s", w.Body.String())
	}
	*calls = nil
	w = httptest.NewRecorder()
	s.handleFlowsApps(w, req(http.MethodGet, "/api/flows/apps?device=10.1.0.1&if=7&traffic=all", "", acme()))
	if w.Code != http.StatusOK || strings.Contains((*calls)[0].sql, "10.70.0.5") {
		t.Errorf("traffic=all must lift the platform exclusion:\n%s", (*calls)[0].sql)
	}
	for _, path := range []string{"/api/flows/apps?since=45d", "/api/flows/apps?type=x", "/api/flows/apps?device=bad'", "/api/flows/apps?from=1"} {
		*calls = nil
		w := httptest.NewRecorder()
		s.handleFlowsApps(w, req(http.MethodGet, path, "", acme()))
		if w.Code != http.StatusBadRequest || len(*calls) != 0 {
			t.Errorf("%s: status %d, %d statements; want 400 and none", path, w.Code, len(*calls))
		}
	}
}
