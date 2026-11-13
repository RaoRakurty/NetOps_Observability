// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Cross-tenant isolation for the link-level flow APIs (tracker 400, §3a.5):
// /api/flows/links and /api/flows/links/series.
//
// The fake ClickHouse records each statement and the tenant_scope it ran at, so
// these tests pin: the STRICTER link ownership rule (own stamped rows, or the
// caller's unambiguous EXPORTER address — never "my device is an endpoint");
// the scope; a no-device tenant never querying; the cross-tenant view grouping
// by tenant; ?as_tenant into another org being ignored; a foreign router's link
// answering exactly like a link with no traffic, with no name or site of a
// device the caller cannot see; and every hostile parameter answering 400
// before anything is queried. The numbers themselves are proven against a real
// ClickHouse in internal/flowquery's integration test.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/models"
)

const acmeLinkClause = "(tenant_id = 'acme' OR sampler_address IN ('10.1.0.1'))"

func TestFlowsLinksScopedUsesTheStricterExporterRule(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[{"tid":"acme","exporter":"10.1.0.1","ifx":7,"if_name":"Gi7","if_name_basis":"resolved","in_b":"10","out_b":"5","prev_in_b":"1","prev_out_b":"1","in_p":"1","out_p":"1","fl":"2"}],"rows":1}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsLinks(w, req(http.MethodGet, "/api/flows/links?since=1h", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(*calls) != 2 {
		t.Fatalf("want the links and the coverage statement, got %d", len(*calls))
	}
	for i, c := range *calls {
		if c.scope != "acme" {
			t.Errorf("statement %d ran at tenant_scope %q, want acme", i, c.scope)
		}
		if !strings.Contains(c.sql, acmeLinkClause) {
			t.Errorf("statement %d lacks the stricter link clause %q:\n%s", i, acmeLinkClause, c.sql)
		}
		// The endpoint branches of the general flow clause must NOT be here:
		// an untagged record in which acme's device is only an endpoint does
		// not put someone else's router on acme's page.
		if strings.Contains(c.sql, "src_addr IN (") || strings.Contains(c.sql, "dst_addr IN (") {
			t.Errorf("statement %d admits endpoint-only records:\n%s", i, c.sql)
		}
		if strings.Contains(c.sql, "globex") || strings.Contains(c.sql, "10.2.0.1") {
			t.Errorf("TENANT LEAK: another tenant reached statement %d:\n%s", i, c.sql)
		}
		if strings.Count(c.sql, "'acme'") != 1 {
			t.Errorf("statement %d: the own-tenant literal must appear exactly once:\n%s", i, c.sql)
		}
	}
	if !strings.Contains((*calls)[0].sql, ifaceJoinKey) {
		t.Errorf("interface names must join on the ROW's tenant:\n%s", (*calls)[0].sql)
	}
	if !strings.Contains((*calls)[1].sql, "sampler_address IN ('10.1.0.1')") {
		t.Errorf("coverage must be bounded to the links' exporters:\n%s", (*calls)[1].sql)
	}
	var body struct {
		Links []map[string]any `json:"links"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Links) != 1 || body.Links[0]["device_name"] != "acme-core" || body.Links[0]["tenant_id"] != nil {
		t.Fatalf("scoped link row = %v (device named, tenant id never echoed)", body.Links)
	}
}

func TestFlowsLinksNoDeviceTenantNeverQueries(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	nobody := jwtClaims{Sub: "n@nobody", Role: RoleOperator, Tenant: "nobody"}
	for _, path := range []string{"/api/flows/links", "/api/flows/links/series?device=10.1.0.1&if=7"} {
		w := httptest.NewRecorder()
		if strings.Contains(path, "series") {
			s.handleFlowsLinkSeries(w, req(http.MethodGet, path, "", nobody))
		} else {
			s.handleFlowsLinks(w, req(http.MethodGet, path, "", nobody))
		}
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, w.Code)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("default-closed: a tenant with no devices ran %d statements", len(*calls))
	}
}

func TestFlowsLinksCrossTenantGroupsByTenant(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[
	  {"tid":"acme","exporter":"10.1.0.1","ifx":7,"in_b":"10","out_b":"0","fl":"1"},
	  {"tid":"globex","exporter":"10.1.0.1","ifx":7,"in_b":"20","out_b":"0","fl":"1"}],"rows":2}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsLinks(w, req(http.MethodGet, "/api/flows/links", "", superA()))
	if w.Code != http.StatusOK || len(*calls) != 2 {
		t.Fatalf("status %d, %d statements", w.Code, len(*calls))
	}
	c := (*calls)[0]
	if c.scope != "__all__" || strings.Contains(c.sql, "IN ('10.") || !strings.Contains(c.sql, "GROUP BY tid, exporter, ifx") {
		t.Errorf("cross-tenant links: scope %q\n%s", c.scope, c.sql)
	}
	var body struct {
		Links []map[string]any `json:"links"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Links) != 2 || body.Links[0]["tenant_id"] == nil || body.Links[0]["tenant_id"] == body.Links[1]["tenant_id"] {
		t.Fatalf("two tenants on one exporter must stay two rows, each naming its tenant: %v", body.Links)
	}
	// acme-core is acme's device: the globex row on the same address must not
	// borrow its name.
	for _, l := range body.Links {
		if l["tenant_id"] == "globex" && l["device_name"] == "acme-core" {
			t.Errorf("TENANT LEAK: globex's link named after acme's router: %v", l)
		}
	}
	// ?tenant narrows a cross-tenant series to one tenant's records.
	*calls = nil
	w = httptest.NewRecorder()
	s.handleFlowsLinkSeries(w, req(http.MethodGet, "/api/flows/links/series?device=10.1.0.1&if=7&tenant=globex", "", superA()))
	if w.Code != http.StatusOK || len(*calls) != 2 || !strings.Contains((*calls)[0].sql, "AND tenant_id = 'globex'") {
		t.Fatalf("cross-tenant ?tenant narrowing: status %d\n%v", w.Code, *calls)
	}
}

// A scoped caller's ?tenant is ignored: it can never point the read elsewhere.
func TestFlowsLinksScopedTenantParamIgnored(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsLinkSeries(w, req(http.MethodGet, "/api/flows/links/series?device=10.1.0.1&if=7&tenant=globex", "", acme()))
	if w.Code != http.StatusOK || len(*calls) != 2 {
		t.Fatalf("status %d, %d statements", w.Code, len(*calls))
	}
	for _, c := range *calls {
		if strings.Contains(c.sql, "globex") || c.scope != "acme" {
			t.Fatalf("TENANT LEAK: a scoped ?tenant reached the read (scope %q):\n%s", c.scope, c.sql)
		}
	}
}

func TestFlowsLinksAsTenantIgnored(t *testing.T) {
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
	st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "user-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": ids["A"],
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	s.discovery.Upsert(models.Device{ID: "a-core", Name: "a-core", Address: "10.1.0.1", TenantID: ids["A"]})
	s.discovery.Upsert(models.Device{ID: "b-core", Name: "b-core", Address: "10.2.0.1", TenantID: ids["B"]})
	tok := login(t, srv, "user-a", "Passw0rd!2345").Token

	for _, path := range []string{
		"/api/flows/links?as_tenant=" + ids["B"],
		"/api/flows/links/series?device=10.2.0.1&if=3&as_tenant=" + ids["B"],
	} {
		*calls = nil
		st, body := do(t, srv, "GET", path, tok, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		if len(*calls) == 0 {
			t.Fatalf("%s: no statement ran", path)
		}
		for _, c := range *calls {
			if c.scope != ids["A"] {
				t.Errorf("%s: as_tenant widened the scope to %q, want org A's %q", path, c.scope, ids["A"])
			}
			// The requested link's own exporter (10.2.0.1) may appear as the
			// link condition; what must never appear is org B's tenant, or org
			// B's address inside the OWNERSHIP clause.
			if strings.Contains(c.sql, ids["B"]) || strings.Contains(c.sql, "OR sampler_address IN ('10.2.0.1')") {
				t.Errorf("%s: TENANT LEAK: org B reached the SQL:\n%s", path, c.sql)
			}
			if !strings.Contains(c.sql, "(tenant_id = '"+ids["A"]+"' OR sampler_address IN ('10.1.0.1'))") {
				t.Errorf("%s: org A's link clause is not the one that ran:\n%s", path, c.sql)
			}
		}
		if strings.Contains(string(body), "b-core") {
			t.Errorf("%s: org B's device named in the answer: %s", path, body)
		}
	}
}

// A link on a router the caller does not own answers exactly like a link that
// does not exist, and no visible-to-someone-else device is named.
func TestFlowsLinkSeriesForeignRouterLooksLikeNoTraffic(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	get := func(dev string) map[string]any {
		w := httptest.NewRecorder()
		s.handleFlowsLinkSeries(w, req(http.MethodGet, "/api/flows/links/series?device="+dev+"&if=3&from=2026-11-13T05:00:00Z&to=2026-11-13T06:00:00Z", "", acme()))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d %s", dev, w.Code, w.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "exporter")
		return m
	}
	foreign, absent := get("10.2.0.1"), get("10.250.0.1")
	fj, _ := json.Marshal(foreign)
	aj, _ := json.Marshal(absent)
	if string(fj) != string(aj) {
		t.Fatalf("a foreign router's link is distinguishable from a missing one:\n%s\n%s", fj, aj)
	}
	if strings.Contains(string(fj), "globex") {
		t.Fatalf("TENANT LEAK in the answer: %s", fj)
	}
	for _, c := range *calls {
		if !strings.Contains(c.sql, acmeLinkClause) || c.scope != "acme" {
			t.Fatalf("the foreign-router read was not bounded by acme's clause (scope %q):\n%s", c.scope, c.sql)
		}
	}
	// Even if a foreign router's row came back, it would not be named: names
	// come from the caller's visible devices only.
	calls2 := fakeCHScoped(t, `{"meta":[],"data":[{"tid":"globex","exporter":"10.2.0.1","ifx":3,"in_b":"10","fl":"1"}],"rows":1}`)
	w := httptest.NewRecorder()
	s.handleFlowsLinks(w, req(http.MethodGet, "/api/flows/links", "", acme()))
	if strings.Contains(w.Body.String(), "globex-core") || len(*calls2) == 0 {
		t.Fatalf("a device acme cannot see was named: %s", w.Body.String())
	}
}

func TestFlowsLinksHostileParametersAre400WithNoQuery(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	for _, path := range []string{
		"/api/flows/links?since=45d",
		"/api/flows/links?since=721h",
		"/api/flows/links?since=1h%3BDROP",
		"/api/flows/links?since=1h&from=2026-11-13T05:00:00Z&to=2026-11-13T06:00:00Z",
		"/api/flows/links?from=2026-11-13T05:00:00Z",
		"/api/flows/links?from=x&to=y",
		"/api/flows/links?limit=0",
		"/api/flows/links?limit=501",
		"/api/flows/links?type=bogus",
		"/api/flows/links?traffic=none",
		"/api/flows/links?device=10.1.0.1')+OR+('1'='1",
		"/api/flows/links?if=abc",
		"/api/flows/links/series",
		"/api/flows/links/series?device=10.1.0.1",
		"/api/flows/links/series?device=10.1.0.1&if=0",
		"/api/flows/links/series?device=10.1.0.1&if=4294967295",
		"/api/flows/links/series?device=10.1.0.1'--&if=3",
		"/api/flows/links/series?device=edge-1&if=3",
		"/api/flows/links/series?device=10.1.0.1&if=3&step=2m",
		"/api/flows/links/series?device=10.1.0.1&if=3&step=60&since=720h",
		"/api/flows/links/series?device=10.1.0.1&if=3&since=1m",
		"/api/flows/links/series?device=10.1.0.1&if=3&type=netflow9",
	} {
		w := httptest.NewRecorder()
		r := req(http.MethodGet, path, "", acme())
		if strings.HasPrefix(path, "/api/flows/links/series") {
			s.handleFlowsLinkSeries(w, r)
		} else {
			s.handleFlowsLinks(w, r)
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", path, w.Code, w.Body.String())
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("a rejected request still queried ClickHouse %d times: %v", len(*calls), *calls)
	}
}

func TestFlowsLinkSeriesZeroFilledBody(t *testing.T) {
	// One bucket returned by ClickHouse; the other eleven are filled with zeros.
	fakeCHScoped(t, `{"meta":[],"data":[{"t":1794546300,"in_b":"500","out_b":"250","in_p":"5","out_p":"2"}],"rows":1}`)
	s := flowsTestServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsLinkSeries(w, req(http.MethodGet, "/api/flows/links/series?device=10.1.0.1&if=7&from=1794546000&to=1794549600&step=5m", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	var b struct {
		Exporter    string    `json:"exporter"`
		IfIndex     int       `json:"ifindex"`
		StepSeconds int       `json:"step_seconds"`
		T           []int64   `json:"t"`
		InBytes     []float64 `json:"in_bytes"`
		OutBytes    []float64 `json:"out_bytes"`
		Window      struct {
			Explicit bool  `json:"explicit"`
			Seconds  int64 `json:"seconds"`
		} `json:"window"`
		Served struct{ From, To string } `json:"served"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Exporter != "10.1.0.1" || b.IfIndex != 7 || b.StepSeconds != 300 || len(b.T) != 12 || !b.Window.Explicit || b.Window.Seconds != 3600 {
		t.Fatalf("series envelope = %+v", b)
	}
	if b.T[0] != 1794546000 || b.InBytes[1] != 500 || b.OutBytes[1] != 250 || b.InBytes[0] != 0 || b.InBytes[11] != 0 {
		t.Fatalf("zero-fill: t=%v in=%v out=%v", b.T, b.InBytes, b.OutBytes)
	}
	if b.Served.From != "2026-11-13T05:00:00Z" || b.Served.To != "2026-11-13T06:00:00Z" {
		t.Fatalf("served = %+v", b.Served)
	}
}
