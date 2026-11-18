// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// flows_legacy_isolation_test.go — CLAUDE.md §3a rule 5 for the older,
// relative-only flow routes (/api/flows/top, topn, timeseries, by-proto,
// by-type, flags, geo, coverage, fanout). Each proxies one ClickHouse statement
// built with flowTenantClause; a hostile fake ClickHouse records every
// statement. Proven per route:
//   - a scoped tenant's data statement names its OWN exporter and never another
//     tenant's device address;
//   - ?as_tenant= into another tenant is ignored for a scoped principal;
//   - a tenant with no devices gets the empty answer with NO statement sent
//     (default-closed, never an unfiltered read).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOlderFlowRoutesCrossTenantIsolation(t *testing.T) {
	var sqls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sqls = append(sqls, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	s := flowsTestServer(t) // acme-core 10.1.0.1, globex-core 10.2.0.1, shared-dns 10.9.0.1

	routes := map[string]http.HandlerFunc{
		"/api/flows/top":        s.handleFlowsTopTalkers,
		"/api/flows/topn":       s.handleFlowsTopN,
		"/api/flows/timeseries": s.handleFlowsTimeseries,
		"/api/flows/by-proto":   s.handleFlowsByProto,
		"/api/flows/by-type":    s.handleFlowsByType,
		"/api/flows/flags":      s.handleFlowsFlags,
		"/api/flows/geo":        s.handleFlowsGeo,
		"/api/flows/coverage":   s.handleFlowsCoverage,
		"/api/flows/fanout":     s.handleFlowsFanout,
	}
	for path, h := range routes {
		for _, q := range []string{"since=1h&by=device", "since=1h&by=device&as_tenant=globex"} {
			sqls = nil
			w := httptest.NewRecorder()
			h(w, req(http.MethodGet, path+"?"+q, "", acme()))
			if w.Code != http.StatusOK || len(sqls) == 0 {
				t.Fatalf("%s?%s as acme: status %d, %d statements", path, q, w.Code, len(sqls))
			}
			data := sqls[len(sqls)-1] // geo/coverage probe a dictionary first
			if !strings.Contains(data, "10.1.0.1") {
				t.Errorf("%s?%s: acme's statement is not scoped to its own exporter:\n%s", path, q, data)
			}
			for _, st := range sqls {
				if strings.Contains(st, "10.2.0.1") || strings.Contains(st, "10.9.0.1") {
					t.Errorf("CROSS-TENANT LEAK: %s?%s as acme names another owner's device:\n%s", path, q, st)
				}
			}
		}
		// A tenant with no devices: empty answer, nothing sent.
		sqls = nil
		w := httptest.NewRecorder()
		h(w, req(http.MethodGet, path+"?since=1h&by=device", "", jwtClaims{Sub: "e@empty", Role: RoleOperator, Tenant: "empty"}))
		if len(sqls) != 0 {
			t.Errorf("%s: a deviceless tenant sent %d statements; want none (default-closed)", path, len(sqls))
		}
	}
}
