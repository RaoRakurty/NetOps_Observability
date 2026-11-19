// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_seasonal_isolation_test.go — CLAUDE.md §3a rule 5 for Iris's seasonal
// baselines (tracker 337 N-H6), driven end to end: the real validator, the
// real planner and the real nlqScope, against a VictoriaMetrics stub that
// APPLIES extra_filters the way the store does while holding BOTH tenants'
// series. Proven:
//   - every read of an above_baseline answer — the current value, every weekly
//     and daily seasonal reference, the flat fallback — carries the caller's
//     own device boundary and never another tenant's device;
//   - the answer names only the caller's device; ?as_tenant= never widens it;
//   - a maintenance window excludes a reference only for a device of its OWN
//     tenant: another tenant's window naming the same device id is ignored,
//     for a workspace user and for a cross-tenant operator alike.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/validate"
	"netops/backend/maintenance"

	nlqast "netops/backend/internal/nlquery/ast"
)

type seasonalVM struct {
	mu      sync.Mutex
	filters [][]string
	queries []string
}

// startSeasonalVM serves device_cpu_percent for dev-a (tenant t-a) and dev-b
// (tenant t-b): 90 % now (a query with no `offset`), 40 % at every earlier
// instant. A series is returned only when the request's extra_filters name its
// device — the store's server-side AND — or when it carries no filter.
func startSeasonalVM(t *testing.T) *seasonalVM {
	t.Helper()
	rec := &seasonalVM{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fs := r.Form["extra_filters[]"]
		q := r.Form.Get("query")
		rec.mu.Lock()
		rec.filters, rec.queries = append(rec.filters, fs), append(rec.queries, q)
		rec.mu.Unlock()
		val := "40"
		if !strings.Contains(q, " offset ") {
			val = "90"
		}
		var parts []string
		for _, d := range []string{"dev-a", "dev-b"} {
			if len(fs) > 0 && !strings.Contains(strings.Join(fs, " "), d) {
				continue
			}
			parts = append(parts, `{"metric":{"device":"`+d+`"},"value":[1794549600,"`+val+`"]}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(parts, ",") + `]}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
	return rec
}

func seasonalServer(t *testing.T) *server {
	t.Helper()
	s, _, _ := nlqFixture(t) // dev-a/edge-a in t-a, dev-b/edge-b in t-b
	s.nlqCatalog = catalog.MustLoad()
	s.maintWindows = maintenance.NewFileStore(filepath.Join(t.TempDir(), "windows.json"))
	now := time.Now()
	add := func(tenant string, back time.Duration) {
		from, to := now.Add(-back-2*time.Hour), now.Add(-back+2*time.Hour)
		if _, err := s.maintWindows.Create(context.Background(), tenant, false, maintenance.Window{
			TenantID: tenant, Name: "planned work " + tenant, DeviceIDs: []string{"dev-a"},
			StartsAt: &from, EndsAt: &to, Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("t-a", 14*24*time.Hour) // dev-a's own tenant: excludes week 2
	add("t-b", 21*24*time.Hour) // ANOTHER tenant naming dev-a: must be ignored
	return s
}

func seasonalAsk(t *testing.T, s *server, r *http.Request, claims jwtClaims, js string) *plan.ResultSet {
	t.Helper()
	a, err := nlqast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	h := s.nlqScopeFor(r, claims)
	v, res := validate.Validate(context.Background(), s.nlqCatalog, h, a)
	if !res.Valid {
		t.Fatalf("query invalid: %+v", res.Errors)
	}
	rs, err := plan.Planner{Cat: s.nlqCatalog}.Execute(context.Background(), h, v, res.Constraints)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

const seasonalAboveCPU = `{"v":1,"query_type":"metric_filter","target":"device","metric":"cpu_util_pct","predicate":{"op":"above_baseline"},"time_range":{"kind":"relative","last":"1h"}}`

func TestSeasonalBaselineReadsAreTheCallersOwn(t *testing.T) {
	s := seasonalServer(t)
	vm := startSeasonalVM(t)
	a := jwtClaims{Sub: "ua", Tenant: "t-a", Role: "operator"}
	rs := seasonalAsk(t, s, req(http.MethodGet, "/api/ai/ask", "", a), a, seasonalAboveCPU)

	if len(vm.filters) < 1+4+6 { // current + 4 weeks + 7 days (one shared)
		t.Fatalf("expected the current read and every seasonal reference, saw %d reads", len(vm.filters))
	}
	for i, fs := range vm.filters {
		joined := strings.Join(fs, " ")
		if len(fs) == 0 || !strings.Contains(joined, "dev-a") || strings.Contains(joined, "dev-b") || strings.Contains(joined, "edge-b") {
			t.Fatalf("read %d (%s) used filters %v — every seasonal read must carry only tenant A's boundary", i, vm.queries[i], fs)
		}
	}
	if len(rs.Rows) != 1 || rs.Rows[0]["device"] != "dev-a" {
		t.Fatalf("CROSS-TENANT LEAK or wrong verdict: rows %+v", rs.Rows)
	}
	b, _ := rs.Rows[0]["baseline"].(string)
	if !strings.Contains(b, "this time of week (3 of 4 weeks used, 1 left out for maintenance)") {
		t.Fatalf("baseline = %q — only dev-a's OWN tenant's window may exclude a week", b)
	}

	// as_tenant never widens a workspace user.
	vm.filters, vm.queries = nil, nil
	r := req(http.MethodGet, "/api/ai/ask?as_tenant=t-b", "", a)
	r.Header.Set("X-Acting-Tenant", "t-b")
	rs = seasonalAsk(t, s, r, a, seasonalAboveCPU)
	for i, fs := range vm.filters {
		if strings.Contains(strings.Join(fs, " "), "dev-b") {
			t.Fatalf("as_tenant widened read %d: %v", i, fs)
		}
	}
	if len(rs.Rows) != 1 || rs.Rows[0]["device"] != "dev-a" {
		t.Fatalf("as_tenant reached another tenant: %+v", rs.Rows)
	}
}

// A cross-tenant operator sees both devices; still, t-b's window naming dev-a
// does not excuse dev-a, and dev-b (no window of its own) keeps all 4 weeks.
func TestSeasonalMaintenanceIsPerDeviceTenantForAnOperator(t *testing.T) {
	s := seasonalServer(t)
	startSeasonalVM(t)
	op := jwtClaims{Sub: "root", Role: RoleSuperAdmin}
	rs := seasonalAsk(t, s, req(http.MethodGet, "/api/ai/ask", "", op), op, seasonalAboveCPU)
	got := map[string]string{}
	for _, row := range rs.Rows {
		b, _ := row["baseline"].(string)
		got[row["device"].(string)] = b
	}
	if !strings.Contains(got["dev-a"], "3 of 4 weeks used, 1 left out for maintenance") {
		t.Fatalf("dev-a baseline = %q", got["dev-a"])
	}
	if !strings.Contains(got["dev-b"], "4 of 4 weeks used)") {
		t.Fatalf("dev-b baseline = %q — another tenant's window must not touch it", got["dev-b"])
	}
}
