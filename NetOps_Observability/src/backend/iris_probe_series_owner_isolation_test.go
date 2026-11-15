// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Probe series owner (tracker 337 N-B5, §3a.5).
//
// The platform's STAMP probe series (probe_*) have env-configured targets and
// no tenant owner, so a workspace user cannot read them. A workspace's OWN
// Digital Experience checks are stamped by the prober with that workspace's
// `tenant` label (dem_probe_*). A workspace user asking for probe loss/latency
// on one of its own checks now reads those series — through the tenant-LABEL
// filter, never the device filter — and nothing else.
//
// Driven end to end: the real validator (CheckScope swap + Visible), the real
// planner and the real nlqScope, against a VictoriaMetrics stub that APPLIES
// extra_filters the way the store does, while holding both tenants' series.
// Two workspaces declare a check with the SAME name and host.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"netops/backend/internal/dem"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/mql"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/validate"
)

type probeOwnerVM struct {
	filters [][]string
	queries []string
}

// probeOwnerStub serves dem_probe_* series for tenants t-a and t-b and honours
// a `{tenant="X"}` / `{tenant!~"X"}` extra filter, as VictoriaMetrics does.
func probeOwnerStub(t *testing.T, ids map[string]string) *probeOwnerVM {
	t.Helper()
	rec := &probeOwnerVM{}
	eq := regexp.MustCompile(`^\{tenant="([^"]*)"\}$`)
	ne := regexp.MustCompile(`^\{tenant!~"([^"]*)"\}$`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fs := r.Form["extra_filters[]"]
		rec.filters = append(rec.filters, fs)
		rec.queries = append(rec.queries, r.Form.Get("query"))
		keep := func(tenant string) bool {
			for _, f := range fs {
				if m := eq.FindStringSubmatch(f); m != nil && m[1] != tenant {
					return false
				}
				if m := ne.FindStringSubmatch(f); m != nil && regexp.MustCompile("^(?:"+m[1]+")$").MatchString(tenant) {
					return false
				}
			}
			return true
		}
		var parts []string
		for tenant, id := range ids {
			if !keep(tenant) {
				continue
			}
			lbl, _ := json.Marshal(map[string]string{"__name__": "dem_probe_loss_pct", "tenant": tenant, "target": id})
			if strings.HasSuffix(r.URL.Path, "query_range") {
				parts = append(parts, `{"metric":`+string(lbl)+`,"values":[[1794549600,"2"]]}`)
			} else {
				parts = append(parts, `{"metric":`+string(lbl)+`,"value":[1794549600,"2"]}`)
			}
		}
		kind := "vector"
		if strings.HasSuffix(r.URL.Path, "query_range") {
			kind = "matrix"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"` + kind + `","result":[` + strings.Join(parts, ",") + `]}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
	return rec
}

func probeOwnerServer(t *testing.T) (*server, map[string]string) {
	t.Helper()
	_, st := newTestServerState(t)
	st.nlqCatalog = catalog.MustLoad()
	st.demTargets = dem.NewFileStore(filepath.Join(t.TempDir(), "dem_targets.json"))
	ids := map[string]string{}
	for _, tenant := range []string{"t-a", "t-b"} {
		tg, err := st.demTargets.Create(context.Background(), dem.Target{
			TenantID: tenant, Name: "ERP check", Kind: "icmp", Host: "erp.example.com", IntervalSec: 60,
		})
		if err != nil {
			t.Fatalf("create %s check: %v", tenant, err)
		}
		ids[tenant] = tg.ID
	}
	return st, ids
}

func probeAsk(t *testing.T, s *server, claims jwtClaims, js string) (*plan.ResultSet, validate.Result) {
	t.Helper()
	a, err := nlqast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", claims), claims)
	v, res := validate.Validate(context.Background(), s.nlqCatalog, h, a)
	if !res.Valid {
		return nil, res
	}
	rs, err := plan.Planner{Cat: s.nlqCatalog}.Execute(context.Background(), h, v, res.Constraints)
	if err != nil {
		t.Fatal(err)
	}
	return rs, res
}

const probeLossOnERP = `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"probe_loss_pct","aggregation":"avg",` +
	`"entities":[{"type":"probe_target","id":"probe:erp.example.com"}],"time_range":{"kind":"relative","last":"1h"}}`

func TestProbeSeriesReachOnlyTheWorkspaceThatDeclaredTheCheck(t *testing.T) {
	s, ids := probeOwnerServer(t)
	vm := probeOwnerStub(t, ids)
	a := jwtClaims{Sub: "a@t-a", Role: RoleOperator, Tenant: "t-a"}

	rs, res := probeAsk(t, s, a, probeLossOnERP)
	if rs == nil {
		t.Fatalf("a workspace asking about its own check must be answered: %+v", res.Errors)
	}
	if len(vm.filters) == 0 {
		t.Fatal("no metrics read happened")
	}
	for i, fs := range vm.filters {
		if len(fs) != 1 || fs[0] != `{tenant="t-a"}` {
			t.Fatalf("read %d used filters %v — want exactly the caller's tenant label", i, fs)
		}
		if strings.Contains(vm.queries[i], ids["t-b"]) {
			t.Fatalf("TENANT LEAK: another workspace's check id reached the query: %s", vm.queries[i])
		}
		if !strings.Contains(vm.queries[i], ids["t-a"]) {
			t.Fatalf("the read was not narrowed to the caller's own check: %s", vm.queries[i])
		}
	}
	if len(rs.Series) != 1 || rs.Series[0].Entity["probe_target"] != "ERP check" {
		t.Fatalf("want exactly the caller's own check, named; got %+v", rs.Series)
	}
	if rs.Metric != "dem_probe_loss_pct" {
		t.Fatalf("answer metric %q, want the workspace equivalent", rs.Metric)
	}
}

// A ?as_tenant= walk or an acting-tenant header never widens a workspace user
// into another workspace's checks: the scope reads the claims, not the request.
func TestProbeSeriesIgnoreAsTenantForAWorkspaceUser(t *testing.T) {
	s, ids := probeOwnerServer(t)
	vm := probeOwnerStub(t, ids)
	a := jwtClaims{Sub: "a@t-a", Role: RoleOperator, Tenant: "t-a"}
	r := req(http.MethodGet, "/api/ai/ask?as_tenant=t-b", "", a)
	r.Header.Set("X-Acting-Tenant", "t-b")
	h := s.nlqScopeFor(r, a)
	if _, _, err := h.TenantMetricInstant(context.Background(), mustSelector(t, "dem_probe_loss_pct"), nlqWin.to, 10); err != nil {
		t.Fatal(err)
	}
	if got := vm.filters[len(vm.filters)-1]; len(got) != 1 || got[0] != `{tenant="t-a"}` {
		t.Fatalf("as_tenant widened the read: filters %v", got)
	}
	checks, err := h.ProbeTargets(context.Background(), nil)
	if err != nil || len(checks) != 1 || checks[0].ID != ids["t-a"] {
		t.Fatalf("own checks = %+v %v, want only t-a's", checks, err)
	}
}

// A workspace naming a destination it does not check itself (the platform's
// 8.8.8.8, or a host only another workspace checks) stays unavailable — never
// answered from someone else's series, never an empty "no loss".
func TestProbeSeriesForANonOwnedTargetStayUnavailable(t *testing.T) {
	s, ids := probeOwnerServer(t)
	if _, err := s.demTargets.Create(context.Background(), dem.Target{
		TenantID: "t-b", Name: "B only", Kind: "icmp", Host: "b-only.example.com", IntervalSec: 60,
	}); err != nil {
		t.Fatal(err)
	}
	vm := probeOwnerStub(t, ids)
	a := jwtClaims{Sub: "a@t-a", Role: RoleOperator, Tenant: "t-a"}
	for _, host := range []string{"8.8.8.8", "b-only.example.com"} {
		js := strings.Replace(probeLossOnERP, "erp.example.com", host, 1)
		rs, res := probeAsk(t, s, a, js)
		if rs != nil {
			t.Fatalf("%s: answered %+v, want refusal", host, rs)
		}
		codes := []string{}
		for _, e := range res.Errors {
			codes = append(codes, e.Code)
		}
		if !strings.Contains(strings.Join(codes, ","), validate.CodeScopeUnavailable) {
			t.Fatalf("%s: want %s, got %v", host, validate.CodeScopeUnavailable, codes)
		}
	}
	if len(vm.filters) != 0 {
		t.Fatalf("a refused question still read metrics: %v", vm.queries)
	}
}

// The Global view keeps the platform probe metric (device-filter path, no
// swap) and owns no workspace check of its own here.
func TestProbeSeriesGlobalViewKeepsThePlatformMetric(t *testing.T) {
	s, _ := probeOwnerServer(t)
	owner := platformOwner()
	a, err := nlqast.Decode([]byte(probeLossOnERP))
	if err != nil {
		t.Fatal(err)
	}
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", owner), owner)
	v, res := validate.Validate(context.Background(), s.nlqCatalog, h, a)
	if !res.Valid || v.Metric != "probe_loss_pct" {
		t.Fatalf("global view: valid=%v metric=%v %+v", res.Valid, v, res.Errors)
	}
	if checks, err := h.ProbeTargets(context.Background(), nil); err != nil || len(checks) != 0 {
		t.Fatalf("the Global view owns no workspace check: %+v %v", checks, err)
	}
}

func mustSelector(t *testing.T, metric string) mql.Expr {
	t.Helper()
	e, err := mql.Selector(metric)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
