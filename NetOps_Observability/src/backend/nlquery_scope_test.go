// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_scope_test.go — the root side of the Iris NL query path (tracker 337
// N-C4). nlqScope is the only implementation of the planner's Scope, and it
// must route every read through the chokepoint the UI's own pages use.
//
// Pinned: (1) structurally, each read method calls its scoping primitive;
// (2) behaviourally, every VictoriaMetrics request carries extra_filters and a
// scoped tenant's filter names only its own devices; (3) §3a, across two
// tenants: device/site resolution, visibility and cost never cross the
// boundary — not even for another tenant's device labelled with the SAME site.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/mql"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/validate"
	"netops/backend/models"
)

// Compile-time: nlqScope satisfies both interfaces.
var (
	_ plan.Scope     = (*nlqScope)(nil)
	_ validate.Scope = (*nlqScope)(nil)
)

func TestNLQScopeMethodsCallTheirChokepoints(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "ai_troubleshoot_deps.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	src := map[string]string{}
	raw := packageGoSources(t)["ai_troubleshoot_deps.go"]
	full := strings.Join(raw, "\n")
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
			if id, ok := star.X.(*ast.Ident); ok && id.Name == "nlqScope" {
				src[fn.Name.Name] = fn.Name.Name
			}
		}
	}
	want := map[string][]string{
		"MetricRange":   {"h.s.metricsScopeFiltersFor(h.claims)"},
		"MetricInstant": {"h.s.metricsScopeFiltersFor(h.claims)"},
		"Incidents":     {"h.s.chTenantScopeFor(h.claims)", "h.s.tenantIDExcludeCondFor(h.claims"},
		"Incident":      {"h.s.chTenantScopeFor(h.claims)", "h.s.tenantIDExcludeCondFor(h.claims"},
		"Changes":       {"principalTenant(h.claims)"},
		"Circuits":      {"h.s.deviceVisibilityFor(h.claims)"},
	}
	for method, needles := range want {
		if src[method] == "" {
			t.Errorf("nlqScope.%s is missing", method)
			continue
		}
		body := methodBody(full, "func (h *nlqScope) "+method+"(")
		for _, n := range needles {
			if !strings.Contains(body, n) {
				t.Errorf("nlqScope.%s no longer calls %s — its read is not scoped", method, n)
			}
		}
	}
	if b := methodBody(full, "func (h *nlqScope) visibleDevices("); !strings.Contains(b, "h.s.visibleDevicesFor(h.claims)") {
		t.Error("device resolution must come from the caller's visible devices")
	}
}

func methodBody(src, sig string) string {
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	j := strings.Index(src[i+1:], "\nfunc ")
	if j < 0 {
		return src[i:]
	}
	return src[i : i+1+j]
}

// nlqFixture: tenant A owns edge-a (site dfw-hq); tenant B owns edge-b, whose
// inventory label ALSO says site dfw-hq.
func nlqFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	_, s := newTestServerState(t)
	for _, d := range []models.Device{
		{ID: "dev-a", Name: "edge-a", TenantID: "t-a", Labels: map[string]string{"site": "dfw-hq"}},
		{ID: "dev-b", Name: "edge-b", TenantID: "t-b", Labels: map[string]string{"site": "dfw-hq"}},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatal(err)
		}
	}
	return s, jwtClaims{Sub: "ua", Tenant: "t-a", Role: "operator"}, jwtClaims{Sub: "ub", Tenant: "t-b", Role: "operator"}
}

func TestNLQScopeDevicesNeverCrossTenants(t *testing.T) {
	s, a, _ := nlqFixture(t)
	h := s.nlqScopeFor(newAITestRequest(t, a), a)
	ctx := context.Background()
	devs, err := h.Devices(ctx, plan.DeviceFilter{Sites: []string{"dfw-hq"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].ID != "dev-a" {
		t.Fatalf("site expansion for tenant A = %+v — another tenant's device with the same site label must never appear", devs)
	}
	if devs, _ := h.Devices(ctx, plan.DeviceFilter{IDs: []string{"dev-b"}}); len(devs) != 0 {
		t.Fatalf("an explicit foreign device id resolved: %+v", devs)
	}
	for id, want := range map[string]bool{"device:dev-a": true, "device:dev-b": false, "device:no-such": false, "interface:dev-b/Gi0/0": false} {
		typ := strings.SplitN(id, ":", 2)[0]
		if got, err := h.Visible(ctx, nlqast.EntityRef{Type: typ, ID: id}); err != nil || got != want {
			t.Errorf("Visible(%s) = %v, %v — want %v", id, got, err, want)
		}
	}
	if n, _ := h.Count(ctx, "device", []nlqast.EntityRef{{Type: "site", ID: "site:dfw-hq"}}); n != 1 {
		t.Fatalf("cost estimate counted %d devices — foreign devices must not count", n)
	}
	if h.CrossTenant() {
		t.Fatal("a tenant operator is not cross-tenant")
	}
}

// Behaviour: every VictoriaMetrics request the NL path makes carries the
// caller's extra_filters, and a scoped tenant's filter names only its own
// devices.
func TestNLQScopeEveryMetricReadCarriesTheTenantFilter(t *testing.T) {
	var mu sync.Mutex
	var seen [][]string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Query()["extra_filters[]"])
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "query_range") {
			_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"edge-a","tenant":"t-a"},"values":[[1,"1"],[2,"NaN"]]}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"edge-a"},"value":[1,"2"]}]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, _ := nlqFixture(t)
	h := s.nlqScopeFor(newAITestRequest(t, a), a)
	e, _ := mql.Selector("device_cpu_percent")
	now := time.Now()
	series, _, err := h.MetricRange(context.Background(), e, now.Add(-time.Hour), now, time.Minute, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || series[0].Points[1].V != 0 {
		t.Fatalf("NaN must decode to 0, series = %+v", series)
	}
	if _, _, err := h.MetricInstant(context.Background(), e, now, 50); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("want 2 VM requests, got %d", len(seen))
	}
	for i, f := range seen {
		joined := strings.Join(f, " ")
		if len(f) == 0 || !strings.Contains(joined, "dev-a") || strings.Contains(joined, "dev-b") || strings.Contains(joined, "edge-b") {
			t.Fatalf("request %d extra_filters = %v — must be present and name only tenant A's devices", i, f)
		}
	}
}

func TestNLQScopeIncidentRejectsMalformedIDsBeforeAnyRead(t *testing.T) {
	s, a, _ := nlqFixture(t)
	h := s.nlqScopeFor(newAITestRequest(t, a), a)
	if _, err := h.Incident(context.Background(), "x' OR 1=1 --"); !errors.Is(err, plan.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestChangeMatchesAppliesEveryFilter(t *testing.T) {
	now := time.Now()
	row := plan.ChangeRow{ID: "c1", Type: "NETWORK_CHANGE", Actor: "John Smith", Site: "dfw-hq", Source: "ledger", At: now.Add(-time.Hour)}
	base := plan.ChangeQuery{From: now.Add(-2 * time.Hour), To: now}
	if !changeMatches(row, base) {
		t.Fatal("an in-window row with no filters must match")
	}
	for name, q := range map[string]plan.ChangeQuery{
		"before window": {From: now.Add(-30 * time.Minute), To: now},
		"after window":  {From: now.Add(-3 * time.Hour), To: now.Add(-2 * time.Hour)},
		"actor":         {From: base.From, To: now, Actors: []string{"Jane"}},
		"type":          {From: base.From, To: now, Types: []string{"DNS_CHANGE"}},
		"site":          {From: base.From, To: now, Sites: []string{"aus"}},
		"excluded":      {From: base.From, To: now, ExcludeIDs: []string{"c1"}},
	} {
		if changeMatches(row, q) {
			t.Errorf("%s: row must be filtered out", name)
		}
	}
}

// incidentRowFrom reads the ISO start the adapter selects (chschema.ISO), and
// an unreadable start is an ERROR — never a zero time that would anchor every
// incident window at 1970.
func TestIncidentRowFromParsesTheSelectedStart(t *testing.T) {
	row, err := incidentRowFrom(map[string]any{"correlation_id": "c-1", "start_iso": "2026-09-21T10:17:00.000Z",
		"affected": `{"sites":["dfw-hq"],"devices":["edge-1"]}`, "top_confidence": 0.9})
	if err != nil || row.CreatedAt.IsZero() || row.CreatedAt.Hour() != 10 || row.Sites[0] != "dfw-hq" {
		t.Fatalf("row = %+v err = %v", row, err)
	}
	if _, err := incidentRowFrom(map[string]any{"correlation_id": "c-2", "start_iso": "2026-09-21 10:17:00.000"}); err == nil {
		t.Fatal("a non-ISO start must be an error, not a zero time")
	}
	if !strings.Contains(nlqIncidentCols, `AS start_iso`) || strings.Contains(nlqIncidentCols, "AS window_start") {
		t.Fatal("window_start must be selected through chschema.ISO under a NON-shadowing alias")
	}
}

// The incident SQL (verified against ClickHouse 24.8 with the production
// init.sql and custom settings on 2026-09-26: row-policy isolation held for
// two tenants on the same site; chaos fixtures and other sites excluded;
// backslash values stayed inside their literals). This pins its shape.
func TestNLQIncidentsSQLShape(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	sql, limit, err := nlqIncidentsSQL(plan.IncidentQuery{From: now.Add(-time.Hour), To: now, States: []string{"open"},
		Owners: []string{"NOC"}, Sites: []string{`dfw\`}, Limit: 500, NewestFirst: true}, "tenant_id NOT IN ('t-z')")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FROM netops.corr_current FINAL", "chaos_fixture = ''", "debug_excluded = 0",
		"tenant_id NOT IN ('t-z')", "state IN ('open')", "lower(owner) IN ('noc')", "created_at >= now() - INTERVAL 24 HOUR",
		`['dfw\\']`, "AS start_iso", "ORDER BY window_start DESC", "LIMIT 201"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL missing %q:\n%s", want, sql)
		}
	}
	if limit != 200 || strings.Contains(sql, "tenant_scope") {
		t.Fatalf("limit=%d — and tenant scope must be the SETTING, not SQL text", limit)
	}
}

// DeviceFilter fields NARROW each other (plan.DeviceFilter): "edge-a in
// Austin" is nothing when edge-a is in Dallas — the old union answered with
// every Austin device (and here, every device of the named site).
func TestNLQScopeDeviceFilterNarrowsAcrossFields(t *testing.T) {
	s, a, _ := nlqFixture(t)
	if err := s.discovery.Upsert(models.Device{ID: "dev-a2", Name: "edge-a2", TenantID: "t-a", Labels: map[string]string{"site": "aus-br"}}); err != nil {
		t.Fatal(err)
	}
	h := s.nlqScopeFor(newAITestRequest(t, a), a)
	ctx := context.Background()
	ids := func(f plan.DeviceFilter) string {
		devs, err := h.Devices(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range devs {
			out = append(out, d.ID)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	for name, tc := range map[string]struct {
		f    plan.DeviceFilter
		want string
	}{
		"device in its site":      {plan.DeviceFilter{IDs: []string{"dev-a"}, Sites: []string{"dfw-hq"}}, "dev-a"},
		"device not in that site": {plan.DeviceFilter{IDs: []string{"dev-a"}, Sites: []string{"aus-br"}}, ""},
		"a list of devices":       {plan.DeviceFilter{IDs: []string{"dev-a", "dev-a2"}}, "dev-a,dev-a2"},
		"a list of sites":         {plan.DeviceFilter{Sites: []string{"dfw-hq", "aus-br"}}, "dev-a,dev-a2"},
		"unconstrained":           {plan.DeviceFilter{}, "dev-a,dev-a2"},
	} {
		if got := ids(tc.f); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}
