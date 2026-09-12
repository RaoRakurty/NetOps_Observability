// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// pipedebug_metrics_scope_test.go — the pipeline debugger's metric-store
// boundary (§3a rule 4, review 3.9-07).
//
// THE DEFECT. A passive gNMI follow exports `{__name__=~"gnmi_.*",source="X"}`
// where X is the device NAME the operator typed. Nothing about that selector is
// self-limiting, and the stage carried no boundary at all: a platform operator
// restricted from a tenant's telemetry (the operator-visibility compliance
// rule), or one scoped INTO a tenant with the switcher, read any device's
// series by naming it. That is the same class of hole the ClickHouse scope on
// this very Principal was built to close — the comment at debugAuthz says so,
// about the manual ticket path — left open one store over, because the metrics
// lane's chokepoint (metricsScopeFiltersFor) was never wired to it.
//
// WHAT IS PROVED HERE: debugAuthz hands the pipedebug Principal the CHOKEPOINT'S
// OWN answer, for all four of its cases, and the transport refuses a scoped read
// it cannot enforce. The other half — that the stage puts the boundary on the
// wire and refuses an underived one — is proved in internal/pipedebug
// (TestPassiveVictoriaStageCarriesTheCallersMetricBoundary,
// TestPassiveVictoriaStageRefusesAnUnderivedBoundary).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// debugScopeFixture is a two-tenant platform with one device each.
func debugScopeFixture(t *testing.T) (*server, string, string) {
	t.Helper()
	dir := t.TempDir()
	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID},
		{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("upsert %s: %v", dev.ID, err)
		}
	}
	return &server{discovery: d, tenants: ts, roles: roles}, acme.ID, globex.ID
}

// debugPrincipalFor runs the REAL gate, so the test cannot pass by calling a
// derivation the shipped route does not use.
func debugPrincipalFor(t *testing.T, s *server, claims jwtClaims) (metricsFilters []string, derived bool) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/debug/trace", nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, claims))
	w := httptest.NewRecorder()
	p, ok := s.debugAuthz(w, r)
	if !ok {
		t.Fatalf("debugAuthz refused the platform owner: %d %s", w.Code, w.Body.String())
	}
	return p.Metrics.Filters, p.Metrics.Derived
}

func TestDebugAuthzCarriesTheMetricsBoundary(t *testing.T) {
	s, acme, globex := debugScopeFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// 1. Unrestricted platform owner: no filters, but the scope IS derived —
	//    which is the distinction the stage fails closed on.
	got, derived := debugPrincipalFor(t, s, owner)
	if !derived {
		t.Fatal("debugAuthz built a Principal with NO derived metric boundary; every passive follow " +
			"would then report not-observable, or (worse, if the guard is ever removed) read unscoped")
	}
	if len(got) != 0 {
		t.Fatalf("an unrestricted platform owner must read unfiltered, got %v", got)
	}

	// 2. Platform owner scoped into a tenant: that tenant's devices only.
	got, _ = debugPrincipalFor(t, s, ownerActing(owner, globex))
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "globex-core") || strings.Contains(joined, "acme-core") {
		t.Fatalf("as_tenant into globex must scope the debugger's metric reads to globex, got %v", got)
	}

	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// 3. Global view with a restricted tenant: its devices are EXCLUDED, so a
	//    passive follow naming acme-core cannot export it.
	got, _ = debugPrincipalFor(t, s, owner)
	if len(got) != 1 || !strings.Contains(got[0], "acme-core") || !strings.Contains(got[0], "!~") {
		t.Fatalf("the Global view must exclude the restricted tenant's devices, got %v", got)
	}

	// 4. Scoped INTO the restricted tenant: the match-nothing sentinel.
	got, _ = debugPrincipalFor(t, s, ownerActing(owner, acme))
	if len(got) != 1 || got[0] != metricsNoVisibleDeviceFilter {
		t.Fatalf("an operator scoped into a restricted tenant must match nothing, got %v", got)
	}

	// The answers are the chokepoint's, not a second derivation of the rule.
	for _, c := range []jwtClaims{owner, ownerActing(owner, acme), ownerActing(owner, globex)} {
		got, _ := debugPrincipalFor(t, s, c)
		want := s.metricsScopeFiltersFor(c)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("debugAuthz derived %v where the chokepoint says %v — the debugger is "+
				"carrying its own copy of the rule", got, want)
		}
	}
}

// extra_filters[] is a VictoriaMetrics extension. A Prometheus upstream IGNORES
// it, which would turn a scoped debug read into an unscoped one with no error
// anywhere — the silent variant of the defect. The read is refused instead.
func TestDebugVictoriaExportRefusesAnUnscopableUpstream(t *testing.T) {
	s := &server{}
	t.Setenv("VICTORIA_URL", "http://prometheus:9090")
	export := s.debugVictoriaExport(http.DefaultClient)

	_, err := export(context.Background(), `{__name__=~"gnmi_.*"}`,
		[]string{`{device=~"acme-core"}`}, time.Unix(1000, 0), time.Unix(2000, 0))
	if err == nil {
		t.Fatal("a scoped read was allowed against an upstream that ignores extra_filters[] — " +
			"the boundary would have been dropped silently")
	}
	if !strings.Contains(err.Error(), "VictoriaMetrics") {
		t.Errorf("the refusal does not name the reason: %v", err)
	}

	// An unrestricted platform owner carries no filters and is unaffected on any
	// backend — the same rule proxyMetrics and igpmonVMQuery apply. It still
	// fails, but on the DIAL, not on the guard.
	_, err = export(context.Background(), `{__name__=~"gnmi_.*"}`, nil, time.Unix(1000, 0), time.Unix(2000, 0))
	if err != nil && strings.Contains(err.Error(), "refusing an unscopable read") {
		t.Errorf("an unfiltered read was refused as unscopable: %v", err)
	}
}
