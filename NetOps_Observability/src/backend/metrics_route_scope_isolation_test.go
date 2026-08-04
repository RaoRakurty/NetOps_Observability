package backend

// metrics_route_scope_isolation_test.go — every VictoriaMetrics read made while
// serving a tenant-scoped HTTP request must carry that caller's device
// boundary.
//
// WHY THIS EXISTS (2026-08-04). The correlation /replay cross-tenant leak
// prompted a sweep for its defect class — "a request-serving handler reaches a
// datastore without the caller's scope riding along" — and the sweep found four
// more, all in the VictoriaMetrics lane:
//
//   /api/health/score        every class read the whole fleet (qVecBy passes a
//                            literal nil filter while qVecByScoped sits beside
//                            it), emitting other tenants' DEVICE NAMES and their
//                            CPU/memory/error rates as this tenant's score
//                            contributions.
//   /api/topology/view       gatherTopoMetrics was hardened for exactly this
//                            (see its comment at topology_view.go:86-91) but the
//                            three path-trace enrichers in the SAME handler were
//                            not — stampByDst, traceByHop, pathIfaceMetrics.
//   /api/wan/interfaces      util/sparkline/resolver maps joined onto rows by
//                            device+ifName NAME, unscoped.
//   /api/rca/path (health)   the shared resolver, unscoped.
//
// The existing guard (topology_metrics_isolation_test.go) called
// gatherTopoMetrics DIRECTLY, so the unscoped siblings in the same request were
// invisible to it — the same shape as the /replay miss, where a route-PREFIX
// classification hid a subresource. This test therefore drives the ROUTER, and
// asserts on every VM query the request produced, not on one helper.
//
// The rule it pins: for a tenant-scoped principal, NO VictoriaMetrics request
// may be made without extra_filters[]. metricsScopeFilters fails closed (a
// tenant with no visible device gets the __netops_no_visible_device__ sentinel),
// so "no devices" must still produce a filter — never a bare fleet-wide query.

import (
	"net/http"
	"strings"
	"testing"

	"netops/backend/models"
)

func TestMetricsRoutesCarryCallerScope(t *testing.T) {
	routes := []struct {
		name string
		path string
	}{
		{"health score (global)", "/api/health/score?scope=global"},
		{"topology path-trace enrichers", "/api/topology/view?mode=path_trace&src=dev-a&dst=8.8.8.8"},
		{"wan interfaces", "/api/wan/interfaces"},
		{"path health resolver", "/api/rca/path/health"},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			cap := &captureVM{}
			cap.start(t)
			srv, s := newTestServerState(t)
			admin := login(t, srv, "admin", "Passw0rd!2345").Token

			// One org/tenant with a tenant-scoped operator, plus a device so the
			// principal has a non-empty visible set (the empty case is covered by
			// the sentinel assertion below either way).
			st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org A"})
			if st != 201 {
				t.Fatalf("create org: %d %s", st, b)
			}
			orgID := idOf(t, b)
			st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant A", "org_id": orgID})
			if st != 201 {
				t.Fatalf("create tenant: %d %s", st, b)
			}
			tenantID := idOf(t, b)
			st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
				"username": "vm-user", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
			})
			if st != 201 {
				t.Fatalf("create user: %d %s", st, b)
			}
			token := login(t, srv, "vm-user", "Passw0rd!2345").Token
			s.discovery.Upsert(models.Device{ID: "dev-a", Name: "dev-a", TenantID: tenantID})

			// Serve the route as the TENANT-SCOPED caller. The request is made
			// TOLERANTLY: some routes cannot complete in this fixture (e.g.
			// handleTopologyView dereferences s.alerts, which newTestServerState
			// does not wire). That is irrelevant to what we assert — the question
			// is whether any VictoriaMetrics query issued BEFORE that point
			// carried the caller's scope. A handler that leaks and then panics
			// has still leaked.
			req, err := http.NewRequest("GET", srv.URL+rt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}

			got := cap.all()
			if len(got) == 0 {
				t.Skipf("route made no VictoriaMetrics call in this fixture — nothing to assert")
			}
			for i, q := range got {
				filters := q["extra_filters[]"]
				if len(filters) == 0 {
					t.Fatalf("VM query %d from %s carried NO extra_filters[] — a tenant-scoped caller must never issue a fleet-wide read.\nquery=%q",
						i, rt.path, strings.Join(q["query"], ""))
				}
				// The filter must actually name a boundary, not be an empty string.
				joined := strings.Join(filters, "")
				if strings.TrimSpace(joined) == "" {
					t.Fatalf("VM query %d from %s carried an EMPTY extra_filters[] — that is a fleet-wide read with extra steps", i, rt.path)
				}
			}
		})
	}
}

// The platform owner legitimately reads across tenants — the scope helper
// returns no filters for a cross-tenant principal, and that must stay true, or
// the fix above would silently break operator views.
func TestMetricsCrossTenantPrincipalIsUnfiltered(t *testing.T) {
	_, s := newTestServerState(t)
	ids, names, cross := s.visibleDeviceMetricLabels(jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if !cross {
		t.Fatal("the platform owner must be cross-tenant")
	}
	if f := metricsScopeFilters(ids, names, cross); len(f) != 0 {
		t.Fatalf("cross-tenant principal must not be filtered, got %v", f)
	}
}

// A tenant with NO visible devices must still be filtered — fail closed, not
// open. This is the property that makes the fix safe to apply everywhere.
func TestMetricsEmptyDeviceSetStillFilters(t *testing.T) {
	f := metricsScopeFilters(nil, nil, false)
	if len(f) == 0 {
		t.Fatal("a tenant with no visible devices must still produce a filter — otherwise 'no devices' means 'the whole fleet'")
	}
	if !strings.Contains(strings.Join(f, ""), "no_visible_device") {
		t.Fatalf("expected the fail-closed sentinel in %v", f)
	}
}

// The handler-level test above can only exercise routes the fixture can serve.
// These call the FIXED readers directly with a known filter and assert it
// reaches VictoriaMetrics — narrower than a handler test, but it pins each fix
// so a future refactor that drops the parameter fails here.
func TestPathEnrichersPropagateScopeFilters(t *testing.T) {
	const sentinel = `device_id=~"only-mine"`
	for _, tc := range []struct {
		name string
		call func(s *server)
	}{
		{"stampByDst", func(s *server) { s.stampByDst(t.Context(), []string{sentinel}) }},
		{"traceByHop", func(s *server) { s.traceByHop(t.Context(), []string{sentinel}) }},
		{"pathIfaceMetrics", func(s *server) { s.pathIfaceMetrics(t.Context(), []string{sentinel}) }},
		{"resolveCurrentByDst", func(s *server) { s.resolveCurrentByDst(t.Context(), []string{sentinel}) }},
		{"wanSparkSeries", func(s *server) { s.wanSparkSeries(t.Context(), 1000, 600, 30, []string{sentinel}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cap := &captureVM{}
			cap.start(t)
			tc.call(&server{})

			got := cap.all()
			if len(got) == 0 {
				t.Fatalf("%s made no VictoriaMetrics call — the test cannot prove the filter propagates", tc.name)
			}
			for i, q := range got {
				if !strings.Contains(strings.Join(q["extra_filters[]"], ""), "only-mine") {
					t.Fatalf("%s query %d dropped the caller's scope filter (extra_filters[]=%v) — an unscoped read of the whole fleet",
						tc.name, i, q["extra_filters[]"])
				}
			}
		})
	}
}
