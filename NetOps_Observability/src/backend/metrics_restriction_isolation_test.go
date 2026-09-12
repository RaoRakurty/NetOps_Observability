// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// metrics_restriction_isolation_test.go — CLAUDE.md §3a rule 5 isolation test
// for the VictoriaMetrics lanes.
//
// A tenant can switch on the operator-visibility restriction. /api/metrics/query
// honoured it, because proxyMetrics resolved it inline. Six lanes that read the
// SAME series did not: they called the pure metricsScopeFilters themselves,
// which knows about the tenant's device set and nothing about the restriction.
// So a platform owner in the Global view read a restricted tenant's device
// series — device_cpu_percent, device_mem_percent, device_if_in_octets,
// probe_rtt_ms — under /api/health/score, /api/paths/health,
// /api/topology/view, /api/wan/interfaces and /api/metrics/forecast, and
// walking in with ?as_tenant read them directly.
//
// The fix is the chokepoint, not six patches: every lane now calls
// s.metricsScopeFiltersFor, and metrics_scope_chokepoint_test.go fails the
// build if a lane stops. This test drives the real router and asserts what goes
// on the wire, for both halves.

import (
	"net/http"
	"strings"
	"testing"

	"netops/backend/models"
)

// metricsRestrictionRoutes are the lanes this fixture can actually drive to a
// VictoriaMetrics read. The others (topology view, wan interfaces) return before
// any VM call in a bare test server; the structural guard covers them.
var metricsRestrictionRoutes = []string{
	"/api/health/score?scope=global",
	"/api/paths/health",
	"/api/metrics/forecast",
	"/api/metrics/query?query=up",
}

func TestMetricsLanesHonourTheOperatorVisibilityRestriction(t *testing.T) {
	vm := &captureVM{}
	vm.start(t)
	// proxyMetrics reads METRICS_URL; the rest read VICTORIA_URL first.
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	mk := func(name, slug string) string {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": name, "org_id": idOf(t, b), "slug": slug})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		return idOf(t, b)
	}
	acme, globex := mk("Acme", "acme"), mk("Globex", "globex")
	s.discovery.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme})
	s.discovery.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex})

	get := func(path, token, asTenant string) {
		t.Helper()
		req, err := http.NewRequest("GET", srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if asTenant != "" {
			req.Header.Set("X-Acting-Tenant", asTenant)
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}

	// ── baseline: nothing restricted, the owner reads the fleet unfiltered.
	for _, rt := range metricsRestrictionRoutes {
		get(rt, admin, "")
	}
	if len(vm.all()) == 0 {
		t.Fatal("no VictoriaMetrics query was issued — this fixture proves nothing")
	}
	for _, q := range vm.all() {
		if len(q["extra_filters[]"]) != 0 {
			t.Fatalf("with nothing restricted the platform owner must read unfiltered, got %v", q["extra_filters[]"])
		}
	}

	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the owner's GLOBAL view. Every query must exclude acme's
	//    device, and must not exclude globex's.
	for _, rt := range metricsRestrictionRoutes {
		t.Run("global "+rt, func(t *testing.T) {
			fresh := &captureVM{}
			fresh.start(t)
			get(rt, admin, "")
			got := fresh.all()
			if len(got) == 0 {
				t.Skip("route made no VictoriaMetrics call in this fixture")
			}
			for i, q := range got {
				joined := strings.Join(q["extra_filters[]"], " ")
				if !strings.Contains(joined, "acme-core") || !strings.Contains(joined, "!~") {
					t.Fatalf("RESTRICTION LEAK: query %d on %s did not exclude the restricted tenant's device acme-core.\n  query=%q\n  filters=%q",
						i, rt, strings.Join(q["query"], ""), joined)
				}
				if strings.Contains(joined, "globex-core") {
					t.Fatalf("query %d on %s excluded globex-core, which is not restricted: %q", i, rt, joined)
				}
			}
		})
	}

	// ── half 2: the owner walks in with ?as_tenant=acme. Every query must carry
	//    the match-nothing sentinel — not a 403, which would confirm acme has
	//    series at all.
	for _, rt := range metricsRestrictionRoutes {
		t.Run("as_tenant "+rt, func(t *testing.T) {
			fresh := &captureVM{}
			fresh.start(t)
			get(rt, admin, acme)
			got := fresh.all()
			if len(got) == 0 {
				t.Skip("route made no VictoriaMetrics call in this fixture")
			}
			for i, q := range got {
				joined := strings.Join(q["extra_filters[]"], " ")
				if !strings.Contains(joined, "__netops_no_visible_device__") {
					t.Fatalf("RESTRICTION LEAK: query %d on %s?as_tenant=acme read acme's series.\n  query=%q\n  filters=%q",
						i, rt, strings.Join(q["query"], ""), joined)
				}
			}
		})
	}

	// ── the owner scoped into the UNRESTRICTED tenant still reads it.
	t.Run("as_tenant globex is untouched", func(t *testing.T) {
		fresh := &captureVM{}
		fresh.start(t)
		get("/api/health/score?scope=global", admin, globex)
		got := fresh.all()
		if len(got) == 0 {
			t.Skip("no VictoriaMetrics call in this fixture")
		}
		for i, q := range got {
			joined := strings.Join(q["extra_filters[]"], " ")
			if !strings.Contains(joined, "globex-core") {
				t.Fatalf("query %d must scope to globex's own devices, got %q", i, joined)
			}
			if strings.Contains(joined, "__netops_no_visible_device__") {
				t.Fatalf("query %d denied an UNRESTRICTED tenant: %q", i, joined)
			}
		}
	})

	// ── acme's own user is never restricted from acme's own series.
	t.Run("the tenant's own user keeps its own series", func(t *testing.T) {
		st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": "a-acme", "password": "Passw0rd!2345", "role": "operator", "tenant_id": acme,
		})
		if st != 201 {
			t.Fatalf("create user: %d %s", st, b)
		}
		token := login(t, srv, "a-acme", "Passw0rd!2345").Token
		fresh := &captureVM{}
		fresh.start(t)
		get("/api/health/score?scope=global", token, "")
		got := fresh.all()
		if len(got) == 0 {
			t.Skip("no VictoriaMetrics call in this fixture")
		}
		for i, q := range got {
			joined := strings.Join(q["extra_filters[]"], " ")
			if !strings.Contains(joined, "acme-core") || strings.Contains(joined, "__netops_no_visible_device__") {
				t.Fatalf("query %d: acme's own user lost its own series, filters=%q", i, joined)
			}
		}
	})
}
