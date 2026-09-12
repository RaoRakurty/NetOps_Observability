// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// metrics_scope_chokepoint_test.go — the metrics lane's §3a invariant.
//
// A LIST of correct VictoriaMetrics lanes is a snapshot. It says nothing about
// the lane somebody adds next month, and the snapshot had already rotted: six
// lanes built their own extra_filters[] out of the pure metricsScopeFilters and
// so carried the tenant's device boundary but NOT the per-tenant
// operator-visibility restriction, because the restriction lived in
// proxyMetrics and nowhere a new lane would trip over it.
//
// This test pins the shape that makes the lane correct BY CONSTRUCTION instead:
// the filter-building primitives are reachable from exactly one place,
// metricsScopeFiltersFor, which folds both rules. A lane that wants a boundary
// has one function to call, and a lane that hand-rolls one turns this red in
// the same commit that writes it.
//
// The flows lane has had this property for a year through addrTenantClauseFor.
// The metrics lane now has it too.

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// metricsFilterPrimitives are the building blocks that produce a VictoriaMetrics
// extra_filters[] value. Each one, used alone, gives HALF the rule.
var metricsFilterPrimitives = []string{"metricsScopeFilters", "metricsExcludeFilter"}

// metricsChokepointFile is the only file allowed to call them.
const metricsChokepointFile = "metrics_query.go"

func TestMetricsFilterPrimitivesAreReachableOnlyFromTheChokepoint(t *testing.T) {
	sources := packageGoSources(t)
	seen := map[string]int{}

	for file, lines := range sources {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, prim := range metricsFilterPrimitives {
				// `\(` keeps metricsScopeFiltersFor( from matching
				// metricsScopeFilters(.
				if !regexp.MustCompile(`\b` + prim + `\(`).MatchString(line) {
					continue
				}
				if strings.Contains(line, "func "+prim+"(") {
					continue // the declaration
				}
				seen[prim]++
				if file != metricsChokepointFile {
					t.Errorf("%s:%d calls %s directly.\n"+
						"  %s\n"+
						"  That primitive gives a caller the tenant's device boundary and NOTHING about\n"+
						"  the operator-visibility restriction, so this lane serves a restricted tenant's\n"+
						"  series to the platform owner. Call s.metricsScopeFiltersFor(claims) instead —\n"+
						"  it folds both rules and is the only derivation there is.",
						file, i+1, prim, trimmed)
				}
			}
		}
	}

	// A sweep that matches nothing passes for the wrong reason.
	for _, prim := range metricsFilterPrimitives {
		if seen[prim] == 0 {
			t.Errorf("the sweep found no call to %s — its regex has drifted away from the code and this guard proves nothing", prim)
		}
	}
}

// The chokepoint's own answers, pinned. The structural test above says every
// lane goes through this function; this says the function is right.
func TestMetricsScopeFiltersForFoldsBothRules(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, _ := ts.Create("Acme", "acme", "", "", "")
	globex, _ := ts.Create("Globex", "globex", "", "", "")
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID})
	s := &server{discovery: d, tenants: ts}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// 1. Platform owner, nothing restricted → unfiltered.
	if f := s.metricsScopeFiltersFor(owner); len(f) != 0 {
		t.Fatalf("an unrestricted platform owner must read unfiltered, got %v", f)
	}

	if _, err := ts.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// 2. Platform owner in the Global view → acme's devices excluded.
	f := s.metricsScopeFiltersFor(owner)
	if len(f) != 1 || !strings.Contains(f[0], "acme-core") {
		t.Fatalf("the Global view must exclude the restricted tenant's devices, got %v", f)
	}
	if !strings.Contains(f[0], `device!~`) {
		t.Fatalf("the Global-view filter must be an EXCLUSION, got %v", f)
	}
	if strings.Contains(f[0], "globex-core") {
		t.Fatalf("an unrestricted tenant must not be excluded, got %v", f)
	}

	// 3. Platform owner walking in with as_tenant → the match-nothing sentinel.
	if f := s.metricsScopeFiltersFor(ownerActing(owner, acme.ID)); len(f) != 1 || f[0] != metricsNoVisibleDeviceFilter {
		t.Fatalf("an operator scoped INTO a restricted tenant must match nothing, got %v", f)
	}

	// 4. as_tenant into an UNRESTRICTED tenant is untouched by the restriction:
	//    the operator reads globex's own devices, not the sentinel.
	f = s.metricsScopeFiltersFor(ownerActing(owner, globex.ID))
	joined := strings.Join(f, " ")
	if len(f) == 0 || f[0] == metricsNoVisibleDeviceFilter {
		t.Fatalf("an unrestricted tenant must stay readable by the operator, got %v", f)
	}
	if !strings.Contains(joined, "globex-core") || strings.Contains(joined, "acme-core") {
		t.Fatalf("as_tenant into globex must scope to globex alone, got %v", f)
	}

	// 5. The restricted tenant's OWN users are never restricted from their own
	//    series — they get their own device boundary, not the sentinel.
	f = s.metricsScopeFiltersFor(jwtClaims{Sub: "alice", Role: RoleOperator, Tenant: acme.ID})
	if len(f) == 0 {
		t.Fatal("a scoped tenant must always carry a boundary")
	}
	if f[0] == metricsNoVisibleDeviceFilter {
		t.Fatal("the restriction must never be applied to the tenant's OWN users")
	}
	if !strings.Contains(strings.Join(f, " "), "acme-core") {
		t.Fatalf("the tenant must see its own device, got %v", f)
	}
}
