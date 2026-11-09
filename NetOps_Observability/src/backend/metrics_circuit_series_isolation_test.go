// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// metrics_circuit_series_isolation_test.go — CLAUDE.md §3a rule 5 isolation
// test for the wan-echo circuit series (tracker 337 N-B5).
//
// The circuit_* series carried no label the tenant metric scope reads, so a
// scoped tenant saw none of its OWN circuit measurements. The fix stamps the
// local device's inventory id (`device`) and tenant (`tenant_id`) at emit. This
// test drives the whole real chain — the WAN projection the publisher runs,
// the publisher's target rendering, the collector's label rendering — and
// evaluates the resulting series against the filters metricsScopeFiltersFor
// (the one chokepoint every metrics lane calls) puts on the wire, with
// VictoriaMetrics semantics (vmAdmits), never by string inspection.

import (
	"context"
	"regexp"
	"strconv"
	"testing"

	"netops/backend/collectors"
	"netops/backend/models"
)

var echoLabelRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"`)

// echoSeries parses the label set the collector renders (EchoSeriesLabels)
// into the series VictoriaMetrics would store.
func echoSeries(t *testing.T, name, lbl string) map[string]string {
	t.Helper()
	out := map[string]string{"__name__": name}
	for _, m := range echoLabelRe.FindAllStringSubmatch(lbl, -1) {
		v, err := strconv.Unquote(`"` + m[2] + `"`)
		if err != nil {
			t.Fatalf("label %s: %v", m[1], err)
		}
		if _, dup := out[m[1]]; dup {
			t.Fatalf("label %s rendered twice in %q — VictoriaMetrics would reject the line", m[1], lbl)
		}
		out[m[1]] = v
	}
	return out
}

func TestCircuitSeriesAreVisibleToTheirOwnTenantOnly(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"acme-wan":   {"10.0.0.1": "Ethernet1"},
		"globex-wan": {"10.9.0.1": "Ethernet1"},
	}
	s := newWanTestServer(t, ifaddr, nil)
	s.discovery.Upsert(models.Device{ID: "acme-wan", Name: "acme-wan", Address: "10.0.0.254", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "globex-wan", Name: "globex-wan", Address: "10.9.0.254", TenantID: "globex"})

	// The publisher's projection: platform infrastructure, every tenant.
	_, circuits, err := s.wanProject(context.Background(), platformInfraDeviceVisibility())
	if err != nil {
		t.Fatalf("wanProject: %v", err)
	}
	series := map[string]map[string]string{} // tenant → its circuit series
	for _, tgt := range echoTargetsFor(circuits) {
		series[tgt.Tenant] = echoSeries(t, "circuit_loss_pct", collectors.EchoSeriesLabels(tgt, "icmp", true))
	}
	acmeSeries, globexSeries := series["acme"], series["globex"]
	if acmeSeries == nil || globexSeries == nil {
		t.Fatalf("the fixture produced no circuit for each tenant (%d circuits): this test proves nothing", len(circuits))
	}

	acme := jwtClaims{Sub: "op@acme", Role: RoleOperator, Tenant: "acme"}
	globex := jwtClaims{Sub: "op@globex", Role: RoleOperator, Tenant: "globex"}

	t.Run("a scoped tenant reads its own circuit series", func(t *testing.T) {
		if f := s.metricsScopeFiltersFor(acme); !vmAdmits(t, f, acmeSeries) {
			t.Fatalf("acme's own circuit series is invisible to acme: filters %q, series %v", f, acmeSeries)
		}
		if f := s.metricsScopeFiltersFor(globex); !vmAdmits(t, f, globexSeries) {
			t.Fatalf("globex's own circuit series is invisible to globex: filters %q, series %v", f, globexSeries)
		}
	})

	t.Run("a scoped tenant never reads another tenant's circuit series", func(t *testing.T) {
		if f := s.metricsScopeFiltersFor(acme); vmAdmits(t, f, globexSeries) {
			t.Fatalf("TENANT LEAK: acme read globex's circuit series: filters %q", f)
		}
		if f := s.metricsScopeFiltersFor(globex); vmAdmits(t, f, acmeSeries) {
			t.Fatalf("TENANT LEAK: globex read acme's circuit series: filters %q", f)
		}
	})

	t.Run("as_tenant into another org is ignored for a scoped caller", func(t *testing.T) {
		walker := acme
		walker.ActingTenant = "globex"
		if f := s.metricsScopeFiltersFor(walker); vmAdmits(t, f, globexSeries) || !vmAdmits(t, f, acmeSeries) {
			t.Fatalf("TENANT LEAK: acme's caller acting as globex changed its circuit scope: filters %q", f)
		}
	})

	t.Run("the platform owner scoped into a tenant reads only that tenant", func(t *testing.T) {
		owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal, ActingTenant: "globex"}
		f := s.metricsScopeFiltersFor(owner)
		if !vmAdmits(t, f, globexSeries) || vmAdmits(t, f, acmeSeries) {
			t.Fatalf("owner acting as globex: filters %q admit the wrong circuit series", f)
		}
	})

	t.Run("a series stamped for another tenant stays out even on a colliding device id", func(t *testing.T) {
		// A stale series of acme's, written while acme owned a device id that
		// globex now holds: the device label alone would admit it.
		stale := echoSeries(t, "circuit_latency_ms", collectors.EchoSeriesLabels(collectors.EchoTarget{
			CircuitID: "wan-stale", Tenant: "acme", LocalDevice: "globex-wan", LocalDeviceID: "globex-wan",
			RemoteAddr: "198.51.100.1"}, "icmp", true))
		if f := s.metricsScopeFiltersFor(globex); vmAdmits(t, f, stale) {
			t.Fatalf("TENANT LEAK: globex read acme's circuit series through a colliding device id: filters %q", f)
		}
	})

	t.Run("a target with no inventory id stays platform-only", func(t *testing.T) {
		// WAN_ECHO_TARGETS entries name the prober, not a tenant's device.
		env := echoSeries(t, "circuit_loss_pct", collectors.EchoSeriesLabels(collectors.EchoTarget{
			CircuitID: "env-198.51.100.9", LocalDevice: "prober", RemoteAddr: "198.51.100.9"}, "icmp", false))
		for _, c := range []jwtClaims{acme, globex} {
			if f := s.metricsScopeFiltersFor(c); vmAdmits(t, f, env) {
				t.Fatalf("an env-configured probe circuit reached scoped tenant %s: filters %q", c.Tenant, f)
			}
		}
		if f := s.metricsScopeFiltersFor(jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}); !vmAdmits(t, f, env) {
			t.Fatalf("the platform owner's Global view lost the env-configured circuit: filters %q", f)
		}
	})
}
