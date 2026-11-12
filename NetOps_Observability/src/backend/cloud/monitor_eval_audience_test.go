// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// monitor_eval_audience_test.go — tracker 359: a tenant's cloud-monitor alert
// is attributed to that tenant and never pages the platform PagerDuty key.
//
// The integrator hands Fire/Resolve to the platform-global notifier, and (since
// the 2026-11-12 owner decision) TenantFire/TenantResolve to the owning
// tenant's own lanes. The only global destination that pages is wrapped in
// notify.PlatformScopeFilter, which forwards platform self-health (`layer`
// label) only. This pins that a monitor firing and clearing carries the
// evaluator's own tenant and no platform layer, so it stays off that key, and
// that the tenant handed to the tenant lane is the evaluator's own.

import (
	"context"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

type monitorAudienceProbe struct{ sent, resolved int }

func (p *monitorAudienceProbe) Name() string                   { return "pagerduty" }
func (p *monitorAudienceProbe) Send(models.Alert) error        { p.sent++; return nil }
func (p *monitorAudienceProbe) SendResolve(models.Alert) error { p.resolved++; return nil }

func TestMonitorAlertsCarryTenantAndNeverPageThePlatformKey(t *testing.T) {
	store := NewMonitorStore("")
	def := Monitor{ID: "m1", Name: "High CPU", Metric: "cloud_cpu_util",
		Mode: MonitorModeThreshold, Condition: MonitorCondAbove, Threshold: 90,
		Enabled: true, LastState: MonitorStateNever}
	if fits, err := store.Upsert("acme", def); err != nil || !fits {
		t.Fatal("seed monitor failed")
	}
	var fired, cleared []models.Alert
	val := 95.0
	e := NewMonitorEvaluator(store, MonitorEvalDeps{
		ResourceIDs: func(context.Context, string) ([]string, error) { return []string{"i-1"}, nil },
		Query: func(context.Context, string) map[string]float64 {
			return map[string]float64{"i-1": val}
		},
		Fire:    func(a models.Alert) { fired = append(fired, a) },
		Resolve: func(a models.Alert) { cleared = append(cleared, a) },
		Now:     func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}, time.Minute)

	e.evaluateAll(context.Background()) // 95 > 90 → fires
	val = 10
	e.evaluateAll(context.Background()) // recovered → resolves
	if len(fired) != 1 || len(cleared) != 1 {
		t.Fatalf("want one fire + one resolve, got fire=%d resolve=%d", len(fired), len(cleared))
	}

	probe := &monitorAudienceProbe{}
	key := notify.NewPlatformScopeFilter(probe)
	for _, a := range []models.Alert{fired[0], cleared[0]} {
		if got := a.Labels["tenant_id"]; got != "acme" {
			t.Fatalf("tenant_id label = %q, want the evaluator's tenant %q", got, "acme")
		}
		if layer, ok := a.Labels["layer"]; ok {
			t.Fatalf("customer monitor alert carries layer=%q — a platform layer would page the global key", layer)
		}
		if err := key.Send(a); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if err := key.SendResolve(a); err != nil {
			t.Fatalf("SendResolve: %v", err)
		}
	}
	if probe.sent != 0 || probe.resolved != 0 {
		t.Fatalf("tenant monitor alert reached the platform paging key: sent=%d resolved=%d", probe.sent, probe.resolved)
	}
}

// TestMonitorTenantDeliveryCarriesTheEvaluatorsTenant — tracker 359: the
// tenant handed to TenantFire/TenantResolve is the store key the monitor was
// read from, not a label and not anything in the monitor definition. A
// monitor whose NAME impersonates another tenant still routes to its owner.
func TestMonitorTenantDeliveryCarriesTheEvaluatorsTenant(t *testing.T) {
	store := NewMonitorStore("")
	for _, tenant := range []string{"acme", "globex"} {
		def := Monitor{ID: "m-" + tenant, Name: "tenant_id=globex", Metric: "cloud_cpu_util",
			Mode: MonitorModeThreshold, Condition: MonitorCondAbove, Threshold: 90,
			Enabled: true, LastState: MonitorStateNever}
		if fits, err := store.Upsert(tenant, def); err != nil || !fits {
			t.Fatal("seed monitor failed")
		}
	}
	type edge struct{ kind, tenant, id string }
	var edges []edge
	val := 95.0
	e := NewMonitorEvaluator(store, MonitorEvalDeps{
		ResourceIDs:   func(context.Context, string) ([]string, error) { return []string{"i-1"}, nil },
		Query:         func(context.Context, string) map[string]float64 { return map[string]float64{"i-1": val} },
		Fire:          func(models.Alert) {},
		Resolve:       func(models.Alert) {},
		TenantFire:    func(tn string, a models.Alert) { edges = append(edges, edge{"fire", tn, a.ID}) },
		TenantResolve: func(tn string, a models.Alert) { edges = append(edges, edge{"resolve", tn, a.ID}) },
		Now:           func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}, time.Minute)

	e.evaluateAll(context.Background()) // both fire
	e.evaluateAll(context.Background()) // still firing — no new edge
	val = 10
	e.evaluateAll(context.Background()) // both resolve
	want := map[edge]bool{
		{"fire", "acme", "cloud-monitor-m-acme"}: true, {"fire", "globex", "cloud-monitor-m-globex"}: true,
		{"resolve", "acme", "cloud-monitor-m-acme"}: true, {"resolve", "globex", "cloud-monitor-m-globex"}: true,
	}
	if len(edges) != len(want) {
		t.Fatalf("want exactly one fire + one resolve per monitor, got %v", edges)
	}
	for _, ed := range edges {
		if !want[ed] {
			t.Fatalf("edge routed to the wrong tenant (or extra edge): %+v in %v", ed, edges)
		}
	}
}
