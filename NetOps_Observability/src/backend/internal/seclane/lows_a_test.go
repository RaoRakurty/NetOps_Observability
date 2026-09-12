// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// lows_a_test.go — review finding 3.3-07, the §3a rule-1 test for the lane's
// own status surface.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/secapi"
)

// statusProbe drives HandleStatus as one principal and returns the body.
func statusProbe(t *testing.T, fx *laneFixture, p secapi.Principal) map[string]any {
	t.Helper()
	var body map[string]any
	fx.lane.deps.Authz = func(http.ResponseWriter, *http.Request, secapi.Gate) (secapi.Principal, bool) {
		return p, true
	}
	fx.lane.deps.WriteJSON = func(_ http.ResponseWriter, _ int, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
	}
	fx.lane.HandleStatus(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/security/lane/status", nil))
	return body
}

// 3.3-07 — THE COUNTER BLOCK IS SCOPED THE WAY THE ROWS ARE.
//
// HandleStatus scoped the tenant rows and then served metrics.Snapshot()
// UNFILTERED: platform-wide scan runs, per-class emission counts, dead-letter
// and lost totals, to any administration:write holder. Not a row leak — an
// aggregate inference channel into every other tenant's activity, which §3a
// answers the same way.
func TestLaneStatusDoesNotHandPlatformCountersToATenantAdmin(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.devices["globex"] = []Device{dev("globex-core", "globex")}
	fx.lane.ScanAll(context.Background())
	// Losses that belong to the PLATFORM, not to any one tenant.
	fx.lane.metrics.AddLost(11)
	fx.lane.metrics.AddDeadLettered(7)
	fx.lane.metrics.AddTruncated(5)

	tenant := statusProbe(t, fx, secapi.Principal{Tenant: "acme", Subject: "tenant-admin"})
	metrics, _ := tenant["metrics"].(map[string]any)
	if metrics == nil {
		t.Fatal("a tenant admin got no metrics block at all")
	}
	for _, leaked := range []string{
		"lost_total", "dead_lettered_total", "findings_truncated_total",
		"emit_failures_total", "ungroundable_total",
		"emitted_posture", "emitted_exposure", "emitted_signal",
	} {
		if v, ok := metrics[leaked]; ok {
			t.Errorf("a tenant admin was served the PLATFORM counter %q (=%v) — it aggregates every other tenant's activity",
				leaked, v)
		}
	}
	// Its own scan count is its own to know, and it is the truth.
	runs, ok := metrics["scan_runs_total"].(float64)
	if !ok || runs != 1 {
		t.Fatalf("scan_runs_total for acme = %v (present=%v), want its own 1", metrics["scan_runs_total"], ok)
	}
	if tenant["metrics_scope"] != "tenant" {
		t.Fatalf("the response does not declare what its numbers cover: %v", tenant["metrics_scope"])
	}
	rows, _ := tenant["tenants"].([]any)
	if len(rows) != 1 {
		t.Fatalf("a tenant admin saw %d rows", len(rows))
	}

	// The platform admin's view is unchanged: it is cross-tenant by definition.
	platform := statusProbe(t, fx, secapi.Principal{Cross: true, Subject: "platform"})
	pm, _ := platform["metrics"].(map[string]any)
	if _, ok := pm["lost_total"]; !ok {
		t.Fatal("the platform admin lost the counters it is meant to have")
	}
	if platform["metrics_scope"] != "platform" {
		t.Fatalf("platform scope = %v", platform["metrics_scope"])
	}
	if runsAll, _ := pm["scan_runs_total"].(float64); runsAll != 2 {
		t.Fatalf("platform scan_runs_total = %v, want 2", pm["scan_runs_total"])
	}
}
