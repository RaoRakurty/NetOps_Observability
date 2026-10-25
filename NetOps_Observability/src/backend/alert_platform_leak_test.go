// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/models"
)

// P1 2026-10-18: tenant RETAIL was shown the PLATFORM's own alerts — collector
// health, the correlation engine, the ingest pipeline — because a device-less
// alert with no owner was treated as "everybody's". These are the exact shapes
// the lab served it (labels as the rule engine stamps them). They are the
// provider's operational state and name its internals (container addresses,
// component ids), so they reach the cross-tenant platform view ONLY.
func TestPlatformStackAlertsNeverReachATenant(t *testing.T) {
	stack := []models.Alert{
		{ID: "a1", Rule: "CollectorFailing", Severity: "critical", Summary: "lldp collector failing", Labels: map[string]string{"collector": "lldp"}},
		{ID: "a2", Rule: "CollectorFailing", Severity: "critical", Summary: "cdp collector failing", Labels: map[string]string{"collector": "cdp"}},
		{ID: "a3", Rule: "OverlayCollectorDegraded", Severity: "warning", Summary: "sdwan_overlay degraded", Labels: map[string]string{"collector": "sdwan_overlay"}},
		{ID: "a4", Rule: "CorrelationScrapeDown", Severity: "warning", Summary: "correlation down", Labels: map[string]string{"instance": "172.18.0.16:8443", "job": "correlation", "layer": "correlation"}},
		{ID: "a5", Rule: "TrapsDropped", Severity: "warning", Summary: "traps dropped", Labels: map[string]string{"counter": "traps_dropped", "layer": "correlation"}},
		{ID: "a6", Rule: "VectorSinkErrors", Severity: "warning", Summary: "syslog writer failed", Labels: map[string]string{"component_id": "syslog_in", "error_type": "writer_failed", "instance": "vector-aggregator:9598", "layer": "ingest"}},
	}
	own := models.Alert{ID: "own", Rule: "HighCPU", Severity: "critical", DeviceID: "edge-retail", Summary: "edge-retail cpu"}
	other := models.Alert{ID: "other", Rule: "HighCPU", Severity: "critical", DeviceID: "edge-acme", Summary: "edge-acme cpu"}
	ids := map[string]bool{"edge-retail": true}

	for _, a := range stack {
		if alertVisibleTenantOnly(a, alertOwnerLabel(a), "t_retail", false, ids) {
			t.Errorf("PLATFORM LEAK: tenant was shown platform alert %s %v", a.Rule, a.Labels)
		}
		if !alertVisibleTenantOnly(a, alertOwnerLabel(a), "", true, nil) {
			t.Errorf("the platform view lost its own alert %s", a.Rule)
		}
	}
	if !alertVisibleTenantOnly(own, "", "t_retail", false, ids) {
		t.Error("a tenant lost sight of its own device's alert — the fix must not blank the tenant")
	}
	if alertVisibleTenantOnly(other, "", "t_retail", false, ids) {
		t.Error("TENANT LEAK: another tenant's device alert was shown")
	}

	// The resolved per-principal rule (/api/alerts, the WebSocket feed, the
	// dashboard and scheduled reports all go through it) agrees.
	v := alertVisibility{tenant: "t_retail", ids: ids}
	got := v.filter(append(append([]models.Alert{}, stack...), own, other))
	if len(got) != 1 || got[0].ID != "own" {
		t.Errorf("tenant view = %v, want exactly its own device alert", got)
	}
	if n := len(alertVisibility{cross: true}.filter(append(append([]models.Alert{}, stack...), own, other))); n != len(stack)+2 {
		t.Errorf("platform view = %d alerts, want all %d", n, len(stack)+2)
	}
}
