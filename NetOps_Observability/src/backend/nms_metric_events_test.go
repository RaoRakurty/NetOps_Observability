// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/nms"
)

// E3: a controller's canonical device_* samples reach the correlation engine's
// metric lane through the bus bridge, carrying the INTEGRATION's tenant (the
// aggregator's metrics HTTP lane would reset it — a controller-only device is
// in no registry) and collection_path via_controller (the controller authority
// bucket in the verdict gate).
func TestControllerMetricEventsCarryTheIntegrationTenant(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Errorf("bus body is not a JSON array: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("BUS_BRIDGE_URL", srv.URL)

	ts := time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)
	tags := map[string]string{"device": "ctl-vmanage-4ebbc8f4bc3c", "ifName": "GigabitEthernet2", "tenant_id": "t_retail"}
	metrics := []nms.ControllerMetric{
		{TenantID: "t_retail", SourceSystem: "vmanage", Name: "device_if_oper_status", Value: 2, Unit: "state", Time: ts, Tags: tags},
		{TenantID: "t_retail", SourceSystem: "vmanage", Name: "device_cpu_percent", Value: 40.6, Unit: "percent", Time: ts,
			Tags: map[string]string{"device": "ctl-vmanage-4ebbc8f4bc3c"}},
		// Not canonical: stays in VictoriaMetrics, never reaches the engine lane.
		{TenantID: "t_retail", SourceSystem: "vmanage", Name: "controller_metric_device_cpu_pct", Value: 5, Time: ts, Tags: tags},
		// No device: nothing to attribute.
		{TenantID: "t_retail", SourceSystem: "vmanage", Name: "device_cpu_percent", Value: 1, Time: ts},
	}
	if err := nmsEmitMetricEvents(context.Background(), "t_retail", metrics); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want the 2 canonical samples with a device, got %d: %v", len(got), got)
	}
	for _, env := range got {
		if env["topic"] != nms.TopicMetrics || env["key"] != "t_retail" {
			t.Errorf("envelope topic/key = %v/%v, want %s keyed by tenant", env["topic"], env["key"], nms.TopicMetrics)
		}
		ev, _ := env["event"].(map[string]any)
		if ev["tenant_id"] != "t_retail" {
			t.Errorf("event tenant_id = %v, want the integration's tenant", ev["tenant_id"])
		}
		if ev["collection_path"] != "via_controller" || ev["observer_type"] != "controller" {
			t.Errorf("provenance %v/%v, want via_controller/controller", ev["collection_path"], ev["observer_type"])
		}
		if ev["device"] != "ctl-vmanage-4ebbc8f4bc3c" {
			t.Errorf("device %v, want the resolved inventory id", ev["device"])
		}
	}
	first := got[0]["event"].(map[string]any)
	if first["metric"] != "device_if_oper_status" || first["if_name"] != "GigabitEthernet2" || first["signal_family"] != "interface" {
		t.Errorf("interface sample mapped wrong: %v", first)
	}
}
