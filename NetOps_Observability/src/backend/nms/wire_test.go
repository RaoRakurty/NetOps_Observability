// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The netops.controller_events wire contract: the correlation consumer
// (src/correlation/controller_events.py) reads exactly these snake_case keys.
// If this test fails, one side of the contract was renamed alone.
func TestControllerEventWireContract(t *testing.T) {
	ev := ControllerEvent{
		TenantID: "t-a", IntegrationID: "i-1", SourceSystem: "vmanage",
		Vendor: "cisco", Product: "Catalyst SD-WAN Manager", EventID: "42",
		EventTime: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		EventType: "bfd-state-change", NormalizedEventType: "controller_bfd_down",
		Severity: "high", DeviceID: "dev1", DeviceName: "edge-1", SiteID: "s1",
		InterfaceName: "ge0/0", TunnelID: "tun1", Message: "BFD down",
		CorrelationHints: map[string]string{"color": "biz-internet"},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	// Every key controller_events.py reads must be present under this exact name.
	for _, key := range []string{
		"tenant_id", "integration_id", "source_system", "vendor", "product",
		"event_id", "event_time", "event_type", "normalized_event_type",
		"severity", "device_id", "device_name", "site_id", "interface_name",
		"tunnel_id", "message", "correlation_hints",
	} {
		if _, ok := m[key]; !ok {
			t.Fatalf("wire contract broken: key %q missing from %s", key, b)
		}
	}
	// The tenant gate is the consumer's first check — a CamelCase regression
	// would silently drop every event.
	if m["tenant_id"] != "t-a" || m["normalized_event_type"] != "controller_bfd_down" {
		t.Fatalf("wire values wrong: %s", b)
	}
}

// The connector-level vmanage transformer must route BOTH lanes: an approute
// payload → metrics, an alarms payload → events/states. A registry regression
// back to the alarms-only transformer silently empties the metric lane.
func TestVManageAutoTransformerRoutesBothLanes(t *testing.T) {
	reg := NewRegistry()
	conn, ok := reg.Get("vmanage")
	if !ok {
		t.Fatal("vmanage not registered")
	}
	stats, err := os.ReadFile(filepath.Join("fixtures", "vmanage", "approute_stats.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := conn.Transformer().Transform("t-a", "i-1", stats)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Metrics) == 0 || len(b.Events) != 0 {
		t.Fatalf("approute payload must route to metrics: metrics=%d events=%d", len(b.Metrics), len(b.Events))
	}
	alarms, err := os.ReadFile(filepath.Join("fixtures", "vmanage", "tunnel_down.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err = conn.Transformer().Transform("t-a", "i-1", alarms)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) == 0 || len(b.Metrics) != 0 {
		t.Fatalf("alarms payload must route to events: metrics=%d events=%d", len(b.Metrics), len(b.Events))
	}
}
