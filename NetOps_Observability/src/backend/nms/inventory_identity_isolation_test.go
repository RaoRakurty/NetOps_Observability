// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"testing"

	"netops/backend/models"
)

// §3a: a controller integration in tenant A must never attach its data to a
// device another tenant — or the platform realm — owns, by any key, even when
// that device carries exactly the system-ip, address, serial or name A's
// controller reports. Unmatched is safe (a second entity); a cross-tenant
// match would put A's alarms on B's device.
func TestInventoryResolverIsTenantStrict(t *testing.T) {
	devs := []models.Device{
		{ID: "edge-b", Name: "edge-1", Address: "10.255.255.40", TenantID: "t_b", SerialNumber: "SN1"},
		{ID: "edge-global", Name: "edge-2", Address: "10.255.255.41", TenantID: "", SerialNumber: "SN2"},
		{ID: "edge-a", Name: "edge-3", Address: "10.255.255.42", TenantID: "t_a", SerialNumber: "SN3"},
	}
	// The overlay snapshot is platform-wide; even an entry filed under A that
	// names B's device must not be honoured.
	sys := map[string]map[string]string{
		"t_b": {"10.255.255.40": "edge-b"},
		"t_a": {"10.255.255.50": "edge-b"},
		"":    {"10.255.255.41": "edge-global"},
	}
	ifs := map[string]map[string]string{"edge-b": {"10.9.9.9": "Lo0"}}
	r := &InventoryResolver{}
	r.Store(BuildInventoryIndex(devs, sys, ifs))

	for _, c := range []struct {
		kind      KeyKind
		key, name string
	}{
		{KeySystemIP, "10.255.255.40", ""}, // B's overlay system-ip + address
		{KeySystemIP, "10.255.255.50", ""}, // forged overlay row under A → B's device
		{KeySystemIP, "10.9.9.9", ""},      // B's interface address
		{KeySystemIP, "10.255.255.41", ""}, // the platform realm's device
		{KeySystemIP, "", "edge-1"},        // B's hostname
		{KeySystemIP, "", "EDGE-2"},        // global hostname
		{KeySerial, "SN1", ""},
		{KeySerial, "sn2", ""},
		{KeyIP, "10.255.255.40", ""},
		{KeyName, "edge-1", ""},
	} {
		if id, ok := r.ResolveDevice("t_a", c.kind, c.key, c.name); ok || id != "" {
			t.Errorf("tenant A resolved %s %q/%q to %q — another scope's device", c.kind, c.key, c.name, id)
		}
	}
	// A's own device still resolves — the isolation is not "resolve nothing".
	if id, ok := r.ResolveDevice("t_a", KeySystemIP, "10.255.255.42", ""); !ok || id != "edge-a" {
		t.Fatalf("own device: %q %v", id, ok)
	}
	if id, ok := r.ResolveDevice("T_A ", KeySerial, "sn3", ""); !ok || id != "edge-a" {
		t.Fatalf("tenant id is normalised the same way devices are: %q %v", id, ok)
	}
	// A platform-owned integration ("global") matches only platform devices
	// (stored as ""), and never a tenant's.
	if id, ok := r.ResolveDevice(PlatformOwner, KeySystemIP, "10.255.255.41", ""); !ok || id != "edge-global" {
		t.Fatalf("platform integration → platform device: %q %v", id, ok)
	}
	for _, key := range []string{"10.255.255.40", "10.255.255.42"} {
		if id, ok := r.ResolveDevice(PlatformOwner, KeySystemIP, key, ""); ok {
			t.Fatalf("platform integration resolved tenant device %q via %s", id, key)
		}
	}
	// B sees only its own.
	if id, ok := r.ResolveDevice("t_b", KeySystemIP, "10.255.255.42", "edge-3"); ok {
		t.Fatalf("tenant B resolved A's device %q", id)
	}
}

// End to end through the runtime pipeline: tenant A's controller alarm for a
// system-ip that only tenant B owns leaves the pipeline still keyed by A's
// controller key, with no claim of a join.
func TestPipelineNeverJoinsAcrossTenants(t *testing.T) {
	r := &InventoryResolver{}
	r.Store(BuildInventoryIndex([]models.Device{{ID: "edge-b", Name: "edge-1", Address: "10.255.255.40", TenantID: "t_b"}}, nil, nil))
	p := NewPipeline(16)
	p.Resolver, p.KeyKind = r, KeySystemIP
	out := p.Route(Batch{
		Events:  []ControllerEvent{{TenantID: "t_a", IntegrationID: "i", EventID: "x", DeviceID: "10.255.255.40", DeviceName: "edge-1"}},
		Metrics: []ControllerMetric{{TenantID: "t_a", Name: "controller_metric_device_cpu_pct", Tags: map[string]string{"device": "10.255.255.40"}}},
	})
	if len(out.Events) != 1 || out.Events[0].DeviceID != "10.255.255.40" || out.Events[0].CorrelationHints["controller_device_id"] != "" {
		t.Fatalf("event %+v", out.Events)
	}
	if len(out.MetricLines) != 1 || out.MetricLines[0] != `controller_metric_device_cpu_pct{device="10.255.255.40"} 0` {
		t.Fatalf("metric %v", out.MetricLines)
	}
}
