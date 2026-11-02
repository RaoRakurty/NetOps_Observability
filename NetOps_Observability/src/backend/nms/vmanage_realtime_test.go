// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"errors"
	"math"
	"testing"

	"netops/backend/collectors"
)

// E3 — vManage real-time interface and system state become the canonical
// device_* families the SNMP poller produces, proven on payloads recorded live
// from the lab's vManage 20.6.1 (testdata/vmanage_20.6/*_realtime_*.json).

func metricsByKey(b Batch) map[string]ControllerMetric {
	out := map[string]ControllerMetric{}
	for _, m := range b.Metrics {
		out[m.Name+"|"+m.Tags["device"]+"|"+m.Tags["ifName"]] = m
	}
	return out
}

func TestCEdgeInterfacesBecomeCanonicalSeries(t *testing.T) {
	b, err := vmanageInterfaceRealtimeTransform("t1", "i1", readFixture(t, "interface_realtime_cedge40.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := metricsByKey(b)
	for _, ifn := range []string{"GigabitEthernet1", "GigabitEthernet2", "Loopback200"} {
		oper, ok := m["device_if_oper_status|10.255.255.40|"+ifn]
		if !ok || oper.Value != 1 {
			t.Errorf("%s: oper status %v (present %v), want 1 (if-oper-state-ready = up)", ifn, oper.Value, ok)
		}
		if a := m["device_if_admin_status|10.255.255.40|"+ifn]; a.Value != 1 {
			t.Errorf("%s: admin status %v, want 1", ifn, a.Value)
		}
		if _, ok := m["device_if_in_octets|10.255.255.40|"+ifn]; !ok {
			t.Errorf("%s: no in-octets counter", ifn)
		}
	}
	if s := m["device_if_speed|10.255.255.40|GigabitEthernet1"]; s.Value != 1000 || s.Unit != "mbps" {
		t.Errorf("speed %v %s, want 1000 mbps (SNMP ifHighSpeed units)", s.Value, s.Unit)
	}
	// The vManage-internal VPN's loopback reuses one address on every device —
	// it is not the managed network.
	for k := range m {
		if k == "device_if_oper_status|10.255.255.40|Loopback65528" {
			t.Fatal("internal VPN 65528 interface was emitted")
		}
	}
	for _, x := range b.Metrics {
		if x.Tags["ifName"] == "" || x.Tags["device"] != "10.255.255.40" || x.Tags["tenant_id"] != "t1" {
			t.Fatalf("labels %v: want device=system-ip, ifName, tenant_id like the SNMP series", x.Tags)
		}
		if x.Time.IsZero() {
			t.Fatalf("sample %s has no timestamp", x.Name)
		}
	}
}

func TestVEdgeInterfacesUseTheirOwnVocabulary(t *testing.T) {
	b, err := vmanageInterfaceRealtimeTransform("t1", "i1", readFixture(t, "interface_realtime_vedge20.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := metricsByKey(b)
	if v := m["device_if_oper_status|10.255.255.20|ge0/0"]; v.Value != 1 {
		t.Errorf("vEdge ge0/0 oper %v, want 1 (\"Up\")", v.Value)
	}
	for k := range m {
		for _, internal := range []string{"loopback65528", "loopback65530", "loopback65531"} {
			if k == "device_if_oper_status|10.255.255.20|"+internal {
				t.Errorf("internal VPN interface %s emitted", internal)
			}
		}
	}
}

func TestInterfaceStatusIsNeverGuessed(t *testing.T) {
	for in, want := range map[string]float64{
		"Up": 1, "if-oper-state-ready": 1, "if-state-up": 1,
		"Down": 2, "if-oper-state-no-pass": 2, "if-oper-state-lower-layer-down": 2, "if-state-down": 2,
	} {
		if v, ok := vmIfStatus(in); !ok || v != want {
			t.Errorf("vmIfStatus(%q) = %v,%v want %v", in, v, ok, want)
		}
	}
	for _, unknown := range []string{"", "testing", "dormant?"} {
		if _, ok := vmIfStatus(unknown); ok {
			t.Errorf("vmIfStatus(%q) guessed a status", unknown)
		}
	}
}

func TestSystemRealtimeGivesCPUAndMemoryPercent(t *testing.T) {
	b, err := vmanageSystemRealtimeTransform("t1", "i1", readFixture(t, "system_realtime_cedge40.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := metricsByKey(b)
	cpu := m["device_cpu_percent|10.255.255.40|"]
	if math.Abs(cpu.Value-40.6) > 0.01 { // 100 - cpu_idle 59.40
		t.Errorf("cpu %v, want 40.6", cpu.Value)
	}
	mem := m["device_mem_percent|10.255.255.40|"]
	if math.Abs(mem.Value-2915096.0/3978264.0*100) > 0.01 {
		t.Errorf("mem %v, want used/total*100", mem.Value)
	}
}

// TestCanonicalFamiliesMirrorTheSNMPAllowlist: a connector's canonical names
// and families are the SNMP poller's, never a parallel vocabulary.
func TestCanonicalFamiliesMirrorTheSNMPAllowlist(t *testing.T) {
	for name, fam := range canonicalDeviceMetrics {
		snmpFam, _, ok := collectors.RCAMetricFamily(name)
		if !ok {
			t.Errorf("%s is not on the SNMP RCA allowlist", name)
			continue
		}
		if snmpFam != fam {
			t.Errorf("%s: family %s, SNMP says %s", name, fam, snmpFam)
		}
	}
}

func TestRoutedCarriesCanonicalSamplesOnly(t *testing.T) {
	b, err := vmanageInterfaceRealtimeTransform("t1", "i1", readFixture(t, "interface_realtime_cedge40.json"))
	if err != nil {
		t.Fatal(err)
	}
	b.Metrics = append(b.Metrics, vmMetric("t1", "i1", "controller_metric_device_cpu_pct", 5, "percent", b.Metrics[0].Time, b.Metrics[0].Tags))
	r := NewPipeline(64).Route(b)
	if len(r.Canonical) != len(b.Metrics)-1 {
		t.Fatalf("canonical %d, want every device_* sample (%d) and no controller_metric_*", len(r.Canonical), len(b.Metrics)-1)
	}
	for _, m := range r.Canonical {
		if _, ok := CanonicalDeviceMetricFamily(m.Name); !ok {
			t.Fatalf("non-canonical %s routed to the engine lane", m.Name)
		}
	}
	if len(r.MetricLines) != len(b.Metrics) {
		t.Fatalf("VictoriaMetrics must still receive every sample")
	}
}

func TestRealtimeStreamsAreDefaultsAndUpgradeTheOldDefaults(t *testing.T) {
	spec := Specs()["vmanage"]
	oldDefault := []string{"alarms", "events", "audit", "inventory", "approute", "interfaces", "qos", "system",
		"counters", "hardware", "certs", "control_connections", "bfd"}
	eff := spec.EffectiveStreams(oldDefault)
	if !contains(eff, "interface_realtime") || !contains(eff, "system_realtime") {
		t.Fatalf("an integration on the previous defaults must gain the realtime streams: %v", eff)
	}
	custom := []string{"alarms", "bfd"}
	if got := spec.EffectiveStreams(custom); len(got) != 2 {
		t.Fatalf("a deliberate choice must be kept: %v", got)
	}
	for _, s := range []string{"interface_realtime", "system_realtime"} {
		if _, ok := vmanagePerDevice[s]; !ok {
			t.Errorf("%s is not polled per device", s)
		}
	}
}

func TestMetricEventSinkFailureIsAccounted(t *testing.T) {
	var gotTenant string
	rt := NewRuntime(NewMemStore(), Sinks{EmitMetricEvents: func(_ context.Context, tenant string, ms []ControllerMetric) error {
		gotTenant = tenant
		return errors.New("bus down")
	}}, 0)
	b, _ := vmanageSystemRealtimeTransform("t1", "i1", readFixture(t, "system_realtime_cedge40.json"))
	rep := rt.sinkRouted(context.Background(), Integration{Tenant: "t1", ID: "i1", Vendor: "vmanage"}, NewPipeline(8).Route(b))
	if gotTenant != "t1" {
		t.Fatalf("metric events carried tenant %q, want the integration's t1", gotTenant)
	}
	if rep.failed[LaneMetricEvents] == nil {
		t.Fatalf("a failed metric-event sink must be reported on its lane: %+v", rep)
	}
}
