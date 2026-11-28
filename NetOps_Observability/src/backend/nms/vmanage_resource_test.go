// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"strings"
	"testing"
)

// Owner 2026-11-25 (ENGINE_SEMVER 3.9.0): a controller-relayed CPU / memory
// threshold is canonical device_resource_anomaly evidence with a `resource`
// hint, and "back to normal" is its `_clear` — so the engine's resource dwell
// holds a 4-second flap instead of opening a case per crossing. Until then it
// was controller_alarm at vManage's severity.

func resourceEvents(t *testing.T, rows ...string) []ControllerEvent {
	t.Helper()
	b, err := vmanageEventsTransform("t1", "i1", []byte(`{"data":[`+strings.Join(rows, ",")+`]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	return b.Events
}

func cpuRow(id, deviceType, ip, details, sev string) string {
	return `{"id":"` + id + `","eventname":"cpu-usage","component":"System","severity_level":"` + sev +
		`","entry_time":1793563978000,"system_ip":"` + ip + `","host_name":"n","device_type":"` + deviceType +
		`","details":"` + details + `"}`
}

func TestRecordedCPUBackToNormalIsAResourceClear(t *testing.T) {
	// The two recorded cpu-usage events (testdata/vmanage_20.6/events.json) both
	// say "back to normal": each must arrive as the clear, never as a fault.
	b, err := vmanageEventsTransform("t1", "i1", readFixture(t, "events.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range b.Events {
		if e.EventType != "cpu-usage" {
			continue
		}
		seen++
		if e.NormalizedEventType != "device_resource_anomaly_clear" || e.Severity != "info" {
			t.Errorf("recorded back-to-normal %s → %s/%s, want device_resource_anomaly_clear/info",
				e.EventID, e.NormalizedEventType, e.Severity)
		}
		if e.CorrelationHints["resource"] != "cpu" || e.CorrelationHints["node_role"] != "edge" {
			t.Errorf("hints = %v, want resource=cpu node_role=edge", e.CorrelationHints)
		}
	}
	if seen != 2 {
		t.Fatalf("recorded cpu-usage events = %d, want 2", seen)
	}
}

func TestCPUAboveThresholdIsAResourceRaiseAtTheControllersSeverity(t *testing.T) {
	ev := resourceEvents(t,
		cpuRow("a", "vedge", "10.255.255.51", "host-name=vEdge-51; warning=System cpu usage is above 75%; cpu-idle-percentage=20.0", "major"),
		cpuRow("b", "vedge", "10.255.255.51", "host-name=vEdge-51; warning=System cpu usage is above 90% (critically high); cpu-idle-percentage=2.0", "critical"))
	if len(ev) != 2 {
		t.Fatalf("events = %d", len(ev))
	}
	for i, want := range []string{"high", "crit"} {
		e := ev[i]
		if e.NormalizedEventType != "device_resource_anomaly" {
			t.Errorf("%s → %s, want device_resource_anomaly", e.EventID, e.NormalizedEventType)
		}
		if e.Severity != want {
			t.Errorf("%s severity %s, want %s (the controller's own, never promoted)", e.EventID, e.Severity, want)
		}
		if e.CorrelationHints["resource"] != "cpu" {
			t.Errorf("%s resource hint %q", e.EventID, e.CorrelationHints["resource"])
		}
		if _, isRecovery := e.CorrelationHints["transition"]; isRecovery {
			t.Errorf("%s marked a recovery", e.EventID)
		}
	}
}

func TestMemoryUsageMapsTheSameWay(t *testing.T) {
	ev := resourceEvents(t,
		`{"id":"m1","eventname":"memory-usage","component":"System","severity_level":"major","entry_time":1,"system_ip":"10.255.255.3","host_name":"vBond","device_type":"vbond","details":"host-name=vBond; warning=System memory usage is above 80%"}`,
		`{"id":"m2","eventname":"memory-usage","component":"System","severity_level":"minor","entry_time":2,"system_ip":"10.255.255.3","host_name":"vBond","device_type":"vbond","details":"host-name=vBond; warning=System memory usage back to normal level"}`)
	if ev[0].NormalizedEventType != "device_resource_anomaly" || ev[0].CorrelationHints["resource"] != "memory" {
		t.Errorf("raise = %s %v", ev[0].NormalizedEventType, ev[0].CorrelationHints)
	}
	if ev[1].NormalizedEventType != "device_resource_anomaly_clear" {
		t.Errorf("back to normal = %s, want the clear", ev[1].NormalizedEventType)
	}
}

func TestNodeRoleNamesControllerNodes(t *testing.T) {
	for dt, want := range map[string]string{
		"vmanage": "controller", "vsmart": "controller", "vbond": "controller", "VBond": "controller",
		"vedge": "edge", "cedge": "edge", "": "", "router": "",
	} {
		if got := vmNodeRole(dt); got != want {
			t.Errorf("vmNodeRole(%q) = %q, want %q", dt, got, want)
		}
	}
	ev := resourceEvents(t, cpuRow("c", "vbond", "10.255.255.3", "host-name=vBond; warning=System cpu usage is above 75%", "major"))
	if ev[0].CorrelationHints["node_role"] != "controller" {
		t.Errorf("vBond node_role = %q, want controller", ev[0].CorrelationHints["node_role"])
	}
	// An event with no device_type states no role (never guessed).
	ev = resourceEvents(t, `{"id":"d","eventname":"cpu-usage","component":"System","severity_level":"major","entry_time":1,"system_ip":"10.0.0.9","host_name":"x","details":"warning=System cpu usage is above 75%"}`)
	if _, ok := ev[0].CorrelationHints["node_role"]; ok {
		t.Errorf("no device_type → node_role must be absent, got %v", ev[0].CorrelationHints)
	}
}

func TestResourceThresholdAlarmsMapAndClear(t *testing.T) {
	raw := []byte(`{"data":[
	 {"uuid":"u1","rule_name_display":"CPU_Usage","eventname":"cpu-usage","component":"System","severity":"Critical","entry_time":1,"active":true,"devices":[{"system-ip":"10.255.255.51"}],"values":[{"host-name":"vEdge-51"}]},
	 {"uuid":"u1","rule_name_display":"CPU_Usage","eventname":"cpu-usage","component":"System","severity":"Critical","entry_time":2,"active":false,"devices":[{"system-ip":"10.255.255.51"}],"values":[{"host-name":"vEdge-51"}]},
	 {"uuid":"u2","rule_name_display":"Memory_Usage","eventname":"memory-usage","component":"System","severity":"Major","entry_time":3,"active":true,"devices":[{"system-ip":"10.255.255.52"}],"values":[{"host-name":"vEdge-52"}]},
	 {"uuid":"u3","rule_name_display":"Disk_Usage","eventname":"disk-usage","component":"System","severity":"Major","entry_time":4,"active":true,"devices":[{"system-ip":"10.255.255.52"}],"values":[{"host-name":"vEdge-52"}]}
	]}`)
	b, err := VManageTransformer{}.Transform("t1", "i1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 4 {
		t.Fatalf("events = %d", len(b.Events))
	}
	want := []struct{ kind, res string }{
		{"device_resource_anomaly", "cpu"},
		{"device_resource_anomaly_clear", "cpu"},
		{"device_resource_anomaly", "memory"},
		{"controller_alarm", ""}, // Disk_Usage stays unclassified (vmanageUnclassifiedAlarms)
	}
	for i, w := range want {
		e := b.Events[i]
		if e.NormalizedEventType != w.kind || e.CorrelationHints["resource"] != w.res {
			t.Errorf("alarm %d = %s resource=%q, want %s resource=%q",
				i, e.NormalizedEventType, e.CorrelationHints["resource"], w.kind, w.res)
		}
	}
}
