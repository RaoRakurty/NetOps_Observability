// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// E2a — vManage alarms and events reach the engine as canonical kinds, proven
// against payloads recorded from a real vManage 20.6.1 (testdata/vmanage_20.6).

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vmanage_20.6", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// TestEveryRecordedAlarmRuleIsMappedOrExplained: the release's full alarm-rule
// vocabulary must each be mapped to a canonical kind or listed as unclassified
// with a reason. A new release adding a rule fails here instead of the rule
// falling silently to controller_alarm.
func TestEveryRecordedAlarmRuleIsMappedOrExplained(t *testing.T) {
	var rules []string
	if err := json.Unmarshal(readFixture(t, "alarm_rules.json"), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) < 90 {
		t.Fatalf("recorded vocabulary has %d rules — the fixture looks truncated", len(rules))
	}
	for _, r := range rules {
		_, mapped := vmanageAlarmKinds[r]
		reason, listed := vmanageUnclassifiedAlarms[r]
		switch {
		case mapped && listed:
			t.Errorf("rule %q is both mapped and listed unclassified", r)
		case !mapped && !listed:
			t.Errorf("rule %q is neither mapped nor explained — map it or list it with a reason", r)
		case listed && strings.TrimSpace(reason) == "":
			t.Errorf("unclassified rule %q has no reason", r)
		}
	}
	for r := range vmanageAlarmKinds {
		if !contains(rules, r) {
			t.Errorf("mapped rule %q is not in the recorded 20.6 vocabulary — a typo maps nothing", r)
		}
	}
	for r := range vmanageUnclassifiedAlarms {
		if !contains(rules, r) {
			t.Errorf("unclassified rule %q is not in the recorded 20.6 vocabulary", r)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// TestRecordedAlarmsCarryTheirDevice is the regression for the shape bug the
// lab capture exposed: a real alarm names its device in devices[].system-ip,
// not a top-level system_ip, so every vManage alarm used to reach the engine
// with no device.
func TestRecordedAlarmsCarryTheirDevice(t *testing.T) {
	b, err := VManageTransformer{}.Transform("t1", "i1", readFixture(t, "alarms.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 20 {
		t.Fatalf("want the 20 recorded alarms, got %d", len(b.Events))
	}
	for _, e := range b.Events {
		if e.DeviceID == "" {
			t.Errorf("alarm %s (%s) has no device", e.EventID, e.CorrelationHints["rule"])
		}
		if e.SiteID == "" {
			t.Errorf("alarm %s (%s) has no site", e.EventID, e.CorrelationHints["rule"])
		}
	}
}

// TestRecordedAlarmsTakeCanonicalKinds: every recorded alarm is a BFD, control
// or OMP rule; none may fall to the orphan controller_alarm, and an *_Up rule
// or a cleared alarm is a recovery (the engine's _clear convention).
func TestRecordedAlarmsTakeCanonicalKinds(t *testing.T) {
	b, err := VManageTransformer{}.Transform("t1", "i1", readFixture(t, "alarms.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range b.Events {
		rule := e.CorrelationHints["rule"]
		base := strings.TrimSuffix(e.NormalizedEventType, "_clear")
		if base == "controller_alarm" {
			t.Errorf("alarm %s (rule %s) fell to the orphan controller_alarm", e.EventID, rule)
		}
		want := vmanageAlarmKinds[rule]
		if base != want.Kind {
			t.Errorf("rule %s → %s, want %s", rule, base, want.Kind)
		}
		isClear := strings.HasSuffix(e.NormalizedEventType, "_clear")
		if strings.HasSuffix(rule, "_Up") && !isClear {
			t.Errorf("rule %s is a recovery but was emitted as fault %s", rule, e.NormalizedEventType)
		}
		if isClear && e.Severity != "info" {
			t.Errorf("recovery %s carries severity %s, want info", rule, e.Severity)
		}
	}
}

// TestRecordedBGPEventsAreBGPAdjacencyChanges: the lab week's 1,941 BGP peer
// changes (cEDGE-81 ↔ 192.168.200.34 flapping in "active") reached the engine as
// controller_alarm. They are bgp_adjacency_change with the peer, and a session
// that is not established is a fault.
func TestRecordedBGPEventsAreBGPAdjacencyChanges(t *testing.T) {
	b, err := vmanageEventsTransform("t1", "i1", readFixture(t, "events.json"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range b.Events {
		if e.EventType != "bgp-peer-state-change" {
			continue
		}
		n++
		if e.NormalizedEventType != "bgp_adjacency_change" {
			t.Errorf("BGP event %s → %s, want bgp_adjacency_change (a non-established state is a fault)", e.EventID, e.NormalizedEventType)
		}
		if e.PeerID == "" || e.DeviceID == "" {
			t.Errorf("BGP event %s lost its device (%q) or peer (%q)", e.EventID, e.DeviceID, e.PeerID)
		}
		if e.Severity != "high" {
			t.Errorf("BGP session down carries severity %s, want high", e.Severity)
		}
	}
	if n == 0 {
		t.Fatal("the recorded events contain no BGP peer change — fixture regressed")
	}
	// cpu-usage stays unclassified until E3 (metric episodes).
	for _, e := range b.Events {
		if e.EventType == "cpu-usage" && e.NormalizedEventType == "bgp_adjacency_change" {
			t.Fatalf("cpu-usage mis-mapped")
		}
	}
}

// TestBGPEstablishedIsARecovery covers the direction the lab week did not
// record (CONSTRUCTED row in the recorded grammar: the same details format).
func TestBGPEstablishedIsARecovery(t *testing.T) {
	raw := `{"data":[{"id":"x1","eventname":"bgp-peer-state-change","component":"VPN","severity_level":"major",
	 "entry_time":1793500000000,"system_ip":"10.255.255.81","host_name":"cEDGE-81",
	 "details":"host-name=cEDGE-81; peer=192.168.200.34; bgp-new-state=established; vpn-id=200"}]}`
	b, err := vmanageEventsTransform("t1", "i1", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 1 || b.Events[0].NormalizedEventType != "bgp_adjacency_change_clear" || b.Events[0].Severity != "info" {
		t.Fatalf("established must be a recovery: %+v", b.Events)
	}
}

// TestInterfaceStateDirectionComesFromNewState: one rule covers both
// directions; up is a recovery, down a fault, and the interface is carried.
func TestInterfaceStateDirectionComesFromNewState(t *testing.T) {
	for _, tc := range []struct{ state, kind string }{
		{"down", "link_state_change"}, {"up", "link_state_change_clear"},
	} {
		raw := `{"data":[{"uuid":"u-` + tc.state + `","rule_name_display":"Interface_State_Change","type":"interface_state_change",
		 "component":"VPN","severity":"Critical","active":true,"entry_time":1793500000000,
		 "devices":[{"system-ip":"10.255.255.40"}],
		 "values":[{"host-name":"cEDGE-40","if-name":"GigabitEthernet2","new-state":"` + tc.state + `","site-id":"40"}]}]}`
		b, err := VManageTransformer{}.Transform("t1", "i1", []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		e := b.Events[0]
		if e.NormalizedEventType != tc.kind || e.InterfaceName != "GigabitEthernet2" || e.DeviceID != "10.255.255.40" {
			t.Errorf("new-state %s → kind %s iface %q device %q, want %s on GigabitEthernet2 of 10.255.255.40",
				tc.state, e.NormalizedEventType, e.InterfaceName, e.DeviceID, tc.kind)
		}
	}
}

// TestBGPStateNoLongerEmitsADuplicateTransition: a BGP change arrives as its
// own vendor event; the derived state transition must not emit it again.
func TestBGPStateNoLongerEmitsADuplicateTransition(t *testing.T) {
	if _, ok := sdwanStateEventType["bgp"]; ok {
		t.Fatal(`sdwanStateEventType["bgp"] would emit every BGP change a second time`)
	}
}

// TestNoMappedKindIsAnOrphan: every kind the table emits must be one the
// engine consumes — mapping an alarm to a kind the engine has never heard of
// just moves the orphan problem. The engine's vocabulary is pinned in E0
// (telemetry-catalog/source_equivalence.py); here the set is the kinds the
// table may legitimately use.
func TestNoMappedKindIsAnOrphan(t *testing.T) {
	allowed := map[string]bool{
		"controller_bfd_down": true, "controller_control_connection_loss": true,
		"bgp_adjacency_change": true, "ospf_adjacency_change": true, "link_state_change": true,
		"device_restart": true, "controller_policy_change": true, "transceiver_unsupported": true,
	}
	for r, k := range vmanageAlarmKinds {
		if !allowed[k.Kind] {
			t.Errorf("rule %s maps to %s — not a kind the engine consumes", r, k.Kind)
		}
	}
	for n, k := range vmanageEventKinds {
		if !allowed[k.Kind] {
			t.Errorf("event %s maps to %s — not a kind the engine consumes", n, k.Kind)
		}
	}
}
