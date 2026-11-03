// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"testing"
)

// E2b — Catalyst Center, Meraki, NDFC, Prime and Versa alarms take canonical
// kinds instead of the orphan controller_alarm. Doc-claimed: the inputs below
// follow the vendors' documented alarm naming; no lab payload exists yet.

func TestClassifyAlarmText(t *testing.T) {
	cases := []struct {
		text, kind string
		ok         bool
	}{
		{"BGP peer 10.0.0.1 went down", "bgp_adjacency_change", true},
		{"OSPF neighbor 10.1.1.2 lost", "ospf_adjacency_change", true},
		{"IS-IS adjacency down on Eth1/1", "isis_adjacency_change", true},
		{"ISIS adjacency down", "isis_adjacency_change", true},
		{"EIGRP neighbor 10.2.2.2 down", "routing_adjacency_change", true},
		{"Device rebooted", "device_restart", true},
		{"Switch reloaded unexpectedly", "device_restart", true},
		{"Interface GigabitEthernet1/0/1 down", "link_state_change", true},
		{"Uplink port 49 down", "link_state_change", true},
		// Specific before general: these also mention a link / port.
		{"Unsupported SFP inserted on port 3", "transceiver_unsupported", true},
		{"BGP session on link to ISP down", "bgp_adjacency_change", true},
		// A process restarting is not the device restarting.
		{"Process snmpd restarted", "", false},
		{"CPU utilisation high", "", false},
		{"Certificate expiring", "", false},
	}
	for _, c := range cases {
		k, _, ok := classifyAlarmText(c.text)
		if ok != c.ok || k != c.kind {
			t.Errorf("%q → (%q, %v), want (%q, %v)", c.text, k, ok, c.kind, c.ok)
		}
	}
}

func TestAlarmTextIsRecovery(t *testing.T) {
	for text, want := range map[string]bool{
		"WAN 1 connectivity restored": true,
		"Interface Gi1 up":            true,
		"BGP session established":     true,
		"Device came online":          true,
		"WAN 1 connectivity lost":     false,
		"Uplink went down":            false,
		"Uplink status changed":       false, // "uplink" is not "up"
		"Port came up then went down": false, // a fault wins
		"Configuration changed":       false,
	} {
		if got := alarmTextIsRecovery(text); got != want {
			t.Errorf("alarmTextIsRecovery(%q) = %v, want %v", text, got, want)
		}
	}
}

func merakiAlert(t *testing.T, typeID, typeText string) ControllerEvent {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{
		"alertId": "a-" + typeID, "alertType": typeText, "alertTypeId": typeID,
		"deviceSerial": "Q234-ABCD-5678", "networkId": "N_1", "alertLevel": "critical",
		"occurredAt": "2026-11-02T10:00:00Z",
	})
	b, err := MerakiTransformer{}.Transform("t1", "i1", raw)
	if err != nil || len(b.Events) != 1 {
		t.Fatalf("transform %s: %v %+v", typeID, err, b)
	}
	return b.Events[0]
}

// TestMerakiUplinkLossIsALinkFaultNotADeadDevice: losing one WAN uplink used
// to be controller_device_unreachable, which steered the RCA to a dead device.
func TestMerakiUplinkLossIsALinkFaultNotADeadDevice(t *testing.T) {
	cases := []struct{ id, text, kind, sev string }{
		{"wan_connectivity_lost", "WAN 1 connectivity lost", "link_state_change", "crit"},
		{"wan_connectivity_restored", "WAN 1 connectivity restored", "link_state_change_clear", "info"},
		{"uplink_status_changed", "Uplink status changed", "link_state_change", "crit"},
		{"gateway_down", "Device went down", "controller_device_unreachable", "crit"},
		{"gateway_online", "Device came online", "controller_device_unreachable_clear", "info"},
		{"settings_changed", "Settings changed", "controller_policy_change", "crit"},
	}
	for _, c := range cases {
		e := merakiAlert(t, c.id, c.text)
		if e.NormalizedEventType != c.kind || e.Severity != c.sev {
			t.Errorf("%q → %s/%s, want %s/%s", c.text, e.NormalizedEventType, e.Severity, c.kind, c.sev)
		}
	}
}

// TestEveryConnectorUsesTheCanonicalFallback: the alarms each connector's own
// rules did not place used to be controller_alarm.
func TestEveryConnectorUsesTheCanonicalFallback(t *testing.T) {
	if k, _ := catalystNormType("routing", "BGP peer down", "device"); k != "bgp_adjacency_change" {
		t.Errorf("Catalyst Center BGP issue → %s", k)
	}
	if k, _ := catalystNormType("connectivity", "Interface down", "interface"); k != "link_state_change" {
		t.Errorf("Catalyst Center interface-down → %s (was controller_alarm)", k)
	}
	if k, _ := ndfcNormType("ospf adjacency down", "routing", false); k != "ospf_adjacency_change" {
		t.Errorf("NDFC OSPF → %s", k)
	}
	if k, _ := ndfcNormType("link down", "interface", false); k != "link_state_change" {
		t.Errorf("NDFC link-down → %s (was controller_alarm)", k)
	}
	if k, _ := primeNormType("device reloaded", "system"); k != "device_restart" {
		t.Errorf("Prime reload → %s", k)
	}
	if k, _ := versaNormType("bgp neighbor down"); k != "bgp_adjacency_change" {
		t.Errorf("Versa BGP → %s", k)
	}
	// The generic rules ("down on a device", "change") no longer swallow them.
	if k, _ := primeNormType("bgp peer state change", "routing"); k != "bgp_adjacency_change" {
		t.Errorf("Prime BGP state change → %s (was policy change)", k)
	}
	if k := merakiNormType("bgp_down", "BGP peer down"); k != "bgp_adjacency_change" {
		t.Errorf("Meraki BGP down → %s (was device unreachable)", k)
	}
	if k, _ := ndfcNormType("switch reloaded", "system", false); k != "device_restart" {
		t.Errorf("NDFC reload → %s", k)
	}
	// Each connector's OWN specific rule still wins.
	if k, _ := versaNormType("tunnel down"); k != "controller_tunnel_state" {
		t.Errorf("Versa tunnel → %s", k)
	}
	if k, _ := catalystNormType("config", "provisioning", "device"); k != "controller_policy_change" {
		t.Errorf("Catalyst Center config → %s", k)
	}
	// E5b: "change" alone is not a configuration change. A link state change is
	// a link event; a change with nothing classifiable stays controller_alarm.
	if k, _ := primeNormType("interface state change", "interface"); k != "link_state_change" {
		t.Errorf("Prime interface state change → %s, want link_state_change (was policy change)", k)
	}
	if k, _ := primeNormType("threshold change", "system"); k != "controller_alarm" {
		t.Errorf("Prime threshold change → %s, want controller_alarm (was policy change)", k)
	}
	if k, _ := primeNormType("configuration archive changed", "configuration"); k != "controller_policy_change" {
		t.Errorf("Prime configuration change → %s, want controller_policy_change", k)
	}
	// Unclassifiable stays controller_alarm.
	if k, _ := primeNormType("cpu high", "system"); k != "controller_alarm" {
		t.Errorf("Prime CPU → %s, want controller_alarm", k)
	}
}

// TestNoSharedRuleEmitsAnOrphan: every kind the shared table can emit must be
// one the engine consumes (the engine vocabulary is pinned in E0).
func TestNoSharedRuleEmitsAnOrphan(t *testing.T) {
	allowed := map[string]bool{
		"transceiver_unsupported": true, "bgp_adjacency_change": true, "ospf_adjacency_change": true,
		"isis_adjacency_change": true, "routing_adjacency_change": true, "device_restart": true,
		"link_state_change": true,
	}
	for _, r := range canonicalAlarmRules {
		if !allowed[r.Kind] {
			t.Errorf("shared rule emits %s — not a kind the engine consumes", r.Kind)
		}
	}
}
