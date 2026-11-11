// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"fmt"
	"strings"
	"testing"

	"netops/backend/internal/bgpfsm"
)

// Tracker 387 on the controller lane (P-424934). Owner rule: only an
// ESTABLISHED session going down is a session failure. vManage's
// bgp-peer-state-change carries only the new state; the connector stamps the
// class (bgp_transition_class) the engine reads, from the trap receiver's own
// classifier (internal/bgpfsm).

func bgpEventRow(id string, at int64, state, routerID string) string {
	det := "host-name=cEDGE-81; peer=192.168.200.34; bgp-new-state=" + state +
		"; local-address=0.0.0.0; local-routerid=192.1.6.2"
	if routerID != "" {
		det += "; peer-routerid=" + routerID
	}
	return fmt.Sprintf(`{"id":%q,"eventname":"bgp-peer-state-change","component":"VPN","severity_level":"major",`+
		`"entry_time":%d,"system_ip":"10.255.255.81","host_name":"cEDGE-81","details":%q}`, id, at, det+"; vpn-id=200")
}

func bgpEvents(t *testing.T, rows ...string) map[string]ControllerEvent {
	t.Helper()
	b, err := vmanageEventsTransform("t1", "i1", []byte(`{"data":[`+strings.Join(rows, ",")+`]}`))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ControllerEvent{}
	for _, e := range b.Events {
		out[e.EventID] = e
	}
	return out
}

// The recorded lab week: cEDGE-81's neighbour 192.168.200.34 oscillating idle
// <-> active, peer-routerid 0.0.0.0 on every report — never established.
func TestRecordedBGPOscillationIsNeverEstablished(t *testing.T) {
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
		if got := e.CorrelationHints["bgp_transition_class"]; got != bgpfsm.NeverEstablished {
			t.Errorf("%s: class %q, want never_established (hints %v)", e.EventID, got, e.CorrelationHints)
		}
		// The event is kept as it was: the engine decides, the evidence stays.
		if e.NormalizedEventType != "bgp_adjacency_change" || e.Severity != "high" {
			t.Errorf("%s: %s/%s — the event itself must not change", e.EventID, e.NormalizedEventType, e.Severity)
		}
	}
	if n != 4 {
		t.Fatalf("recorded BGP reports %d, want 4", n)
	}
}

func TestBGPTransitionClassAndBasis(t *testing.T) {
	cases := []struct {
		name       string
		rows       []string
		id         string
		class, bas string
	}{
		{"lone idle, router id unset", []string{bgpEventRow("a", 100, "idle", "0.0.0.0")},
			"a", bgpfsm.NeverEstablished, vmBGPBasisRouterIDZero},
		{"lone active, router id unset", []string{bgpEventRow("a", 100, "active", "0.0.0.0")},
			"a", bgpfsm.NeverEstablished, vmBGPBasisRouterIDZero},
		// A genuine drop: the peer's router id is known, nothing says it was not
		// established — unknown, so the engine keeps reading it as a down.
		{"lone idle, router id set", []string{bgpEventRow("a", 100, "idle", "10.9.9.9")},
			"a", bgpfsm.Unknown, vmBGPBasisNewState},
		// No router id at all: nothing is inferred from an absent field.
		{"lone idle, no router id", []string{bgpEventRow("a", 100, "idle", "")},
			"a", bgpfsm.Unknown, vmBGPBasisNewState},
		// Direct evidence of the prior state wins over the router id: an
		// established session that dropped is a session failure even when the
		// box reports the peer's id cleared.
		{"established then idle (router id cleared)", []string{
			bgpEventRow("up", 100, "established", "10.9.9.9"), bgpEventRow("down", 200, "idle", "0.0.0.0")},
			"down", bgpfsm.SessionLost, vmBGPBasisPeerHistory},
		{"established then idle (router id set)", []string{
			bgpEventRow("down", 200, "idle", "10.9.9.9"), bgpEventRow("up", 100, "established", "10.9.9.9")},
			"down", bgpfsm.SessionLost, vmBGPBasisPeerHistory},
		{"idle then active, router id set", []string{
			bgpEventRow("b", 200, "active", "10.9.9.9"), bgpEventRow("a", 100, "idle", "10.9.9.9")},
			"b", bgpfsm.NeverEstablished, vmBGPBasisPeerHistory},
		{"active then opensent", []string{
			bgpEventRow("a", 100, "active", "0.0.0.0"), bgpEventRow("b", 200, "opensent", "10.9.9.9")},
			"b", bgpfsm.Progressing, vmBGPBasisPeerHistory},
		{"up is session_up", []string{bgpEventRow("a", 100, "established", "10.9.9.9")},
			"a", bgpfsm.SessionUp, vmBGPBasisNewState},
		// Two reports at one instant that disagree: the order is not evidenced,
		// so neither is the prior state.
		{"tied prior reports disagree", []string{
			bgpEventRow("x", 100, "established", "10.9.9.9"), bgpEventRow("y", 100, "active", "10.9.9.9"),
			bgpEventRow("z", 200, "idle", "10.9.9.9")},
			"z", bgpfsm.Unknown, vmBGPBasisNewState},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, ok := bgpEvents(t, c.rows...)[c.id]
			if !ok {
				t.Fatalf("event %s missing", c.id)
			}
			if got := e.CorrelationHints["bgp_transition_class"]; got != c.class {
				t.Errorf("class %q, want %q", got, c.class)
			}
			if got := e.CorrelationHints["bgp_transition_basis"]; got != c.bas {
				t.Errorf("basis %q, want %q", got, c.bas)
			}
		})
	}
}

// History is per device|peer: another peer's established report says nothing
// about this one.
func TestBGPHistoryIsPerPeer(t *testing.T) {
	other := strings.Replace(bgpEventRow("o", 100, "established", "10.9.9.9"), "peer=192.168.200.34", "peer=192.168.200.99", 1)
	e := bgpEvents(t, other, bgpEventRow("a", 200, "idle", "0.0.0.0"))["a"]
	if e.CorrelationHints["bgp_transition_class"] != bgpfsm.NeverEstablished ||
		e.CorrelationHints["bgp_transition_basis"] != vmBGPBasisRouterIDZero {
		t.Fatalf("hints %v", e.CorrelationHints)
	}
}

// Non-BGP events carry no BGP hint.
func TestNonBGPEventsCarryNoTransitionClass(t *testing.T) {
	raw := `{"data":[{"id":"i1","eventname":"interface-state-change","component":"VPN","severity_level":"major",
	 "entry_time":1793500000000,"system_ip":"10.255.255.81","host_name":"cEDGE-81",
	 "details":"if-name=GigabitEthernet2; new-state=down; peer-routerid=0.0.0.0"}]}`
	b, err := vmanageEventsTransform("t1", "i1", []byte(raw))
	if err != nil || len(b.Events) != 1 {
		t.Fatalf("%v %+v", err, b)
	}
	if _, ok := b.Events[0].CorrelationHints["bgp_transition_class"]; ok {
		t.Fatalf("interface event stamped a BGP class: %v", b.Events[0].CorrelationHints)
	}
}
