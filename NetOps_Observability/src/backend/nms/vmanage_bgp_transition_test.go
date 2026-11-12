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
// classifier (internal/bgpfsm), using the peer's previous report — in the same
// poll, or remembered across polls (vmBGPMemory). peer-routerid 0.0.0.0 decides
// nothing: IOS / IOS-XE clears it on teardown.

func bgpEventRow(id string, at int64, state, routerID string) string {
	return bgpEventRowPeer(id, at, state, routerID, "192.168.200.34")
}

func bgpEventRowPeer(id string, at int64, state, routerID, peer string) string {
	det := "host-name=cEDGE-81; peer=" + peer + "; bgp-new-state=" + state +
		"; local-address=0.0.0.0; local-routerid=192.1.6.2"
	if routerID != "" {
		det += "; peer-routerid=" + routerID
	}
	return fmt.Sprintf(`{"id":%q,"eventname":"bgp-peer-state-change","component":"VPN","severity_level":"major",`+
		`"entry_time":%d,"system_ip":"10.255.255.81","host_name":"cEDGE-81","details":%q}`, id, at, det+"; vpn-id=200")
}

func bgpPoll(t *testing.T, mem *vmBGPMemory, tenant, integration string, rows ...string) map[string]ControllerEvent {
	t.Helper()
	b, err := vmanageEventsTransform(tenant, integration, []byte(`{"data":[`+strings.Join(rows, ",")+`]}`), mem)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ControllerEvent{}
	for _, e := range b.Events {
		out[e.EventID] = e
	}
	return out
}

func bgpEvents(t *testing.T, rows ...string) map[string]ControllerEvent {
	t.Helper()
	return bgpPoll(t, nil, "t1", "i1", rows...)
}

func newTestBGPMemory() *vmBGPMemory {
	return newVMBGPMemory(vmBGPMemoryMaxPeers, vmBGPMemoryReports, vmBGPMemoryTTLms)
}

func wantClass(t *testing.T, e ControllerEvent, class, basis string) {
	t.Helper()
	if got := e.CorrelationHints["bgp_transition_class"]; got != class {
		t.Errorf("%s: class %q, want %q (hints %v)", e.EventID, got, class, e.CorrelationHints)
	}
	if got := e.CorrelationHints["bgp_transition_basis"]; got != basis {
		t.Errorf("%s: basis %q, want %q", e.EventID, got, basis)
	}
}

// The recorded lab week in ONE poll: cEDGE-81's neighbour 192.168.200.34
// oscillating idle <-> active. The first report of the batch has no prior
// report, so it is unknown (it reads as a down); every later one follows a
// below-established report and is never_established.
func TestRecordedBGPOscillationInOnePoll(t *testing.T) {
	b, err := vmanageEventsTransform("t1", "i1", readFixture(t, "events.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	n := 0
	for _, e := range b.Events {
		if e.EventType != "bgp-peer-state-change" {
			continue
		}
		n++
		counts[e.CorrelationHints["bgp_transition_class"]]++
		if e.CorrelationHints["bgp_peer_routerid"] != "unset" {
			t.Errorf("%s: the 0.0.0.0 router id must be annotated", e.EventID)
		}
		// The event is kept as it was: the engine decides, the evidence stays.
		if e.NormalizedEventType != "bgp_adjacency_change" || e.Severity != "high" {
			t.Errorf("%s: %s/%s — the event itself must not change", e.EventID, e.NormalizedEventType, e.Severity)
		}
	}
	if n != 4 || counts[bgpfsm.Unknown] != 1 || counts[bgpfsm.NeverEstablished] != 3 {
		t.Fatalf("recorded BGP reports %d, classes %v — want 1 unknown + 3 never_established", n, counts)
	}
}

func TestBGPTransitionClassAndBasis(t *testing.T) {
	cases := []struct {
		name       string
		rows       []string
		id         string
		class, bas string
	}{
		// The review finding: IOS clears the remote router-id on teardown, so a
		// lone idle with 0.0.0.0 is what an established session's drop looks
		// like. With no remembered report it is unknown — read as a down.
		{"lone idle, router id unset", []string{bgpEventRow("a", 100, "idle", "0.0.0.0")},
			"a", bgpfsm.Unknown, vmBGPBasisNewState},
		{"lone active, router id unset", []string{bgpEventRow("a", 100, "active", "0.0.0.0")},
			"a", bgpfsm.Unknown, vmBGPBasisNewState},
		{"lone idle, router id set", []string{bgpEventRow("a", 100, "idle", "10.9.9.9")},
			"a", bgpfsm.Unknown, vmBGPBasisNewState},
		{"lone idle, no router id", []string{bgpEventRow("a", 100, "idle", "")},
			"a", bgpfsm.Unknown, vmBGPBasisNewState},
		{"established then idle (router id cleared)", []string{
			bgpEventRow("up", 100, "established", "10.9.9.9"), bgpEventRow("down", 200, "idle", "0.0.0.0")},
			"down", bgpfsm.SessionLost, vmBGPBasisPeerHistory},
		{"established then idle (router id set)", []string{
			bgpEventRow("down", 200, "idle", "10.9.9.9"), bgpEventRow("up", 100, "established", "10.9.9.9")},
			"down", bgpfsm.SessionLost, vmBGPBasisPeerHistory},
		{"idle then active", []string{
			bgpEventRow("b", 200, "active", "0.0.0.0"), bgpEventRow("a", 100, "idle", "0.0.0.0")},
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
			wantClass(t, e, c.class, c.bas)
		})
	}
}

// ── across polls (vmBGPMemory) ───────────────────────────────────────────────

// A session established in one poll that drops in a later poll is a session
// failure, even though the drop reports peer-routerid 0.0.0.0.
func TestEstablishedThenIdleAcrossPollsIsSessionLost(t *testing.T) {
	mem := newTestBGPMemory()
	bgpPoll(t, mem, "t1", "i1", bgpEventRow("up", 1_000, "established", "10.9.9.9"))
	e := bgpPoll(t, mem, "t1", "i1", bgpEventRow("down", 3_600_000, "idle", "0.0.0.0"))["down"]
	wantClass(t, e, bgpfsm.SessionLost, vmBGPBasisPeerHistory)
}

// The lab's churn across polls: once the memory has seen the peer below
// established, every later report stays never_established poll after poll.
func TestIdleActiveChurnAcrossPollsIsNeverEstablished(t *testing.T) {
	mem := newTestBGPMemory()
	states := []string{"idle", "active"}
	first := bgpPoll(t, mem, "t1", "i1", bgpEventRow("p0", 10_000, "idle", "0.0.0.0"))["p0"]
	wantClass(t, first, bgpfsm.Unknown, vmBGPBasisNewState) // no memory yet: reads as a down, once
	for poll := 1; poll <= 6; poll++ {
		id := fmt.Sprintf("p%d", poll)
		at := int64(10_000 + poll*120_000)
		e := bgpPoll(t, mem, "t1", "i1", bgpEventRow(id, at, states[poll%2], "0.0.0.0"))[id]
		wantClass(t, e, bgpfsm.NeverEstablished, vmBGPBasisPeerHistory)
	}
}

// The 2-minute poll overlap: a report polled twice classifies the same way.
func TestARePolledReportClassifiesTheSameWay(t *testing.T) {
	mem := newTestBGPMemory()
	rows := []string{bgpEventRow("a", 100, "established", "10.9.9.9"), bgpEventRow("b", 200, "idle", "0.0.0.0")}
	first := bgpPoll(t, mem, "t1", "i1", rows...)
	again := bgpPoll(t, mem, "t1", "i1", rows[1], bgpEventRow("c", 300, "active", "0.0.0.0"))
	wantClass(t, first["b"], bgpfsm.SessionLost, vmBGPBasisPeerHistory)
	wantClass(t, again["b"], bgpfsm.SessionLost, vmBGPBasisPeerHistory)
	wantClass(t, again["c"], bgpfsm.NeverEstablished, vmBGPBasisPeerHistory)
}

// A remembered report older than the TTL is not evidence of the prior state.
func TestTheMemoryExpires(t *testing.T) {
	mem := newTestBGPMemory()
	bgpPoll(t, mem, "t1", "i1", bgpEventRow("old", 1_000, "active", "0.0.0.0"))
	late := int64(1_000) + vmBGPMemoryTTLms + 1
	e := bgpPoll(t, mem, "t1", "i1", bgpEventRow("new", late, "idle", "0.0.0.0"))["new"]
	wantClass(t, e, bgpfsm.Unknown, vmBGPBasisNewState)
	within := late + vmBGPMemoryTTLms - 1
	e = bgpPoll(t, mem, "t1", "i1", bgpEventRow("next", within, "active", "0.0.0.0"))["next"]
	wantClass(t, e, bgpfsm.NeverEstablished, vmBGPBasisPeerHistory)
}

// Bounded: past maxPeers the least recently reported peer is forgotten, and a
// peer keeps at most maxReports reports.
func TestTheMemoryIsBounded(t *testing.T) {
	mem := newVMBGPMemory(2, 3, vmBGPMemoryTTLms)
	for i, peer := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		bgpPoll(t, mem, "t1", "i1", bgpEventRowPeer(fmt.Sprintf("e%d", i), int64(1000+i), "established", "10.9.9.9", peer))
	}
	if mem.size() != 2 {
		t.Fatalf("size %d, want 2", mem.size())
	}
	// 10.0.0.1 was evicted: its drop has no memory.
	e := bgpPoll(t, mem, "t1", "i1", bgpEventRowPeer("d1", 5000, "idle", "0.0.0.0", "10.0.0.1"))["d1"]
	wantClass(t, e, bgpfsm.Unknown, vmBGPBasisNewState)
	// 10.0.0.3 is still remembered.
	e = bgpPoll(t, mem, "t1", "i1", bgpEventRowPeer("d3", 5001, "idle", "0.0.0.0", "10.0.0.3"))["d3"]
	wantClass(t, e, bgpfsm.SessionLost, vmBGPBasisPeerHistory)

	for i := 0; i < 10; i++ {
		bgpPoll(t, mem, "t1", "i1", bgpEventRow(fmt.Sprintf("r%d", i), int64(10_000+i), "active", "0.0.0.0"))
	}
	if got := len(mem.recall(vmBGPMemoryKey("t1", "i1", "10.255.255.81|192.168.200.34"), 10_000)); got != 3 {
		t.Fatalf("reports kept %d, want 3", got)
	}
}

// §3a: the same system-ip|peer in another integration or another tenant shares
// nothing.
func TestTheMemoryIsScopedByTenantAndIntegration(t *testing.T) {
	mem := newTestBGPMemory()
	bgpPoll(t, mem, "t1", "i1", bgpEventRow("up", 1_000, "established", "10.9.9.9"))
	for _, scope := range [][2]string{{"t1", "i2"}, {"t2", "i1"}} {
		e := bgpPoll(t, mem, scope[0], scope[1], bgpEventRow("down", 2_000, "idle", "0.0.0.0"))["down"]
		wantClass(t, e, bgpfsm.Unknown, vmBGPBasisNewState)
	}
	e := bgpPoll(t, mem, "t1", "i1", bgpEventRow("down", 2_000, "idle", "0.0.0.0"))["down"]
	wantClass(t, e, bgpfsm.SessionLost, vmBGPBasisPeerHistory)
}

// The registered transformer carries a memory; the zero value does not.
func TestTheRegisteredTransformerRemembers(t *testing.T) {
	c, ok := NewRegistry().Get("vmanage")
	if !ok {
		t.Fatal("vmanage not registered")
	}
	tr, ok := c.Transformer().(VManageAutoTransformer)
	if !ok || tr.bgp == nil {
		t.Fatalf("the registered vManage transformer has no BGP memory: %#v", c.Transformer())
	}
	if (VManageAutoTransformer{}).bgp != nil {
		t.Fatal("the zero value must not share a memory")
	}
}

// History is per device|peer: another peer's established report says nothing
// about this one.
func TestBGPHistoryIsPerPeer(t *testing.T) {
	other := bgpEventRowPeer("o", 100, "established", "10.9.9.9", "192.168.200.99")
	e := bgpEvents(t, other, bgpEventRow("a", 200, "idle", "0.0.0.0"))["a"]
	wantClass(t, e, bgpfsm.Unknown, vmBGPBasisNewState)
}

// Non-BGP events carry no BGP hint.
func TestNonBGPEventsCarryNoTransitionClass(t *testing.T) {
	raw := `{"data":[{"id":"i1","eventname":"interface-state-change","component":"VPN","severity_level":"major",
	 "entry_time":1793500000000,"system_ip":"10.255.255.81","host_name":"cEDGE-81",
	 "details":"if-name=GigabitEthernet2; new-state=down; peer-routerid=0.0.0.0"}]}`
	b, err := vmanageEventsTransform("t1", "i1", []byte(raw), nil)
	if err != nil || len(b.Events) != 1 {
		t.Fatalf("%v %+v", err, b)
	}
	for _, k := range []string{"bgp_transition_class", "bgp_peer_routerid"} {
		if _, ok := b.Events[0].CorrelationHints[k]; ok {
			t.Fatalf("interface event stamped %s: %v", k, b.Events[0].CorrelationHints)
		}
	}
}
