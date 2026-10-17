// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func bgpE(m *fakeMIB) bgpEnv { return bgpEnv{walk: m.walk, addr: "x", cr: v2c("c"), max: 100} }

func TestInetFromArcs(t *testing.T) {
	for _, c := range []struct {
		arcs []int
		want string
		used int
		ok   bool
	}{
		{[]int{1, 4, 192, 0, 2, 1}, "192.0.2.1", 6, true},
		{[]int{1, 192, 0, 2, 1}, "192.0.2.1", 5, true},
		{append([]int{2, 16}, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), "2001:db8::1", 18, true},
		{[]int{3, 4, 1, 2, 3, 4}, "", 0, false},        // unknown address type
		{[]int{1, 4, 192, 0, 2}, "4.192.0.2", 5, true}, // a valid BARE 4.192.0.2
		{[]int{1, 4, 192, 0}, "", 0, false},            // truncated
		{[]int{1, 4, 192, 0, 2, 1, 7}, "", 0, false},   // over-long
		{[]int{1, 4, 300, 0, 2, 1}, "", 0, false},
	} {
		got, used, ok := inetFromArcs(c.arcs)
		if got != c.want || ok != c.ok || (ok && used != c.used) {
			t.Errorf("%v → %q %d %v", c.arcs, got, used, ok)
		}
	}
}

func TestCiscoPeer3NamesVRFsAndDedupesGlobals(t *testing.T) {
	m := newFakeMIB()
	// vrf id 0 (global) peer also in BGP4-MIB; vrf id 3 "CUST-A" peer; an IPv6 global.
	m.set(oidPlus(cbgpPeer3Entry, 5), "0.1.4.192.0.2.1", intVal(6))
	m.set(oidPlus(cbgpPeer3Entry, 5), "3.1.4.10.0.0.2", intVal(3))
	m.set(oidPlus(cbgpPeer3Entry, 4), "3.1.4.10.0.0.2", strVal("CUST-A"))
	m.set(oidPlus(cbgpPeer3Entry, 13), "3.1.4.10.0.0.2", intVal(65010))
	m.set(oidPlus(cbgpPeer3Entry, 5), "0.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.9", intVal(6))
	m.set(oidPlus(cbgpPeer3Entry, 5), "3.1.4.10.0.0.7", intVal(9)) // outside 1..6: dropped
	r, err := bgpP3.read(context.Background(), bgpE(m))
	if err != nil || r == nil {
		t.Fatal(err)
	}
	r.dedupe(map[string]bool{"192.0.2.1": true})
	lines := strings.Join(bgpVRFLines("pe1", r, 5), "\n")
	for _, want := range []string{
		`device_bgp_peer_state{device="pe1",peer="10.0.0.2",vrf="CUST-A",mib="cisco-bgp-peer3"} 3 5`,
		`device_bgp_peer_remote_as{device="pe1",peer="10.0.0.2",vrf="CUST-A",mib="cisco-bgp-peer3"} 65010 5`,
		`device_bgp_peer_state{device="pe1",peer="2001:db8::9",vrf="default",mib="cisco-bgp-peer3"} 6 5`,
		`collector_bgp_vrf_rows_dropped{device="pe1"} 1 5`,
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %s\n%s", want, lines)
		}
	}
	if strings.Contains(lines, `peer="192.0.2.1"`) {
		t.Error("a global IPv4 peer BGP4-MIB already publishes was emitted twice")
	}
	if strings.Contains(lines, "source=") {
		t.Error("never a source= label (metrics scope rule)")
	}
}

// A VRF peer with the SAME address as a global peer is a different session:
// kept, with its VRF.
func TestOverlappingAddressInAVRFIsKept(t *testing.T) {
	r := newBGPReading(bgpSrcCiscoP3)
	r.peer("CUST-A", "192.0.2.1").State = 6
	r.peer(defaultVRF, "192.0.2.1").State = 6
	r.peer("vrf-id 4", "192.0.2.1").State = 6 // unnamed: treated as possibly global
	r.dedupe(map[string]bool{"192.0.2.1": true})
	if len(r.Peers) != 1 || r.Peers["CUST-A|192.0.2.1"] == nil {
		t.Fatalf("%v", r.Peers)
	}
}

func TestViptelaZeroBasedStatesAndVPNNames(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(viptelaBGPNbrEntry, 10), "10.10.1.1.2", intVal(5)) // established (0-based)
	m.set(oidPlus(viptelaBGPNbrEntry, 10), "10.10.1.1.3", intVal(6)) // clearing → idle, never established
	m.set(oidPlus(viptelaBGPNbrEntry, 10), "10.10.1.1.4", intVal(7)) // deleted → dropped
	m.set(oidPlus(viptelaBGPNbrEntry, 2), "10.10.1.1.2", intVal(65020))
	r, _ := bgpViptela.read(context.Background(), bgpE(m))
	if r == nil || len(r.Peers) != 2 || r.Dropped != 1 {
		t.Fatalf("%+v", r)
	}
	if p := r.Peers["10|10.1.1.2"]; p == nil || p.State != 6 || p.RemoteAS != 65020 {
		t.Fatalf("%+v", p)
	}
	if p := r.Peers["10|10.1.1.3"]; p == nil || p.State != 1 {
		t.Fatalf("clearing must read idle, got %+v", p)
	}
}

func TestNokiaJoinsVRtrNamesAndRefusesUnnamed(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(tBgpPeerNgEntry, 59), "1.1.4.192.0.2.1", intVal(6))
	m.set(oidPlus(tBgpPeerNgEntry, 59), "5.1.4.10.9.9.9", intVal(2))
	m.set(oidPlus(tBgpPeerNgEntry, 59), "7.1.4.10.9.9.8", intVal(2)) // no vRtr row
	m.set(oidPlus(vRtrConfEntry, 28), "1", intVal(1))
	m.set(oidPlus(vRtrConfEntry, 28), "5", intVal(2))
	m.set(oidPlus(vRtrConfEntry, 4), "5", strVal("vprn100"))
	r, _ := bgpNokia.read(context.Background(), bgpE(m))
	if r == nil || r.Peers["default|192.0.2.1"] == nil || r.Peers["vprn100|10.9.9.9"] == nil || r.Dropped != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestHuaweiFoldsAddressFamilies(t *testing.T) {
	m := newFakeMIB()
	// {InstanceId, Afi, Safi, Type, Addr}: one peer in two AF rows.
	m.set(oidPlus(hwBgpPeerEntry, 5), "2.1.1.1.4.10.0.0.1", intVal(3))
	m.set(oidPlus(hwBgpPeerEntry, 5), "2.2.1.1.4.10.0.0.1", intVal(6))
	m.set(oidPlus(hwBgpPeerAFEntry, 6), "2.1.1.1.4.10.0.0.1", strVal("RED"))
	m.set(oidPlus(hwBgpPeerAFEntry, 6), "2.2.1.1.4.10.0.0.1", strVal("RED"))
	r, _ := bgpHuawei.read(context.Background(), bgpE(m))
	if r == nil || len(r.Peers) != 1 || r.Peers["RED|10.0.0.1"].State != 6 {
		t.Fatalf("%+v", r)
	}
}

func TestBGPCollectorSkipsGNMIAndReportsCapability(t *testing.T) {
	c := NewBGPVRFPeers(nil).(*bgpVRFCollector)
	if r := c.pollDevice(context.Background(), Target{ID: "g", GNMICapable: true}); r.capability() != "gnmi" {
		t.Fatal(r.capability())
	}
	c.get = func(context.Context, string, snmpCreds, []int) (berVal, error) {
		return berVal{}, errors.New("timeout")
	}
	if r := c.pollDevice(context.Background(), Target{ID: "d", Address: "192.0.2.9"}); r.capability() != "not_answering" {
		t.Fatal(r.capability())
	}
	m := newFakeMIB()
	m.failOn[oidStr(oidPlus(cbgpPeer2Entry, 3))] = errors.New("genErr")
	c.walk = m.walk
	c.get = func(context.Context, string, snmpCreds, []int) (berVal, error) { return berVal{}, nil } // no sysObjectID → unknown vendor
	if r := c.pollDevice(context.Background(), Target{ID: "d", Address: "192.0.2.9"}); r.capability() != "walk_failed" {
		t.Fatal(r.capability())
	}
	order := func(ss []bgpSource) string {
		var o []string
		for _, s := range ss {
			o = append(o, s.name)
		}
		return strings.Join(o, ",")
	}
	if got := order(bgpSourcesFor(9, true)); got != "cisco-bgp-peer3,cisco-bgp-peer2" {
		t.Error(got)
	}
	if got := order(bgpSourcesFor(0, false)); got != "cisco-bgp-peer2" {
		t.Error("SONiC / unknown vendors read cbgpPeer2:", got)
	}
}
