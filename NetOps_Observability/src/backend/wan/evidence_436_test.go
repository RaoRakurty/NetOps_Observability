// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"strings"
	"testing"
)

// Tracker 436 (b)/(c): a plain-router estate — no SD-WAN controller, no TLOC
// table, no operator marks, no declared next-hops — used to show an EMPTY
// confirmed WAN list. The device itself states two WAN facts over standard
// MIBs every vendor answers: the medium of a port (IF-MIB ifType) and an eBGP
// session to a peer the inventory does not hold, from a port's own address
// (BGP4-MIB bgpPeerLocalAddr). Both now confirm the port, and say so.

func TestExternalBGPPeersIsEBGPToAPeerOutsideTheInventory(t *testing.T) {
	inv := map[string]bool{"10.0.0.2": true} // the core router, in the inventory
	sessions := []BGPSession{
		{Peer: "203.0.113.1", Local: "203.0.113.2", RemoteAS: 64500}, // ISP A: eBGP, external → yes
		{Peer: "10.0.0.2", Local: "10.0.0.1", RemoteAS: 64999},       // eBGP to an inventory device → no
		{Peer: "10.9.9.9", Local: "10.9.9.8", RemoteAS: 65010},       // iBGP (same AS) → no
		{Peer: "198.51.100.1", Local: "", RemoteAS: 64501},           // not up: no local address → no
		{Peer: "100.64.0.1", Local: "100.64.0.2", RemoteAS: 0},       // remote AS unknown → no
		{Peer: "192.0.2.9", Local: "192.0.2.10", RemoteAS: 23456},    // a 4-byte-AS peer of a 2-byte-AS router → yes
	}
	got := ExternalBGPPeers(sessions, 65010, inv)
	if len(got) != 2 {
		t.Fatalf("external sessions %v, want exactly ISP A and the 4-byte peer", got)
	}
	if p := got["203.0.113.2"]; p.Peer != "203.0.113.1" || p.RemoteAS != 64500 || p.LocalAS != 65010 {
		t.Errorf("ISP A: %+v", p)
	}
	if _, ok := got["192.0.2.10"]; !ok {
		t.Error("a 4-byte-AS peer (AS_TRANS 23456) of a 2-byte-AS router is eBGP")
	}
	// The router's own AS unknown, or itself AS_TRANS: eBGP cannot be told — nothing.
	if n := len(ExternalBGPPeers(sessions, 0, inv)); n != 0 {
		t.Errorf("local AS unknown: %d sessions, want 0", n)
	}
	if n := len(ExternalBGPPeers(sessions, 23456, inv)); n != 0 {
		t.Errorf("local AS is AS_TRANS: %d sessions, want 0", n)
	}
}

func TestExternalBGPPeersIsDeterministicWhenTwoPeersShareALocalAddress(t *testing.T) {
	// An exchange LAN: two external peers from one port address.
	a := []BGPSession{{Peer: "198.51.100.20", Local: "198.51.100.5", RemoteAS: 64600},
		{Peer: "198.51.100.10", Local: "198.51.100.5", RemoteAS: 64601}}
	b := []BGPSession{a[1], a[0]}
	for _, s := range [][]BGPSession{a, b} {
		if p := ExternalBGPPeers(s, 65010, nil)["198.51.100.5"]; p.Peer != "198.51.100.10" {
			t.Fatalf("named %q, want the lowest peer address", p.Peer)
		}
	}
}

// The plain-router estate end to end through BuildFacts + Classify, one row per
// vendor spelling: the ports the device's own MIBs call WAN are confirmed, with
// the evidence named; LAN ports, a loopback-sourced session and a tunnel stay out.
func TestPlainRouterEstateGetsConfirmedWANPortsFromItsOwnMIBs(t *testing.T) {
	for _, c := range []struct {
		vendor, serial, dialer, isp, lan, lo, tun string
	}{
		{"cisco IOS-XE", "Serial0/1/0", "Dialer1", "GigabitEthernet0/0/0", "GigabitEthernet0/0/1", "Loopback0", "Tunnel10"},
		{"juniper", "t1-1/0/0", "pp0.0", "ge-0/0/0.0", "ge-0/0/1.0", "lo0.0", "st0.0"},
		{"nokia", "1/1/1", "ppp-1", "to-isp-a", "1/1/2", "system", "tunnel-1"},
		{"arista", "Serial1", "Dialer1", "Ethernet1", "Ethernet2", "Loopback0", "Tunnel1"},
		{"sonic", "Serial0", "Dialer0", "Ethernet0", "Ethernet4", "Loopback0", "Tunnel0"},
	} {
		in := DeviceInputs{
			DeviceID: "br-gw-1", Name: "br-gw-1", Candidate: true,
			AddrIf: map[string]string{
				"198.51.100.2": c.serial, "100.64.10.2": c.dialer, "203.0.113.2": c.isp,
				"10.10.0.1": c.lan, "10.255.0.1": c.lo, "172.31.0.1": c.tun,
			},
			SNMP: map[string]SNMPIf{
				c.serial: {Kind: "wan_media", Type: "propPointToPointSerial(22)"},
				c.dialer: {Kind: "wan_media", Type: "ppp(23)"},
				c.isp:    {Kind: "ethernet", Type: "ethernetCsmacd(6)"},
				c.lan:    {Kind: "ethernet", Type: "ethernetCsmacd(6)"},
				c.lo:     {Kind: "loopback", Type: "softwareLoopback(24)"},
				c.tun:    {Kind: "tunnel", Type: "tunnel(131)"},
			},
			ExternalBGP: ExternalBGPPeers([]BGPSession{
				{Peer: "203.0.113.1", Local: "203.0.113.2", RemoteAS: 64500}, // ISP over the Ethernet hand-off
				{Peer: "192.0.2.77", Local: "10.255.0.1", RemoteAS: 64777},   // multihop from the loopback
				{Peer: "172.31.0.2", Local: "172.31.0.1", RemoteAS: 64888},   // over a tunnel (cloud VPN)
			}, 65010, map[string]bool{}),
		}
		got := verdicts(BuildFacts(in, nil))
		want(t, got, c.serial, Confirmed, BasisWANMedia)
		want(t, got, c.dialer, Confirmed, BasisWANMedia)
		want(t, got, c.isp, Confirmed, BasisExternalBGP)
		want(t, got, c.lan, "", "")
		want(t, got, c.lo, "", "")
		want(t, got, c.tun, "", "")
		if ev := got[c.serial].Evidence; len(ev) == 0 || ev[0].Source != "snmp" || !strings.Contains(ev[0].Detail, "propPointToPointSerial(22)") {
			t.Errorf("%s: the medium evidence names the IF-MIB ifType: %+v", c.vendor, ev)
		}
		if r := got[c.isp].Reason; !strings.Contains(r, "203.0.113.1") || !strings.Contains(r, "64500") {
			t.Errorf("%s: the eBGP reason names the peer and its AS: %q", c.vendor, r)
		}
		if ev := got[c.isp].Evidence; len(ev) == 0 || ev[0].Source != "bgp" {
			t.Errorf("%s: the eBGP evidence is bgp: %+v", c.vendor, ev)
		}
	}
}

// An eBGP session alone confirms only on a device that already looks like a WAN
// router: in a partly-onboarded data centre a leaf's eBGP uplinks to spines the
// inventory does not hold yet must not be probed as WAN circuits. Elsewhere it
// is offered as POSSIBLE (shown apart, never measured until an operator marks
// it). A WAN medium is physics: it confirms on any device.
func TestExternalBGPConfirmsOnlyOnACandidateDevice(t *testing.T) {
	in := DeviceInputs{
		DeviceID: "dc-leaf-7", Name: "dc-leaf-7", Candidate: false,
		AddrIf: map[string]string{"10.1.0.1": "Ethernet49", "10.2.0.1": "Serial0"},
		SNMP:   map[string]SNMPIf{"Serial0": {Kind: "wan_media", Type: "hdlc(118)"}},
		ExternalBGP: ExternalBGPPeers([]BGPSession{{Peer: "10.1.0.0", Local: "10.1.0.1", RemoteAS: 65100}},
			65101, nil),
	}
	got := verdicts(BuildFacts(in, nil))
	want(t, got, "Ethernet49", Possible, BasisExternalBGP)
	want(t, got, "Serial0", Confirmed, BasisWANMedia)
}

// The controller's own facts still come first, and an operator's "not WAN"
// still wins over the device's MIBs.
func TestMIBEvidenceRanksAfterControllerAndOperator(t *testing.T) {
	in := DeviceInputs{
		DeviceID: "e", Name: "e", Candidate: true,
		AddrIf: map[string]string{"200.1.1.1": "ge0/0", "200.2.2.2": "Serial0"},
		Rows:   []IfRow{{Name: "ge0/0", VRF: "0", Role: "transport", Addrs: []string{"200.1.1.1"}}},
		SNMP:   map[string]SNMPIf{"Serial0": {Kind: "wan_media", Type: "ppp(23)"}, "ge0/0": {Kind: "ethernet", Type: "ethernetCsmacd(6)"}},
		Marks:  map[string]string{"Serial0": MarkNotWAN},
		ExternalBGP: ExternalBGPPeers([]BGPSession{{Peer: "200.1.1.254", Local: "200.1.1.1", RemoteAS: 64500}},
			65010, nil),
	}
	got := verdicts(BuildFacts(in, nil))
	want(t, got, "ge0/0", Confirmed, BasisSDWANTransport)
	want(t, got, "Serial0", "", "")
}

// SNMP facts fill only interfaces the bridge already knows (an address or a
// controller row): a 48-port switch's IF-MIB never becomes 48 WAN rows.
func TestSNMPFactsNeverInventInterfaces(t *testing.T) {
	in := DeviceInputs{
		DeviceID: "sw", Name: "sw-gw", Candidate: true,
		AddrIf: map[string]string{"10.0.0.1": "Vlan1"},
		SNMP:   map[string]SNMPIf{"Serial9": {Kind: "wan_media", Type: "ppp(23)"}, "Gi1/0/1": {Kind: "ethernet"}},
	}
	f := BuildFacts(in, nil)
	if len(f.Ifaces) != 1 || f.Ifaces[0].Name != "Vlan1" {
		t.Fatalf("interfaces %+v, want only Vlan1", f.Ifaces)
	}
}
