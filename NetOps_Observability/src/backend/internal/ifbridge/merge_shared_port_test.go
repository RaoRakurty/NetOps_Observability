// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"testing"
	"time"
)

// Tracker 437: one address a controller reports on two ports of ONE device
// (cEdge: Tunnel1 rides GigabitEthernet1's VPN 0 address) used to resolve to
// whichever row came last — the store sorts rows by name, so `Tunnel1` beat
// `GigabitEthernet1` every time, and a newer controller reading then overrode
// the device's own SNMP row (conflict_won / conflict_lost). The bridge now
// names the port that owns the address: never a tunnel riding it.

func TestTunnelPortIsVendorNeutral(t *testing.T) {
	for _, c := range []struct {
		name, kind string
		want       bool
	}{
		// IANA ifType (cEdge `interface-type`) decides alone.
		{"Whatever", KindTunnel, true},
		// Cisco IOS / IOS-XE / NX-OS / IOS-XR, Arista EOS, SONiC.
		{"Tunnel1", "", true}, {"Tu100", "", true}, {"tunnel-ip1", "", true}, {"tunnel-te10", "", true},
		// Juniper: GRE, IP-IP, secure tunnel, flexible tunnel.
		{"gr-0/0/0.0", "", true}, {"ip-0/0/0", "", true}, {"st0.1", "", true}, {"fti0.0", "", true},
		// Nokia SR OS / SR Linux style, Viptela vEdge and Linux.
		{"tunnel-1", "", true}, {"ipsec1", "", true}, {"gre1", "", true}, {"vti0", "", true},
		// Not tunnels.
		{"GigabitEthernet1", KindEthernet, false}, {"GigabitEthernet0/0/0/0", "", false},
		{"ge-0/0/0.0", "", false}, {"xe-0/0/1", "", false}, {"ae0", "", false},
		{"Ethernet1", "", false}, {"Ethernet0", "", false}, {"Port-channel1", "", false},
		{"Vlan10", "", false}, {"Loopback0", KindLoopback, false}, {"Stack1", "", false},
		{"to-isp", "", false}, {"1/1/1", "", false}, {"Sdwan-system-intf", "", false},
		{"ge0/0", "", false}, {"", "", false},
	} {
		if got := TunnelPort(c.name, c.kind); got != c.want {
			t.Errorf("TunnelPort(%q, %q) = %v, want %v", c.name, c.kind, got, c.want)
		}
	}
}

// Every vendor's spelling, both row orders: the non-tunnel port stands.
func TestMergeSharedAddressOnOneDeviceNamesTheNonTunnelPort(t *testing.T) {
	for _, c := range []struct {
		vendor, port, tunnel, kindPort, kindTunnel string
	}{
		{"cisco cEdge", "GigabitEthernet1", "Tunnel1", "iana-iftype-ethernet-csmacd", "iana-iftype-tunnel"},
		{"cisco IOS-XR", "GigabitEthernet0/0/0/0", "tunnel-ip1", "", ""},
		{"viptela vEdge", "ge0/0", "gre1", "", ""},
		{"juniper GRE", "ge-0/0/0.0", "gr-0/0/0.0", "", ""},
		{"juniper secure tunnel", "ge-0/0/1.0", "st0.0", "", ""},
		{"juniper fti", "xe-0/0/0.0", "fti0.0", "", ""},
		{"nokia", "to-isp", "tunnel-1", "", ""},
		{"arista", "Ethernet1", "Tunnel1", "", ""},
		{"sonic", "Ethernet0", "Tunnel0", "", ""},
	} {
		port := Row{IfIndex: "1", IfName: c.port, VRF: "0", Kind: CleanKind(c.kindPort), Addrs: []string{"203.0.113.10"}}
		tun := Row{IfIndex: "13", IfName: c.tunnel, VRF: "0", Kind: CleanKind(c.kindTunnel), Addrs: []string{"203.0.113.10"}}
		for _, rows := range [][]Row{{port, tun}, {tun, port}} {
			st := nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.UnixMilli(), Rows: rows}})
			m := Merge(SNMP{}, st, nil, nil)
			if got := m.Addr["d"]["203.0.113.10"]; got != c.port {
				t.Errorf("%s (rows %s,%s): address names %q, want %q", c.vendor, rows[0].IfName, rows[1].IfName, got, c.port)
			}
			if m.AddrVRF["d"]["203.0.113.10"] != "0" || m.AddrSource["d"]["203.0.113.10"] != SourceNMS {
				t.Errorf("%s: VRF/source %v %v", c.vendor, m.AddrVRF["d"], m.AddrSource["d"])
			}
			if n := m.Stats[StatKey{SourceNMS, MergeMultiPort}]; n != 1 {
				t.Errorf("%s: multi_port_address = %d, want 1", c.vendor, n)
			}
			// The ifIndex map and the raw rows still carry both ports.
			if m.Index["d"]["13"] != c.tunnel || len(m.NMS["d"].Rows) != 2 {
				t.Errorf("%s: the tunnel row itself was lost: %v", c.vendor, m.Index["d"])
			}
		}
	}
}

// The lab shape end to end: the store's name sort put Tunnel1 last; the device's
// own walk names GigabitEthernet1, and a NEWER controller reading must agree with
// it, not override it.
func TestMergeTunnelRidingAPortAgreesWithTheDeviceWalk(t *testing.T) {
	s := NewStore()
	s.Ingest("global", "i", "vmanage", recs("cedge-40", "matched", t0,
		Row{IfIndex: "1", IfName: "GigabitEthernet1", VRF: "0", Kind: "iana-iftype-ethernet-csmacd", Addrs: []string{"192.1.4.2/24"}},
		Row{IfIndex: "13", IfName: "Tunnel1", VRF: "0", Kind: "iana-iftype-tunnel", Addrs: []string{"192.1.4.2"}},
	), t0)
	st, _ := s.Snapshot(map[string]string{"cedge-40": ""}, t0)
	snmp := SNMP{
		Addr:   map[string]map[string]string{"cedge-40": {"192.1.4.2": "Gi1"}},
		AddrAt: map[string]int64{"cedge-40": t0.Add(-time.Hour).UnixMilli()},
	}
	m := Merge(snmp, st, gi, map[string]string{"cedge-40": ""})
	if m.Addr["cedge-40"]["192.1.4.2"] != "Gi1" || m.AddrSource["cedge-40"]["192.1.4.2"] != SourceSNMP {
		t.Fatalf("the tunnel overrode the device's own walk: %v %v", m.Addr, m.AddrSource)
	}
	if m.Stats[StatKey{SourceNMS, MergeConflictWon}] != 0 || m.Stats[StatKey{SourceSNMP, MergeConflictLost}] != 0 ||
		m.Stats[StatKey{SourceNMS, MergeAgreed}] < 1 {
		t.Fatalf("a tunnel riding a port read as a disagreement: %v", m.Stats)
	}
	if m.AddrVRF["cedge-40"]["192.1.4.2"] != "0" {
		t.Fatal("the VRF of the agreed address was lost")
	}
}

// Two non-tunnel ports of one device with one address (VRF-lite reuse): the
// device's own walk decides when it names one of them; otherwise the lowest
// ifIndex, then the name — never the row order.
func TestMergeSharedAddressTieBreakIsStable(t *testing.T) {
	a := Row{IfIndex: "7", IfName: "Gi7", VRF: "red", Addrs: []string{"10.9.9.1"}}
	b := Row{IfIndex: "3", IfName: "Gi9", VRF: "blue", Addrs: []string{"10.9.9.1"}}
	for _, rows := range [][]Row{{a, b}, {b, a}} {
		st := nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.UnixMilli(), Rows: rows}})
		m := Merge(SNMP{}, st, nil, nil)
		if m.Addr["d"]["10.9.9.1"] != "Gi9" || m.AddrVRF["d"]["10.9.9.1"] != "blue" {
			t.Fatalf("lowest ifIndex did not stand: %v %v", m.Addr["d"], m.AddrVRF["d"])
		}
		snmp := SNMP{Addr: map[string]map[string]string{"d": {"10.9.9.1": "Gi7"}}, AddrAt: map[string]int64{"d": 1}}
		m = Merge(snmp, st, nil, nil)
		if m.Addr["d"]["10.9.9.1"] != "Gi7" || m.AddrVRF["d"]["10.9.9.1"] != "red" ||
			m.Stats[StatKey{SourceNMS, MergeConflictWon}] != 0 {
			t.Fatalf("the port the device's walk names did not stand: %v %v %v", m.Addr["d"], m.AddrVRF["d"], m.Stats)
		}
		noIdx := []Row{{IfName: "eth2", Addrs: []string{"10.9.9.2"}}, {IfName: "ETH1", Addrs: []string{"10.9.9.2"}}}
		if rows[0].IfName == "Gi9" {
			noIdx[0], noIdx[1] = noIdx[1], noIdx[0]
		}
		st = nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.UnixMilli(), Rows: noIdx}})
		if got := Merge(SNMP{}, st, nil, nil).Addr["d"]["10.9.9.2"]; got != "ETH1" {
			t.Fatalf("name tie-break: %q", got)
		}
	}
	// One port listed twice under two spellings is ONE port: no multi-port count.
	st := nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.UnixMilli(), Rows: []Row{
		{IfIndex: "3", IfName: "GigabitEthernet3", Addrs: []string{"10.0.0.3"}},
		{IfName: "Gi3", VRF: "x", Addrs: []string{"10.0.0.3"}},
	}}})
	if n := Merge(SNMP{}, st, gi, nil).Stats[StatKey{SourceNMS, MergeMultiPort}]; n != 0 {
		t.Fatalf("one port under two spellings counted as multi-port: %d", n)
	}
}
