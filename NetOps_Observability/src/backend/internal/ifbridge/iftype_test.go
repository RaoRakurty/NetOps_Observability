// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import "testing"

// Tracker 436 (c): IF-MIB ifType reaches the bridge, so the WAN rule can read
// the medium of a port on a router no controller describes. Only what the IANA
// number states for certain is mapped; everything else says nothing.

func TestIfTypeKindIsAClosedSetFromTheIANANumber(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{
		// LAN media: every vendor's Ethernet ports.
		{6, KindEthernet}, {62, KindEthernet}, {69, KindEthernet}, {117, KindEthernet},
		// Not a port of the managed network's edge.
		{24, KindLoopback}, {131, KindTunnel}, {150, KindTunnel},
		// Media that only ever carry a WAN or access circuit: serial/HDLC/PPP,
		// Frame Relay, ATM, T1/E1/T3, SONET, ISDN, the DSL family, DOCSIS cable,
		// cellular (wwanPP / wwanPP2).
		{18, KindWANMedia}, {19, KindWANMedia}, {20, KindWANMedia}, {21, KindWANMedia},
		{22, KindWANMedia}, {23, KindWANMedia}, {30, KindWANMedia}, {32, KindWANMedia},
		{37, KindWANMedia}, {39, KindWANMedia}, {63, KindWANMedia}, {94, KindWANMedia},
		{95, KindWANMedia}, {96, KindWANMedia}, {97, KindWANMedia}, {118, KindWANMedia},
		{127, KindWANMedia}, {169, KindWANMedia}, {230, KindWANMedia}, {238, KindWANMedia},
		{243, KindWANMedia}, {244, KindWANMedia}, {251, KindWANMedia},
		// No statement: other(1), propVirtual(53), l2vlan(135), l3ipvlan(136),
		// ieee8023adLag(161), bridge(209), and anything unknown or out of range.
		{1, ""}, {53, ""}, {135, ""}, {136, ""}, {161, ""}, {209, ""}, {0, ""}, {-1, ""}, {100000, ""},
	} {
		if got := IfTypeKind(c.n); got != c.want {
			t.Errorf("IfTypeKind(%d) = %q, want %q", c.n, got, c.want)
		}
	}
	if IfTypeName(23) != "ppp" || IfTypeName(243) != "wwanPP" || IfTypeName(131) != "tunnel" || IfTypeName(999) != "" {
		t.Fatalf("IfTypeName: %q %q %q %q", IfTypeName(23), IfTypeName(243), IfTypeName(131), IfTypeName(999))
	}
}

func TestCleanKindNamesWANMediaFromAController(t *testing.T) {
	// cEdge reports the IANA ifType NAME as `interface-type`.
	for in, want := range map[string]string{
		"iana-iftype-ppp": KindWANMedia, "iana-iftype-prop-point-to-point-serial": KindWANMedia,
		"propPointToPointSerial": KindWANMedia, "iana-iftype-frame-relay": KindWANMedia,
		"iana-iftype-ds1": KindWANMedia, "iana-iftype-adsl": KindWANMedia, "vdsl2": KindWANMedia,
		"iana-iftype-wwanpp": KindWANMedia, "iana-iftype-hdlc": KindWANMedia,
		"iana-iftype-mpls-tunnel": KindTunnel, "iana-iftype-l2vlan": "",
	} {
		if got := CleanKind(in); got != want {
			t.Errorf("CleanKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIfType(t *testing.T) {
	for in, want := range map[string]int{"23": 23, " 6 ": 6, "0": 0, "": 0, "-3": 0, "x": 0, "99999999999": 0} {
		if got := ParseIfType(in); got != want {
			t.Errorf("ParseIfType(%q) = %d, want %d", in, got, want)
		}
	}
}

// The SNMP ifType map lands in the merged view keyed by ifIndex, as the closed
// kind and as the validated number; junk says nothing.
func TestMergeCarriesTheSNMPIfType(t *testing.T) {
	snmp := SNMP{
		Index: map[string]map[string]string{"r1": {"1": "Serial0/0/0", "2": "GigabitEthernet0/1", "3": "Tunnel0", "4": "Dialer1", "5": "Vlan10"}},
		Type:  map[string]map[string]string{"r1": {"1": "22", "2": "6", "3": "131", "4": "23", "5": "136", "6": "junk"}},
	}
	m := Merge(snmp, NewState(), nil, nil)
	want := map[string]string{"1": KindWANMedia, "2": KindEthernet, "3": KindTunnel, "4": KindWANMedia}
	if len(m.Kind["r1"]) != len(want) {
		t.Fatalf("kinds %v, want %v", m.Kind["r1"], want)
	}
	for idx, k := range want {
		if m.Kind["r1"][idx] != k {
			t.Errorf("ifIndex %s: kind %q, want %q", idx, m.Kind["r1"][idx], k)
		}
	}
	if m.IfType["r1"]["1"] != 22 || m.IfType["r1"]["5"] != 136 || m.IfType["r1"]["6"] != 0 {
		t.Fatalf("numbers %v", m.IfType["r1"])
	}
}

// Tracker 437 meets 436: a controller that states no kind for two ports sharing
// an address, neither named like a tunnel, is told apart by the device's own
// IF-MIB ifType for those ports — the tunnel(131) port never owns the address.
func TestMergeSharedAddressUsesTheSNMPIfTypeWhenTheControllerStatesNone(t *testing.T) {
	snmp := SNMP{
		Index: map[string]map[string]string{"d": {"1": "to-isp", "9": "wan-ipsec"}},
		Type:  map[string]map[string]string{"d": {"1": "6", "9": "131"}},
	}
	// Without the ifType the tunnel row would win: its controller ifIndex (2) is
	// the lowest, and neither name matches the tunnel spelling.
	tun := Row{IfIndex: "2", IfName: "wan-ipsec", VRF: "0", Addrs: []string{"198.51.100.7"}}
	port := Row{IfIndex: "5", IfName: "to-isp", VRF: "0", Addrs: []string{"198.51.100.7"}}
	for _, rows := range [][]Row{{tun, port}, {port, tun}} {
		st := nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.UnixMilli(), Rows: rows}})
		m := Merge(snmp, st, nil, nil)
		if got := m.Addr["d"]["198.51.100.7"]; got != "to-isp" {
			t.Fatalf("rows %s,%s: address names %q, want to-isp (the SNMP ifType says wan-ipsec is a tunnel)", rows[0].IfName, rows[1].IfName, got)
		}
	}
}
