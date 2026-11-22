// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"sort"
	"strings"
	"testing"
)

// gi is a small canonical port key for the tests ("Gi1" ≡ "GigabitEthernet1").
func gi(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "gigabitethernet") {
		return "gi" + strings.TrimPrefix(s, "gigabitethernet")
	}
	return s
}

func confirmedOf(d DeviceFacts) (confirmed, possible []string) {
	for _, v := range Classify(d) {
		switch v.Confidence {
		case Confirmed:
			confirmed = append(confirmed, v.Interface)
		case Possible:
			possible = append(possible, v.Interface)
		}
	}
	sort.Strings(confirmed)
	sort.Strings(possible)
	return
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The lab, from the recorded vManage 20.6 interface payloads
// (nms/testdata/vmanage_20.6) and the stored cedge-81 rows: vEdge names its
// transport ports; cEdge does not, but its SD-WAN tunnels ride their address.
func TestLabEdgesUnderTheRule(t *testing.T) {
	vedge20 := DeviceInputs{DeviceID: "vedge-20-02efdcad", Name: "vedge-20", Candidate: true, Rows: []IfRow{
		{Name: "ge0/0", VRF: "0", Role: "transport", Addrs: []string{"200.20.2.20"}},
		{Name: "ge0/2", VRF: "0", Role: "transport", Addrs: []string{"192.1.5.1"}},
		{Name: "system", VRF: "0", Role: "loopback", Addrs: []string{"10.255.255.20"}},
		{Name: "ge0/1", VRF: "100", Role: "service", Addrs: []string{"192.168.100.25"}},
		{Name: "ge0/3", VRF: "200", Role: "service", Addrs: []string{"192.168.172.2"}},
		{Name: "loopback200", VRF: "200", Role: "service", Addrs: []string{"192.168.222.104"}},
		{Name: "eth0", VRF: "512", Role: "service", Alias: "OOB"},
	}}
	c, p := confirmedOf(BuildFacts(vedge20, gi))
	if !same(c, []string{"ge0/0", "ge0/2"}) || len(p) != 0 {
		t.Errorf("vedge-20: confirmed %v possible %v, want [ge0/0 ge0/2] and none", c, p)
	}

	cedge40 := DeviceInputs{DeviceID: "cedge-40-fdf7b64f", Name: "cedge-40", Candidate: true, Rows: []IfRow{
		{Name: "GigabitEthernet1", VRF: "0", Kind: "ethernet", Addrs: []string{"200.40.1.40"}},
		{Name: "GigabitEthernet2", VRF: "0", Kind: "ethernet", Addrs: []string{"172.16.40.40"}},
		{Name: "GigabitEthernet3", VRF: "200", Kind: "ethernet", Addrs: []string{"192.168.172.3"}},
		{Name: "GigabitEthernet4", VRF: "100", Kind: "ethernet", Addrs: []string{"192.168.100.49"}},
		{Name: "Loopback200", VRF: "200", Kind: "loopback", Addrs: []string{"192.168.222.107"}},
		{Name: "NVI0", VRF: "0", Kind: "other"},
		{Name: "Sdwan-system-intf", VRF: "0", Kind: "loopback", Addrs: []string{"10.255.255.40"}},
		{Name: "Tunnel1", VRF: "0", Kind: "tunnel", Addrs: []string{"200.40.1.40"}},
		{Name: "Tunnel2", VRF: "0", Kind: "tunnel", Addrs: []string{"172.16.40.40"}},
	},
		// SNMP spells the port its own way; the merged bridge's spelling is shown.
		AddrIf: map[string]string{"200.40.1.40": "Gi1", "192.168.172.3": "Gi3"},
	}
	c, p = confirmedOf(BuildFacts(cedge40, gi))
	if !same(c, []string{"Gi1", "GigabitEthernet2"}) || len(p) != 0 {
		t.Errorf("cedge-40: confirmed %v possible %v, want [Gi1 GigabitEthernet2] (the bridge's spelling) and none", c, p)
	}

	// cedge-81: one transport port with a tunnel, two VPN 0 sub-interfaces without.
	cedge81 := DeviceInputs{DeviceID: "cedge-81-dde8d64d", Name: "cedge-81", Candidate: true, Rows: []IfRow{
		{Name: "GigabitEthernet2", VRF: "0", Addrs: []string{"192.1.6.2"}},
		{Name: "GigabitEthernet4.100", VRF: "0", Addrs: []string{"12.12.12.2"}},
		{Name: "GigabitEthernet4.200", VRF: "0", Addrs: []string{"14.14.14.2"}},
		{Name: "Sdwan-system-intf", VRF: "0", Addrs: []string{"10.255.255.81"}},
		{Name: "GigabitEthernet1", VRF: "100", Addrs: []string{"192.168.100.33"}},
		{Name: "GigabitEthernet3", VRF: "200", Addrs: []string{"192.168.200.33"}},
		{Name: "Loopback200", VRF: "200", Addrs: []string{"192.168.222.106"}},
		{Name: "Tunnel2", VRF: "0", Addrs: []string{"192.1.6.2"}},
	}}
	c, p = confirmedOf(BuildFacts(cedge81, gi))
	if !same(c, []string{"GigabitEthernet2"}) || !same(p, []string{"GigabitEthernet4.100", "GigabitEthernet4.200"}) {
		t.Errorf("cedge-81: confirmed %v possible %v, want [GigabitEthernet2] / [Gi4.100 Gi4.200]", c, p)
	}
}

func TestBuildFactsTLOCByNameAndAddressButNeverATunnelByAddress(t *testing.T) {
	f := BuildFacts(DeviceInputs{
		AddrIf:     map[string]string{"200.1.1.1": "ge0/0", "200.2.2.2": "ge0/1", "200.2.2.3": "Tunnel5"},
		TLOCIfaces: []string{"GE0/0"},
		TLOCAddrs:  []string{"200.2.2.2", "200.2.2.3"},
	}, nil)
	by := map[string]IfFacts{}
	for _, i := range f.Ifaces {
		by[i.Name] = i
	}
	if !by["ge0/0"].InTLOC || !by["ge0/1"].InTLOC {
		t.Fatalf("TLOC by name and by address: %+v", by)
	}
	if by["Tunnel5"].InTLOC {
		t.Fatal("a tunnel interface carrying a TLOC address is not the transport port")
	}
	if !f.SDWAN {
		t.Fatal("TLOC facts make the device SD-WAN")
	}
}

func TestBuildFactsNextHopMarksAndLinks(t *testing.T) {
	f := BuildFacts(DeviceInputs{
		DeviceID: "r1-abc", Name: "r1",
		AddrIf: map[string]string{"10.0.0.1": "Gi1", "10.0.0.2": "Gi2", "10.0.0.3": "Gi3", "10.0.0.4": "Gi4"},
		// The editor asks for the device by name; keys by id still work.
		NextHops: map[string]string{"r1/Gi1": "203.0.113.1", "r1-abc/Gi2": "203.0.113.2", "r1": "203.0.113.9"},
		Marks:    map[string]string{"GigabitEthernet3": MarkNotWAN, "Gi4": "maybe"},
		Linked:   map[string]string{"gigabitethernet4": "wan-r9"},
	}, gi)
	by := map[string]IfFacts{}
	for _, i := range f.Ifaces {
		by[i.Name] = i
	}
	if by["Gi1"].NextHop != "203.0.113.1" || by["Gi2"].NextHop != "203.0.113.2" {
		t.Fatalf("per-port next-hops: %+v", by)
	}
	if by["Gi3"].NextHop != "" {
		t.Fatal("a device-wide next-hop does not say which port is WAN")
	}
	if by["Gi3"].Mark != MarkNotWAN || by["Gi4"].Mark != "" {
		t.Fatalf("marks: only the closed set, matched canonically: %+v", by)
	}
	if by["Gi4"].Linked != "wan-r9" {
		t.Fatalf("linked, matched canonically: %+v", by["Gi4"])
	}
}
