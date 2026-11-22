// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"strings"
	"testing"
)

func verdicts(d DeviceFacts) map[string]Verdict {
	out := map[string]Verdict{}
	for _, v := range Classify(d) {
		out[v.Interface] = v
	}
	return out
}

func want(t *testing.T, got map[string]Verdict, ifn, conf string, basis Basis) {
	t.Helper()
	v, ok := got[ifn]
	if !ok {
		t.Fatalf("%s: no verdict", ifn)
	}
	if v.Confidence != conf || v.Basis != basis {
		t.Errorf("%s: %q/%q, want %q/%q (reason %q)", ifn, v.Confidence, v.Basis, conf, basis, v.Reason)
	}
	if conf != "" && (v.Reason == "" || len(v.Evidence) == 0) {
		t.Errorf("%s: a WAN verdict must say why: %+v", ifn, v)
	}
	if conf == "" && (v.Reason != "" || v.Basis != "") {
		t.Errorf("%s: a not-WAN verdict carries a reason: %+v", ifn, v)
	}
}

// One case per basis and per exclusion.
func TestClassifyEveryBasisAndExclusion(t *testing.T) {
	d := DeviceFacts{Candidate: true, SDWAN: true, Ifaces: []IfFacts{
		{Name: "ge0/0", VRF: "0", Role: "transport", Addrs: []string{"200.20.2.20"}},
		{Name: "ge0/5", VRF: "0", InTLOC: true, Addrs: []string{"10.5.5.5"}},
		{Name: "GigabitEthernet1", VRF: "0", TunnelOver: "Tunnel1", Addrs: []string{"200.40.1.40"}},
		{Name: "ge0/6", NextHop: "203.0.113.1", Addrs: []string{"192.0.2.6"}},
		{Name: "ge0/7", Mark: MarkWAN, VRF: "100", Addrs: []string{"192.168.7.1"}},
		{Name: "ge0/8", Mark: MarkNotWAN, VRF: "0", Role: "transport", Addrs: []string{"200.8.8.8"}},
		{Name: "Gi4.100", VRF: "0", Addrs: []string{"12.12.12.1"}},
		{Name: "ge0/1", VRF: "100", Role: "service", Addrs: []string{"192.168.100.25"}},
		{Name: "eth0", VRF: "512", Addrs: []string{"10.70.1.1"}},
		{Name: "system", VRF: "0", Role: "loopback", Addrs: []string{"10.255.255.20"}},
		{Name: "Tunnel1", VRF: "0", Kind: "tunnel", Addrs: []string{"200.40.1.40"}},
		{Name: "Loopback200", VRF: "200", Kind: "loopback", Addrs: []string{"192.168.222.107"}},
		{Name: "NVI0", VRF: "0", Kind: "other", Addrs: []string{"10.1.1.1"}},
		{Name: "mgmt0", Addrs: []string{"10.70.1.2"}},
	}}
	got := verdicts(d)
	want(t, got, "ge0/0", Confirmed, BasisSDWANTransport)
	want(t, got, "ge0/5", Confirmed, BasisSDWANTLOC)
	want(t, got, "GigabitEthernet1", Confirmed, BasisSDWANTunnelSource)
	if !strings.Contains(got["GigabitEthernet1"].Reason, "Tunnel1") {
		t.Errorf("the tunnel-source reason names the tunnel: %q", got["GigabitEthernet1"].Reason)
	}
	want(t, got, "ge0/6", Confirmed, BasisDeclaredNextHop)
	want(t, got, "ge0/7", Confirmed, BasisOperator)
	want(t, got, "ge0/8", "", "")
	want(t, got, "Gi4.100", Possible, BasisTransportNoTunnel)
	for _, ifn := range []string{"ge0/1", "eth0", "system", "Tunnel1", "Loopback200", "NVI0", "mgmt0"} {
		want(t, got, ifn, "", "")
	}
}

// Rule order: the operator wins both ways; management loses to nothing but the
// operator; positive evidence beats the loopback exclusion.
func TestClassifyPrecedence(t *testing.T) {
	got := verdicts(DeviceFacts{SDWAN: true, Ifaces: []IfFacts{
		// A TLOC bound to a loopback is still WAN.
		{Name: "loopback1", InTLOC: true, VRF: "0", Addrs: []string{"203.0.113.9"}},
		// A management port the controller calls transport is still not WAN…
		{Name: "Management1", Role: "transport", VRF: "0", Addrs: []string{"203.0.113.10"}},
		// …unless an operator says so.
		{Name: "mgmt1", Mark: MarkWAN, Addrs: []string{"203.0.113.11"}},
		// SD-WAN VPN 512 is management even with a WAN word in its description.
		{Name: "ge0/9", VRF: "512", Alias: "internet uplink", Addrs: []string{"203.0.113.12"}},
	}})
	want(t, got, "loopback1", Confirmed, BasisSDWANTLOC)
	want(t, got, "Management1", "", "")
	want(t, got, "mgmt1", Confirmed, BasisOperator)
	want(t, got, "ge0/9", "", "")
}

func TestClassifyPossibleKinds(t *testing.T) {
	// Not an SD-WAN device: VPN numbers mean nothing, VRF excludes nothing.
	got := verdicts(DeviceFacts{Candidate: true, Ifaces: []IfFacts{
		{Name: "Ethernet1", Alias: "To ISP-A (internet)", VRF: "INET", Addrs: []string{"10.9.9.1"}},
		{Name: "Ethernet2", Addrs: []string{"198.51.100.2"}}, // public, on a candidate
		{Name: "Ethernet3", Addrs: []string{"10.0.0.3"}},
		{Name: "Ethernet4", Alias: "server rack 4", Addrs: []string{"10.0.0.4"}},
	}})
	want(t, got, "Ethernet1", Possible, BasisDescribedAsWAN)
	want(t, got, "Ethernet2", Possible, BasisPublicAddress)
	// Nothing confirmed on a candidate: its remaining addressed ports are offered.
	want(t, got, "Ethernet3", Possible, BasisCandidateRouterOnly)
	want(t, got, "Ethernet4", Possible, BasisCandidateRouterOnly)

	// A description word is possible, never confirmed — "to WAN-RTR" on a LAN
	// port is the false positive that rules it out.
	got = verdicts(DeviceFacts{Ifaces: []IfFacts{{Name: "Gi0/1", Alias: "to WAN-RTR", Addrs: []string{"10.1.1.1"}}}})
	want(t, got, "Gi0/1", Possible, BasisDescribedAsWAN)

	// Linked: the port facing a WAN router, on a device that is not one.
	got = verdicts(DeviceFacts{Ifaces: []IfFacts{
		{Name: "Eth3", Linked: "wan-r2", Addrs: []string{"10.0.0.2"}},
		{Name: "Eth1", Addrs: []string{"10.1.0.1"}},
	}})
	want(t, got, "Eth3", Possible, BasisLinked)
	want(t, got, "Eth1", "", "")
}

// Once anything on a candidate is confirmed, the rest is not offered wholesale:
// the confirmed port answered the question.
func TestClassifyCandidateFallbackOnlyWhenNothingIsConfirmed(t *testing.T) {
	got := verdicts(DeviceFacts{Candidate: true, Ifaces: []IfFacts{
		{Name: "Ethernet1", NextHop: "203.0.113.1", Addrs: []string{"192.0.2.1"}},
		{Name: "Ethernet2", Addrs: []string{"10.0.0.2"}},
		{Name: "Ethernet3"}, // no address: never offered
	}})
	want(t, got, "Ethernet1", Confirmed, BasisDeclaredNextHop)
	want(t, got, "Ethernet2", "", "")
	want(t, got, "Ethernet3", "", "")

	// Not a candidate and no evidence: nothing at all.
	got = verdicts(DeviceFacts{Ifaces: []IfFacts{{Name: "Ethernet2", Addrs: []string{"198.51.100.2"}}}})
	want(t, got, "Ethernet2", "", "")
}

// Interface names from every vendor the platform supports, with no controller
// facts: only management and loopback-like names are excluded by name, and no
// name alone ever confirms.
func TestClassifyMultiVendorNamesWithoutEvidence(t *testing.T) {
	excludedByName := []string{
		"Loopback0", "lo0.0", "lo0", "system", "Null0", "NVI0", "Sdwan-system-intf", // IOS-XE, Junos, SR OS
		"fxp0", "em0", "me0", "ma1", "Management1", "mgmt0", // Junos, EOS, NX-OS
		"Tunnel10", "gr-0/0/0", "ip-0/0/0", "st0.1", // tunnels
	}
	ports := []string{"GigabitEthernet0/0/0", "ge-0/0/0.0", "1/1/1", "Ethernet1/1", "Ethernet0", "eth0"}
	var ifs []IfFacts
	for _, n := range append(append([]string{}, excludedByName...), ports...) {
		ifs = append(ifs, IfFacts{Name: n, Addrs: []string{"10.0.0.1"}})
	}
	got := verdicts(DeviceFacts{Candidate: true, Ifaces: ifs})
	for _, n := range excludedByName {
		want(t, got, n, "", "")
	}
	for _, n := range ports {
		// SONiC eth0 is its management port, EOS/SONiC Ethernet0 a data port; with
		// no evidence either way both are only offered, never confirmed.
		want(t, got, n, Possible, BasisCandidateRouterOnly)
	}
}

func TestClassifyIsDeterministic(t *testing.T) {
	d := DeviceFacts{Candidate: true, Ifaces: []IfFacts{
		{Name: "b", Addrs: []string{"10.0.0.2"}}, {Name: "a", Addrs: []string{"10.0.0.1"}}, {Name: "c", Role: "transport", Addrs: []string{"200.1.1.1"}},
	}}
	first := Classify(d)
	for i := 0; i < 20; i++ {
		again := Classify(d)
		for j := range first {
			if first[j].Interface != again[j].Interface || first[j].Basis != again[j].Basis {
				t.Fatalf("run %d differs: %+v vs %+v", i, first, again)
			}
		}
	}
	if first[0].Interface != "a" || first[2].Interface != "c" {
		t.Fatalf("not sorted by name: %+v", first)
	}
}
