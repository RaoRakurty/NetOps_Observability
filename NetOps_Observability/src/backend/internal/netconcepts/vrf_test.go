// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package netconcepts

import "testing"

func TestIsVRFTermAcrossDialects(t *testing.T) {
	yes := []string{
		"vrf", "VRF", "VRF-Lite",
		"routing-instance", "routing_instance", "Routing-Instance",
		"VPRN", "vprn",
		"VPN instance", "vpn-instance",
		"network-instance", "L3VPN",
	}
	for _, term := range yes {
		if !IsVRFTerm(term) {
			t.Errorf("IsVRFTerm(%q) = false, want true", term)
		}
	}
	no := []string{"", "vlan", "vxlan", "vsys", "zone", "bridge-domain", "instance"}
	for _, term := range no {
		if IsVRFTerm(term) {
			t.Errorf("IsVRFTerm(%q) = true, want false — over-matching merges DISTINCT concepts", term)
		}
	}
}

func TestVRFDisplayTermPerVendor(t *testing.T) {
	cases := map[string]string{
		"cisco": "VRF", "IOS-XR": "VRF", "arista": "VRF", "eos": "VRF", "": "VRF",
		"juniper": "routing-instance", "JunOS": "routing-instance",
		"nokia": "VPRN", "SR Linux": "VPRN", "sros": "VPRN",
		"huawei": "VPN instance",
	}
	for vendor, want := range cases {
		if got := VRFDisplayTerm(vendor); got != want {
			t.Errorf("VRFDisplayTerm(%q) = %q, want %q", vendor, got, want)
		}
	}
}

func TestVRFEntityTokenIsDialectFree(t *testing.T) {
	// The whole point: different dialects, same identity.
	a := VRFEntityToken("Edge-R1", "CORP-WAN") // from a cisco syslog "vrf CORP-WAN"
	b := VRFEntityToken("edge-r1", "CORP-WAN") // from juniper "routing-instance CORP-WAN"
	if a != b {
		t.Fatalf("dialects diverged: %q vs %q", a, b)
	}
	if a != "vrf:edge-r1:CORP-WAN" {
		t.Fatalf("token = %q", a)
	}
	// Instance names are operator identifiers — case must be preserved
	// (CORP-WAN and corp-wan may be two real instances on one box).
	if VRFEntityToken("r1", "corp-wan") == VRFEntityToken("r1", "CORP-WAN") {
		t.Fatal("instance-name case must be preserved")
	}
}
