// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"reflect"
	"testing"
)

func TestExternalBGPPeerCountsSubtractTheTenantsOwnAddresses(t *testing.T) {
	got := ExternalBGPPeerCounts(BGPPeerInputs{
		DevTenant: map[string]string{"ce1": "a", "core": "a"},
		DevAddrs:  map[string][]string{"ce1": {"10.0.0.1"}, "core": {"10.0.0.2", "192.0.2.9/30"}},
		Peers: map[string][]string{
			// ISP peer, an internal iBGP peer (core's interface IP), and a duplicate.
			"ce1":  {"203.0.113.1", "192.0.2.9", "203.0.113.1"},
			"core": {"10.0.0.1"},
		},
	})
	if !reflect.DeepEqual(got, map[string]int{"ce1": 1}) {
		t.Fatalf("got %v, want only ce1's ISP peer counted", got)
	}
}

// §3a: another tenant's inventory must never change this tenant's facts. Tenant
// B owns the address tenant A's router peers with; for A it is still external.
func TestExternalBGPPeerCountsAreTenantScoped(t *testing.T) {
	in := BGPPeerInputs{
		DevTenant: map[string]string{"a-ce": "tenant-a", "b-pe": "tenant-b"},
		DevAddrs:  map[string][]string{"a-ce": {"10.1.0.1"}, "b-pe": {"198.51.100.7"}},
		Peers:     map[string][]string{"a-ce": {"198.51.100.7"}},
	}
	if got := ExternalBGPPeerCounts(in)["a-ce"]; got != 1 {
		t.Fatalf("tenant B's device made tenant A's peer look internal: count %d", got)
	}
	// And the classification it feeds: A's router is a routed WAN edge.
	r := ClassifyDeviceRole(DeviceFact{ID: "a-ce", Type: "router", ExternalBGPPeers: ExternalBGPPeerCounts(in)["a-ce"]})
	if r.Role != DevRoleWANEdge || r.WANFlavor != WANFlavorRouted {
		t.Fatalf("classification: %+v", r)
	}
}

func TestFabricNeighborCounts(t *testing.T) {
	facts := []DeviceFact{
		{ID: "leaf1", Name: "dc1-leaf01", Type: "switch"},
		{ID: "spine1", Name: "dc1-spine01", Type: "switch"},
		{ID: "border", Name: "dc1-border", Type: "router"},
		{ID: "branch", Name: "br-7", Type: "router"},
	}
	links := []TopoLink{
		{Source: "border", Target: "leaf1", Resolved: true},
		{Source: "border", Target: "spine1", Resolved: true},
		{Source: "spine1", Target: "border", Resolved: true}, // the same adjacency seen from the other end
		{Source: "branch", Target: "ext:isp-pe", Resolved: false},
	}
	got := FabricNeighborCounts(facts, links)
	if got["border"] != 2 || got["branch"] != 0 {
		t.Fatalf("got %v, want border=2 branch=0", got)
	}
	// Feeds the DC classification of a routed border.
	r := ClassifyDeviceRole(DeviceFact{ID: "border", Type: "router", ExternalBGPPeers: 1, FabricNeighborCount: got["border"]})
	if r.Role != DevRoleDCWANEdge {
		t.Fatalf("border: %+v", r)
	}
}

func TestSortedIfNames(t *testing.T) {
	if got := SortedIfNames(map[string]string{"3": "Sdwan-intf", "1": "Gi1", "2": " ", "4": "Tu1"}); !reflect.DeepEqual(got, []string{"Gi1", "Sdwan-intf", "Tu1"}) {
		t.Fatalf("got %v", got)
	}
}
