// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_roles_test.go — the role-fact gathering + spine stamping glue
// (device_roles.go). Pure-function tests with mock facts; the §3a isolation
// property under test: a spine hop can only ever be stamped from the index the
// caller's visible-device set produced — a device outside that set never
// stamps, so roles cannot leak the existence of another tenant's device.

import (
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/pathgraph"
	"netops/backend/topology"
)

func TestAdjacencySummaries(t *testing.T) {
	typeByID := map[string]string{"a": "switch", "b": "router", "c": "switch"}
	links := []topoLink{
		{Source: "a", Target: "b", Resolved: true, SourceProto: "lldp"},
		{Source: "a", Target: "c", Resolved: true, SourceProto: "lldp+bgp_ls", IGP: "isis-l2"},
		{Source: "b", Target: "ext:isp-gw", Resolved: false, SourceProto: "cdp"}, // unresolved: total only
	}
	adj := adjacencySummaries(links, typeByID)

	a := adj["a"]
	if a == nil || a.total != 2 || a.switches != 1 || a.routers != 1 || !a.igp {
		t.Fatalf("a: got %+v", a)
	}
	b := adj["b"]
	if b == nil || b.total != 2 || b.switches != 1 {
		t.Fatalf("b: got %+v", b)
	}
	c := adj["c"]
	if c == nil || c.total != 1 || c.switches != 1 || !c.igp {
		t.Fatalf("c: got %+v", c)
	}
	if adj["ext:isp-gw"] != nil {
		t.Fatalf("unresolved neighbour must not accumulate a summary")
	}
}

func TestToDeviceFactsCarriesRoleFacts(t *testing.T) {
	devs := []models.Device{
		{ID: "sw1", Name: "flr1-sw1", Vendor: "Cisco", Model: "WS-C2960", OS: "Cisco IOS, C2960 Software", LastSeen: time.Now()},
		{ID: "r1", Name: "core-r1", Vendor: "Cisco", Model: "ASR1001", LastSeen: time.Now()},
	}
	links := []topoLink{{Source: "sw1", Target: "r1", Resolved: true, SourceProto: "bgp_ls", IGP: "ospfv2"}}
	facts := toDeviceFacts(devs, nil, nil, links, nil)
	if len(facts) != 2 {
		t.Fatalf("want 2 facts, got %d", len(facts))
	}
	sw := facts[0]
	if sw.SysDescr == "" || !sw.HasIGPAdjacency || sw.NeighborCount != 1 || sw.RouterNeighborCount != 1 {
		t.Fatalf("switch fact: %+v", sw)
	}
}

func TestStampSpineRolesResolvesByRefAddressAndLabel(t *testing.T) {
	idx := map[string]topology.RoleResult{
		"dev-1":      {Role: topology.DevRoleWANEdge, Confidence: topology.RoleConfStrong},
		"10.0.0.9":   {Role: topology.DevRoleCoreRouter, Confidence: topology.RoleConfMedium},
		"dc1-leaf03": {Role: topology.DevRoleDCLeaf, Confidence: topology.RoleConfMedium},
	}
	spine := []pathgraph.SpineNode{
		{Index: 0, EntityRef: "dev-1", Label: "br1-cpe"},  // by entity ref
		{Index: 1, Address: "10.0.0.9", Label: "unnamed"}, // by address
		{Index: 2, Label: "DC1-LEAF03"},                   // by (case-folded) label
		{Index: 3, Address: "8.8.8.8", Label: "transit"},  // no resolution → untouched
	}
	stampSpineRoles(spine, idx)
	if spine[0].DeviceRole != topology.DevRoleWANEdge || spine[0].RoleConfidence != "strong" {
		t.Fatalf("hop0: %+v", spine[0])
	}
	if spine[1].DeviceRole != topology.DevRoleCoreRouter {
		t.Fatalf("hop1: %+v", spine[1])
	}
	if spine[2].DeviceRole != topology.DevRoleDCLeaf {
		t.Fatalf("hop2: %+v", spine[2])
	}
	if spine[3].DeviceRole != "" || spine[3].RoleConfidence != "" {
		t.Fatalf("unresolved hop must stay role-less: %+v", spine[3])
	}
}

func TestSpineRolesNeverStampFromOutsideTheVisibleIndex(t *testing.T) {
	// §3a: the index IS the isolation boundary — it is built from the caller's
	// visible devices only (deviceRoleIndex). A hop whose address belongs to a
	// device NOT in the index (another tenant's) must remain role-less, even
	// when its label "looks like" a classified name.
	otherTenantAddr := "10.99.0.1"
	idx := map[string]topology.RoleResult{
		"10.1.0.1": {Role: topology.DevRoleWANEdge, Confidence: topology.RoleConfStrong},
	}
	spine := []pathgraph.SpineNode{
		{Index: 0, Address: otherTenantAddr, Label: "t2-wan-edge"},
	}
	stampSpineRoles(spine, idx)
	if spine[0].DeviceRole != "" {
		t.Fatalf("cross-tenant hop must not be stamped: %+v", spine[0])
	}
}

// Tracker 349: the WAN-edge flavor facts reach the classifier through the one
// fact builder every caller uses (view, role index, reconcile).
func TestToDeviceFactsCarriesWANFlavorFacts(t *testing.T) {
	devs := []models.Device{
		{ID: "cedge-1", Name: "cEDGE-1", Vendor: "cisco"},
		{ID: "ce-2", Name: "branch-ce-2", Labels: map[string]string{"site_kind": "branch"}},
		{ID: "dc-border", Name: "dc1-border"},
		{ID: "leaf-1", Name: "dc1-leaf01"},
	}
	links := []topoLink{{Source: "dc-border", Target: "leaf-1", Resolved: true}}
	wan := &wanFacts{
		ifNames:     map[string][]string{"cedge-1": {"Gi1", "Sdwan-intf"}},
		externalBGP: map[string]int{"ce-2": 1, "dc-border": 2},
	}
	byID := map[string]topology.DeviceFact{}
	for _, f := range toDeviceFacts(devs, nil, nil, links, wan) {
		byID[f.ID] = f
	}
	if f := byID["cedge-1"]; len(f.IfNames) != 2 {
		t.Fatalf("interface names not carried: %+v", f)
	}
	if f := byID["ce-2"]; f.ExternalBGPPeers != 1 || f.SiteKind != "branch" {
		t.Fatalf("external BGP / site kind not carried: %+v", f)
	}
	if f := byID["dc-border"]; f.FabricNeighborCount != 1 {
		t.Fatalf("fabric neighbors not counted: %+v", f)
	}
	if r := topology.ClassifyDeviceRole(byID["cedge-1"]); r.WANFlavor != topology.WANFlavorSDWAN {
		t.Fatalf("cEdge: %+v", r)
	}
	// A nil wan argument (callers without the inputs) leaves the facts zero.
	for _, f := range toDeviceFacts(devs, nil, nil, nil, nil) {
		if len(f.IfNames) != 0 || f.ExternalBGPPeers != 0 || f.FabricNeighborCount != 0 {
			t.Fatalf("nil inputs must leave the facts zero: %+v", f)
		}
	}
}
