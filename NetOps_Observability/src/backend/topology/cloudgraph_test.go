// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// cloudgraph_test.go — #130a/b. The path graph reaches into the cloud, and says
// honestly when it cannot.
//
// Three claims are load-bearing and each has a test here: a cloud node IS a
// vertex (so the endpoint picker is not advertising a trace we cannot run); a
// trace that must cross an undiscovered seam reports NO SEAM rather than
// inventing the hop; and the on-prem inventory still wins every id collision.

import "testing"

func cloudNodeFact(id string) Node {
	return Node{ID: id, Label: id, Kind: KindCloud, Health: HealthUnknown, Confidence: 0.9,
		Resolved: true, Tags: map[string]string{"provider": "aws"},
		Evidence: []EvidenceRef{{Source: "cloud_api", Confidence: 0.9}}}
}

func cloudEdgeFact(id, src, dst string) Edge {
	return Edge{ID: id, Source: src, Target: dst, Relationship: RelConnectedTo,
		Protocol: "cloud_api", Confidence: 0.9,
		Evidence: []EvidenceRef{{Source: "cloud_api", Confidence: 0.9}}}
}

// The fabric: wan-edge — core. The cloud: subnet-app — vpn-1. The SEAM edge
// vpn-1 ↔ wan-edge is the discovered adjacency that joins them.
func seamPathInput(withSeam bool) Input {
	now := baseNow()
	in := Input{
		Mode: ModePathTrace, Now: now, SrcID: "core", DstID: "subnet-app",
		Devices:    []DeviceFact{{ID: "core", LastSeen: now}, {ID: "wan-edge", LastSeen: now}},
		Links:      []LinkFact{{Source: "core", Target: "wan-edge", Protocol: "lldp", Metric: 1, LastSeen: now}},
		CloudNodes: []Node{cloudNodeFact("subnet-app"), cloudNodeFact("vpn-1")},
		CloudEdges: []Edge{cloudEdgeFact("route-1", "subnet-app", "vpn-1")},
		CloudGroups: []Group{
			{ID: "vpc-a", Label: "VPC · prod", GroupType: "vpc", ParentID: "region:aws:us-west-2",
				Children: []string{"subnet-app"}, Health: HealthUnknown},
			{ID: "region:aws:us-west-2", Label: "aws · us-west-2", GroupType: "region",
				Children: []string{}, Health: HealthUnknown},
		},
	}
	if withSeam {
		in.CloudEdges = append(in.CloudEdges, cloudEdgeFact("seam-vpn_1-wan_edge", "vpn-1", "wan-edge"))
	}
	return in
}

func TestPathTraceCrossesADiscoveredSeam(t *testing.T) {
	v := Project(seamPathInput(true))
	want := []string{"core", "wan-edge", "vpn-1", "subnet-app"}
	if len(v.Path) != len(want) {
		t.Fatalf("path = %v, want %v", v.Path, want)
	}
	for i, h := range want {
		if v.Path[i] != h {
			t.Fatalf("hop %d = %q, want %q (path %v)", i, v.Path[i], h, v.Path)
		}
	}
	// The frozen contract's honesty state survives crossing the seam: this is
	// still an inference over the discovered graph, never a live trace.
	if v.PathSource != PathComputed {
		t.Fatalf("path_source = %q, want %q", v.PathSource, PathComputed)
	}
	if v.PathState != "" {
		t.Fatalf("a resolved path must carry no failure state, got %q", v.PathState)
	}
}

func TestPathTraceWithoutASeamIsAnHonestDistinctState(t *testing.T) {
	v := Project(seamPathInput(false))
	if len(v.Path) != 0 {
		t.Fatalf("no seam was discovered — no hop may be invented, got %v", v.Path)
	}
	if v.PathState != PathStateNoSeam {
		t.Fatalf("path_state = %q, want %q", v.PathState, PathStateNoSeam)
	}
	if v.PathSource != "" {
		t.Fatalf("no path → no provenance claim, got %q", v.PathSource)
	}
	// The cloud endpoint is still ON the canvas: the picker offers it, and the
	// answer is an honest refusal rather than a hidden control.
	if _, ok := findNode(v, "subnet-app"); !ok {
		t.Fatal("the cloud endpoint must stay on the canvas even when unreachable")
	}
}

func TestNoSeamStateOnlyClaimedWhenTheSeamIsTheReason(t *testing.T) {
	now := baseNow()
	// Both endpoints on-prem, simply disconnected: the plain no-route state.
	v := Project(Input{Mode: ModePathTrace, Now: now, SrcID: "a", DstID: "b",
		Devices:    []DeviceFact{{ID: "a", LastSeen: now}, {ID: "b", LastSeen: now}},
		CloudNodes: []Node{cloudNodeFact("subnet-app")},
	})
	if v.PathState != "" {
		t.Fatalf("an on-prem-to-on-prem miss is not a seam problem, got %q", v.PathState)
	}
	// A seam EXISTS but the two ends are still disconnected — also not a seam gap.
	v = Project(Input{Mode: ModePathTrace, Now: now, SrcID: "a", DstID: "subnet-b",
		Devices:    []DeviceFact{{ID: "a", LastSeen: now}, {ID: "wan-edge", LastSeen: now}},
		CloudNodes: []Node{cloudNodeFact("subnet-b"), cloudNodeFact("vpn-1")},
		CloudEdges: []Edge{cloudEdgeFact("seam-vpn_1-wan_edge", "vpn-1", "wan-edge")},
	})
	if v.PathState != "" {
		t.Fatalf("a discovered seam exists — the failure is a route gap, got %q", v.PathState)
	}
}

func TestCloudObjectsMergeUnderTheOnPremWinsRule(t *testing.T) {
	now := baseNow()
	v := Project(Input{Mode: ModeExplore, Now: now,
		Devices: []DeviceFact{{ID: "core", Name: "core-sw1", LastSeen: now}},
		CloudNodes: []Node{
			{ID: "core", Label: "not-your-device", Kind: KindCloud, Confidence: 0.9,
				Evidence: []EvidenceRef{{Source: "cloud_api", Confidence: 0.9}}},
			cloudNodeFact("subnet-app"),
		},
		// An edge to a node that did not come across is never drawn.
		CloudEdges: []Edge{cloudEdgeFact("route-x", "subnet-app", "gw-missing")},
		// A container whose parent did not come across is un-nested, not lost.
		CloudGroups: []Group{{ID: "vpc-a", Label: "VPC · prod", GroupType: "vpc",
			ParentID: "region-that-is-not-here", Children: []string{"subnet-app"}, Health: HealthUnknown}},
	})
	n, ok := findNode(v, "core")
	if !ok || n.Label != "core-sw1" {
		t.Fatalf("the on-prem inventory must win the id collision, got %+v", n)
	}
	for _, e := range v.Edges {
		if e.ID == "route-x" {
			t.Fatal("drew a cloud edge to a node that is not in the view")
		}
	}
	var vpc *Group
	for i := range v.Groups {
		if v.Groups[i].ID == "vpc-a" {
			vpc = &v.Groups[i]
		}
	}
	if vpc == nil {
		t.Fatal("lost the whole VPC rather than un-nesting it")
	}
	if vpc.ParentID != "" {
		t.Fatalf("dangling parent reference kept: %q", vpc.ParentID)
	}
}

func TestNoCloudObjectsIsTheIdentityPath(t *testing.T) {
	now := baseNow()
	in := Input{Mode: ModeExplore, Now: now, Devices: []DeviceFact{{ID: "core", LastSeen: now}}}
	v := Project(in)
	if len(v.Nodes) != 1 || v.Nodes[0].ID != "core" {
		t.Fatalf("a tenant with no cloud slice must get exactly its fabric, got %+v", v.Nodes)
	}
	if v.PathState != "" {
		t.Fatalf("no path state outside path_trace, got %q", v.PathState)
	}
}
