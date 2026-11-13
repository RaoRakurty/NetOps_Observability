// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"fmt"
	"strings"
	"testing"
)

// A campus: core-1 joins two distribution switches; access-1 hangs off dist-1
// only. core-1 and dist-1 are cut vertices; the dist-1↔access-1 link is a bridge.
func campusView() View {
	return View{Nodes: []Node{
		{ID: "c1", Label: "core-1", Kind: KindRouter, DeviceRole: DevRoleCoreRouter, Site: "hq", Vendor: "arista"},
		{ID: "d1", Label: "dist-1", Kind: KindSwitch, DeviceRole: DevRoleDistributionSwitch, Site: "hq", Vendor: "cisco"},
		{ID: "d2", Label: "dist-2", Kind: KindSwitch, DeviceRole: DevRoleDistributionSwitch, Site: "hq", Vendor: "juniper"},
		{ID: "a1", Label: "access-1", Kind: KindSwitch, DeviceRole: DevRoleAccessSwitch, Site: "hq", Vendor: "sonic", MgmtIP: "10.1.1.9"},
		{ID: "ext:isp", Label: "isp-pe", Kind: KindUnresolved},
	}, Edges: []Edge{
		{Source: "c1", Target: "d1", Relationship: RelConnectedTo, Protocol: "lldp", Status: StatusUp},
		{Source: "c1", Target: "d2", Relationship: RelRoutedAdjacency, Protocol: "bgp_ls", Status: StatusUp,
			Evidence: []EvidenceRef{{Source: "bgp_ls", Detail: "isis-l2 49.0001 metric 10"}}},
		{Source: "d1", Target: "a1", Relationship: RelConnectedTo, Protocol: "lldp+cdp", Status: StatusUp},
		{Source: "c1", Target: "ext:isp", Relationship: RelConnectedTo, Protocol: "lldp", Status: StatusUp},
	}}
}

func TestDesignFindsSinglePointsOfFailure(t *testing.T) {
	sm := Summarize(SummaryInput{View: campusView(), OverlayRead: true})
	if sm.SPOFState != SPOFPresent || !sm.Coverage.SPOFComputed {
		t.Fatalf("spof state = %q computed=%v", sm.SPOFState, sm.Coverage.SPOFComputed)
	}
	got := map[string]int{}
	for _, x := range sm.SPOF {
		got[x.Kind+":"+x.Name] = x.Isolates
	}
	want := map[string]int{
		"device:core-1":          1, // dist-2 is cut off from {dist-1, access-1}
		"device:dist-1":          1, // access-1 is cut off
		"link:core-1 ↔ dist-1":   2, // {dist-1, access-1} vs {core-1, dist-2}
		"link:core-1 ↔ dist-2":   1,
		"link:access-1 ↔ dist-1": 1,
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("SPOF %s isolates %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("SPOF set = %v, want exactly %v", got, want)
	}
	if sm.SPOF[0].Isolates != 2 {
		t.Fatalf("most consequential first: %+v", sm.SPOF)
	}
	// An external neighbour is not a managed device and joins no cut.
	for _, x := range sm.SPOF {
		if strings.Contains(x.Name, "isp") {
			t.Fatalf("an unmanaged neighbour joined the SPOF graph: %+v", x)
		}
	}
}

func TestDesignRingHasNoSinglePointOfFailure(t *testing.T) {
	v := View{Nodes: []Node{
		{ID: "a", Label: "r-a", Kind: KindRouter, Site: "s1"},
		{ID: "b", Label: "r-b", Kind: KindRouter, Site: "s1"},
		{ID: "c", Label: "r-c", Kind: KindRouter, Site: "s1"},
	}, Edges: []Edge{
		{Source: "a", Target: "b", Relationship: RelConnectedTo, Protocol: "lldp"},
		{Source: "b", Target: "c", Relationship: RelConnectedTo, Protocol: "lldp"},
		{Source: "c", Target: "a", Relationship: RelConnectedTo, Protocol: "lldp"},
	}}
	sm := Summarize(SummaryInput{View: v})
	if sm.SPOFState != SPOFNone || len(sm.SPOF) != 0 {
		t.Fatalf("a ring has no single point of failure: %+v", sm.SPOF)
	}
	if sm.CoverageState != CoverageFull {
		t.Fatalf("links + sites for every device → full coverage, got %q (%+v)", sm.CoverageState, sm.Coverage)
	}
}

// No adjacency evidence at all: the search is NOT run, and the gap is said —
// an unread graph is never "no single point of failure".
func TestDesignWithoutAdjacencyIsUnknown(t *testing.T) {
	v := View{Nodes: []Node{{ID: "a", Label: "r-a", Kind: KindRouter}, {ID: "b", Label: "r-b", Kind: KindRouter}}}
	sm := Summarize(SummaryInput{View: v})
	if sm.SPOFState != SPOFUnknown || sm.Coverage.SPOFComputed || len(sm.SPOF) != 0 {
		t.Fatalf("no adjacencies → unknown: state=%q spof=%+v", sm.SPOFState, sm.SPOF)
	}
	if !strings.Contains(strings.Join(sm.Notes, " "), "could not be computed") {
		t.Fatalf("the gap must be said: %v", sm.Notes)
	}
	if sm.CoverageState != CoveragePartial || sm.Coverage.SitesKnown {
		t.Fatalf("no links and no sites → partial: %+v", sm.Coverage)
	}
}

func TestDesignProtocolsComeFromAdjacencyEvidence(t *testing.T) {
	sm := Summarize(SummaryInput{View: campusView()})
	protos := map[string]string{}
	for _, d := range sm.Devices {
		protos[d.Name] = strings.Join(d.Protocols, ",")
	}
	if protos["core-1"] != "isis,lldp" {
		t.Errorf("core-1 protocols = %q, want isis,lldp (IS-IS from the BGP-LS origin)", protos["core-1"])
	}
	if protos["dist-2"] != "isis" || protos["access-1"] != "cdp,lldp" {
		t.Errorf("protocols = %v", protos)
	}
	if !sm.Coverage.LinkDiscovery || !sm.Coverage.RoutedLinks {
		t.Fatalf("coverage = %+v", sm.Coverage)
	}
}

// The SD-WAN lab: a site with two edges is dual-edge; every site rides only
// mpls, so each is single-transport and single-homed in that sense.
func TestDesignSitesAndRedundancyOnTheLab(t *testing.T) {
	v, pairs := labView()
	sm := Summarize(SummaryInput{View: v, Pairs: pairs, OverlayRead: true})
	bySite := map[string]SiteSummary{}
	for _, s := range sm.SiteDetails {
		bySite[s.Name] = s
	}
	s50 := bySite["SD-WAN site 50"]
	if s50.Devices != 2 || s50.WANEdges != 2 || s50.SingleEdge || !s50.SingleTransport || !s50.SingleHomed {
		t.Fatalf("site 50: %+v", s50)
	}
	if s80 := bySite["SD-WAN site 80"]; !s80.SingleEdge || s80.Uplinks != 1 {
		t.Fatalf("site 80 has one edge and one uplink to the ISP PE: %+v", s80)
	}
	if len(sm.Overlay.SitesOnOneTransport) != 3 {
		t.Fatalf("every lab site rides one transport: %v", sm.Overlay.SitesOnOneTransport)
	}
	var dual []string
	for _, g := range sm.RedundancyGroups {
		dual = append(dual, g.Kind+"@"+g.Site)
	}
	if strings.Join(dual, ";") != "dual_edge@SD-WAN site 50" {
		t.Fatalf("redundancy groups = %v", dual)
	}
	if !strings.Contains(sm.RedundancyNote, "not collected") {
		t.Fatalf("LAG/FHRP must be declared uncollected: %q", sm.RedundancyNote)
	}
	// Full overlay mesh: no device or link cut.
	if sm.SPOFState != SPOFNone {
		t.Fatalf("a full-mesh overlay holds no single point of failure: %+v", sm.SPOF)
	}
	// Two transports on one site → dual_transport.
	pairs = append(pairs, OverlayPair{A: "ve51", B: "ce80", Colors: []string{"biz-internet"}, Sessions: 1, Up: 1})
	sm = Summarize(SummaryInput{View: v, Pairs: pairs, OverlayRead: true})
	found := false
	for _, g := range sm.RedundancyGroups {
		if g.Kind == RedundancyDualTransport && g.Site == "SD-WAN site 80" && strings.Join(g.Members, ",") == "biz-internet,mpls" {
			found = true
		}
	}
	if !found {
		t.Fatalf("site 80 now rides two transports: %+v", sm.RedundancyGroups)
	}
}

// No management address reaches the design fields either.
func TestDesignCarriesNoManagementAddress(t *testing.T) {
	v := campusView()
	v.Nodes[3].Label = "10.1.1.9" // an unnamed access switch
	sm := Summarize(SummaryInput{View: v})
	dump := fmt.Sprintf("%+v %+v %+v", sm.SPOF, sm.SiteDetails, sm.RedundancyGroups)
	if strings.Contains(dump, "10.1.1.9") {
		t.Fatalf("a management address reached the design reading: %s", dump)
	}
	if !strings.Contains(dump, "unnamed device") {
		t.Fatalf("the unnamed device must appear by its neutral name: %s", dump)
	}
}

// The search is bounded: above summarySPOFMaxNodes it is skipped and said.
func TestDesignSPOFSearchIsBounded(t *testing.T) {
	var v View
	for i := 0; i <= summarySPOFMaxNodes; i++ {
		v.Nodes = append(v.Nodes, Node{ID: fmt.Sprintf("n%03d", i), Label: fmt.Sprintf("dev-%03d", i), Kind: KindRouter})
		if i > 0 {
			v.Edges = append(v.Edges, Edge{Source: fmt.Sprintf("n%03d", i-1), Target: fmt.Sprintf("n%03d", i), Relationship: RelConnectedTo, Protocol: "lldp"})
		}
	}
	sm := Summarize(SummaryInput{View: v})
	if sm.SPOFState != SPOFUnknown || sm.Coverage.SPOFComputed {
		t.Fatalf("an oversized graph must not be searched: %q", sm.SPOFState)
	}
}
