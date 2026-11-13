// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"strings"
	"testing"
)

func designNet() NetworkTopology {
	return NetworkTopology{
		Collected: true, DevicesTotal: 3, OverlayRead: true,
		Devices: []NetworkDevice{{Name: "core-1", Role: "core_router", Protocols: []string{"isis", "lldp"}, Telemetry: []string{"snmp"}}},
		SiteDetails: []NetworkSite{
			{Name: "hq", Devices: 3, WANEdges: 1, SingleEdge: true},
			{Name: "branch-7", Devices: 1, WANEdges: 2, Transports: []string{"mpls"}, SingleTransport: true},
		},
		Redundancy:     []NetworkRedundancy{{Kind: "dual_edge", Site: "branch-7", Members: []string{"e1", "e2"}}},
		RedundancyNote: "link aggregation (LAG) membership and first-hop redundancy (HSRP/VRRP) are not collected",
		SPOF:           []NetworkSPOF{{Kind: "device", Name: "core-1", Isolates: 2}},
		SPOFTotal:      1, SPOFState: "present",
		Coverage:      NetworkCoverage{LinkDiscovery: true, OverlayRead: true, SitesKnown: true, SPOFComputed: true},
		CoverageState: "full",
	}
}

func TestNetworkTopologyDesignReading(t *testing.T) {
	res := RenderNetworkTopology(designNet())
	byID := map[string]EvidenceItem{}
	for _, it := range res.Items {
		byID[strings.TrimPrefix(it.CitationID, NetworkTopologyCitationPrefix)] = it
	}
	sh := byID["design:single-homed"]
	if !strings.Contains(sh.Text, "site hq (one WAN edge)") || !strings.Contains(sh.Text, "site branch-7 (one transport (mpls))") {
		t.Fatalf("single-homed item = %q", sh.Text)
	}
	sp := byID["design:spof"]
	if sp.Class != ClassDerived || !strings.Contains(sp.Text, "device core-1 (cuts off 2 devices)") || !strings.Contains(sp.Text, "has not discovered") {
		t.Fatalf("a single point of failure is an INFERENCE over discovered adjacencies: %+v", sp)
	}
	if byID["design:redundancy"].Class != "" || !strings.Contains(byID["design:redundancy"].Text, "branch-7 has two or more WAN edges") {
		t.Fatalf("redundancy item = %+v", byID["design:redundancy"])
	}
	if _, ok := byID["design:coverage"]; ok {
		t.Fatal("full coverage needs no coverage item")
	}
	if d := byID["dev:1"].Text; !strings.Contains(d, "seen running isis, lldp") || !strings.Contains(d, "collected via snmp") {
		t.Fatalf("device line = %q", d)
	}
	sig := strings.Join(res.Signals, " ")
	for _, want := range []string{"topo:overlay_shape=none", "topo:spof=present", "topo:coverage=full"} {
		if !strings.Contains(sig, want) {
			t.Fatalf("signals %v lack %s", res.Signals, want)
		}
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "not collected") {
		t.Fatalf("the redundancy coverage note must travel: %v", res.Notes)
	}

	// Unknown: no SPOF item at all (never "none"), and the coverage gap is said.
	nt := designNet()
	nt.SPOF, nt.SPOFTotal, nt.SPOFState = nil, 0, "unknown"
	nt.Coverage = NetworkCoverage{}
	nt.CoverageState, nt.OverlayRead = "partial", false
	res = RenderNetworkTopology(nt)
	for _, it := range res.Items {
		if it.CitationID == NetworkTopologyCitationPrefix+"design:spof" {
			t.Fatalf("an uncomputed SPOF search must not produce an item: %+v", it)
		}
		if it.CitationID == NetworkTopologyCitationPrefix+"design:coverage" && !strings.Contains(it.Text, "no LLDP/CDP neighbours") {
			t.Fatalf("coverage item = %q", it.Text)
		}
	}
	sig = strings.Join(res.Signals, " ")
	if !strings.Contains(sig, "topo:spof=unknown") || !strings.Contains(sig, "topo:overlay_shape=unknown") || !strings.Contains(sig, "topo:coverage=partial") {
		t.Fatalf("signals = %v", res.Signals)
	}
	// Every declared signal is inside the closed vocabulary the chain accepts.
	f := newChainFacts()
	f.addSignals(res.Signals)
	if len(f.topo) != 3 {
		t.Fatalf("the chain accepted %d of 3 declared topo signals: %v", len(f.topo), f.topo)
	}
}
