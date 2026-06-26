package main

import (
	"testing"

	"netops/backend/topology"
)

func TestReliabilityScore(t *testing.T) {
	cases := []struct {
		name              string
		up, errDisc, pkts float64
		want              float64
	}{
		{"down → 0", 0, 0, 100, 0},
		{"up, no traffic → 100", 1, 0, 0, 100},
		{"up, clean traffic → 100", 1, 0, 1000, 100},
		{"up, 1% error/discard → 99", 1, 10, 990, 99},
		{"up, all errors → 0", 1, 100, 0, 0},
	}
	for _, c := range cases {
		got := reliabilityScore(c.up, c.errDisc, c.pkts)
		if got < c.want-0.01 || got > c.want+0.01 {
			t.Errorf("%s: reliabilityScore(%v,%v,%v) = %.2f, want %.2f",
				c.name, c.up, c.errDisc, c.pkts, got, c.want)
		}
	}
}

func TestEnrichPathIfMetrics_MatchesEdgeByInterface(t *testing.T) {
	view := &topology.View{
		Edges: []topology.Edge{
			{ID: "e1", Source: "leaf1", SourcePort: "Ethernet1", Target: "spine1", TargetPort: "Ethernet2"},
			{ID: "e2", Source: "leaf9", SourcePort: "Ethernet9", Target: "spine9", TargetPort: "Ethernet9"},
		},
	}
	byIface := map[[2]string]ifaceMetric{
		{"leaf1", canonIface("Ethernet1")}: {bwMbps: 10000, hasBW: true, thrMbps: 250, hasThr: true, reliability: 99.5, hasRel: true},
	}
	enrichPathIfMetrics(view, byIface)

	if e := view.Edges[0]; e.BandwidthMbps != 10000 || e.ThroughputMbps != 250 || e.Reliability != 99.5 {
		t.Errorf("e1 not enriched from source interface: %+v", e)
	}
	if view.Edges[0].MTU != 0 {
		t.Error("MTU must stay 0 (unset → honest —) when no series")
	}
	if e := view.Edges[1]; e.BandwidthMbps != 0 || e.Reliability != 0 {
		t.Errorf("e2 has no matching interface → must stay unset, got %+v", e)
	}
}

func TestEnrichPathIfMetrics_TargetFallback(t *testing.T) {
	view := &topology.View{Edges: []topology.Edge{
		{ID: "e", Source: "a", SourcePort: "Et1", Target: "b", TargetPort: "Ethernet5"},
	}}
	byIface := map[[2]string]ifaceMetric{
		{"b", canonIface("Ethernet5")}: {bwMbps: 1000, hasBW: true},
	}
	enrichPathIfMetrics(view, byIface)
	if view.Edges[0].BandwidthMbps != 1000 {
		t.Errorf("should fall back to target interface, got %v", view.Edges[0].BandwidthMbps)
	}
}

func TestEnrichPathIfMetrics_NilSafe(t *testing.T) {
	enrichPathIfMetrics(nil, nil)
	enrichPathIfMetrics(&topology.View{}, nil)
}
