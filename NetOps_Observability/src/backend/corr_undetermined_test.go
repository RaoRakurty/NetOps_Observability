package backend

import (
	"testing"
	"time"
)

func TestSplitGapToken(t *testing.T) {
	cases := []struct{ in, sig, clause string }{
		{"ospf_adjacency_loss: needs second-modality observer", "ospf_adjacency_loss", "second-modality observer"},
		{"bgp_session_down: single observer", "bgp_session_down", "single observer"},
		{"freeform note without colon", "uncategorized", "freeform note without colon"},
		{"  ", "", ""},
	}
	for _, c := range cases {
		sig, clause := splitGapToken(c.in)
		if sig != c.sig || clause != c.clause {
			t.Errorf("splitGapToken(%q) = (%q,%q), want (%q,%q)", c.in, sig, clause, c.sig, c.clause)
		}
	}
}

func TestClusterUndetermined(t *testing.T) {
	base := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	objs := []undeterminedObj{
		// Three incidents that all almost-hit the same nearest signature → one cluster.
		{CorrelationID: "a", WindowStart: base, EvidenceMissing: []string{"ospf_adjacency_loss: needs second observer"}, EntityTypes: []string{"device"}, SignalCount: 2},
		{CorrelationID: "b", WindowStart: base.Add(time.Hour), EvidenceMissing: []string{"ospf_adjacency_loss: needs second observer"}, EntityTypes: []string{"device", "interface"}, SignalCount: 4},
		{CorrelationID: "c", WindowStart: base.Add(2 * time.Hour), EvidenceMissing: []string{"ospf_adjacency_loss: needs fate-shared pair"}, EntityTypes: []string{"device"}, SignalCount: 3},
		// A different, less-frequent shape.
		{CorrelationID: "d", WindowStart: base.Add(3 * time.Hour), EvidenceMissing: []string{"bgp_session_down: single observer"}, EntityTypes: []string{"path"}, SignalCount: 1},
		// No evidence tokens → falls back to the affected-entity shape, never dropped.
		{CorrelationID: "e", WindowStart: base, EvidenceMissing: nil, EntityTypes: []string{"site"}, SignalCount: 1},
	}

	clusters := clusterUndetermined(objs, 0)
	if len(clusters) != 3 {
		t.Fatalf("expected 3 clusters, got %d: %+v", len(clusters), clusters)
	}

	// Most-frequent first: the ospf cluster (3) leads.
	top := clusters[0]
	if top.Count != 3 {
		t.Fatalf("top cluster count = %d, want 3", top.Count)
	}
	if len(top.NearestSignatures) != 1 || top.NearestSignatures[0] != "ospf_adjacency_loss" {
		t.Errorf("top nearest signatures = %v, want [ospf_adjacency_loss]", top.NearestSignatures)
	}
	// Examples capped at 3, last-seen is the most recent member, entity-type union.
	if len(top.Examples) != 3 {
		t.Errorf("examples = %v, want 3", top.Examples)
	}
	if top.LastSeen != base.Add(2*time.Hour).Format(time.RFC3339) {
		t.Errorf("last_seen = %q, want %v", top.LastSeen, base.Add(2*time.Hour))
	}
	if !eqStrSet(top.EntityTypes, []string{"device", "interface"}) {
		t.Errorf("entity types = %v, want device+interface", top.EntityTypes)
	}
	// avg signals = (2+4+3)/3 = 3.0
	if top.AvgSignals != 3.0 {
		t.Errorf("avg signals = %v, want 3.0", top.AvgSignals)
	}
	// The most common gap clause leads top_gaps (two "needs second observer").
	if len(top.TopGaps) == 0 || top.TopGaps[0].Clause != "second observer" || top.TopGaps[0].Count != 2 {
		t.Errorf("top gap = %+v, want {second observer, 2}", top.TopGaps)
	}

	// The token-less object survives as its own shape cluster.
	var siteShape *undeterminedCluster
	for i := range clusters {
		if clusters[i].Fingerprint == "shape:site" {
			siteShape = &clusters[i]
		}
	}
	if siteShape == nil || siteShape.Count != 1 {
		t.Fatalf("token-less object must form a shape cluster, got %+v", clusters)
	}

	// topN truncates.
	if got := clusterUndetermined(objs, 1); len(got) != 1 {
		t.Errorf("topN=1 should return 1 cluster, got %d", len(got))
	}
}

func TestEntityTypesFromAffected(t *testing.T) {
	got := entityTypesFromAffected(`{"devices":["r1"],"interfaces":["r1/Et1"],"paths":[]}`)
	if !eqStrSet(got, []string{"device", "interface"}) {
		t.Errorf("entity types = %v, want device+interface", got)
	}
	if got := entityTypesFromAffected(""); len(got) != 0 {
		t.Errorf("empty affected → no types, got %v", got)
	}
	if got := entityTypesFromAffected("not json"); len(got) != 0 {
		t.Errorf("bad json → no types, got %v", got)
	}
}

func eqStrSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}
