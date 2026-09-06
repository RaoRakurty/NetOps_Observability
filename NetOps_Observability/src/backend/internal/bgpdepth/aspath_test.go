// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

import (
	"encoding/json"
	"testing"
	"time"
)

// realBGPState is the verbatim shape of RIPEstat's bgp-state data call for
// 193.0.0.0/21 (captured 2026-09-02) — paths are integer arrays.
const realBGPState = `{"resource":"193.0.0.0/21","timestamp":"2026-09-02T13:59:55","bgp_state":[
 {"target_prefix":"193.0.0.0/21","source_id":"00-102.208.105.2","path":[328840,327727,174,1273,3333],"community":["64525:10"]},
 {"target_prefix":"193.0.0.0/21","source_id":"00-103.212.68.10","path":[55720,6939,3333],"community":[]},
 {"target_prefix":"193.0.0.0/21","source_id":"00-12.0.1.63","path":[7018,1299,1273,3333],"community":[]},
 {"target_prefix":"193.0.0.0/21","source_id":"00-154.11.12.212","path":[852,2914,1136,3333],"community":[]}]}`

func nowFixed() time.Time { return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) }

func TestParseBGPStateReadsTheRealPayload(t *testing.T) {
	paths := ParseBGPState(json.RawMessage(realBGPState))
	if len(paths) != 4 {
		t.Fatalf("got %d paths, want 4", len(paths))
	}
	if len(paths[0]) != 5 || paths[0][4] != 3333 {
		t.Fatalf("path 0 = %v", paths[0])
	}
	if got := ParseBGPState(json.RawMessage(`{"bgp_state":"nope"}`)); got != nil {
		t.Fatalf("garbage yielded %v", got)
	}
}

func TestParseLookingGlassHandlesStringPathsAndASSets(t *testing.T) {
	lg := `{"rrcs":[{"peers":[{"as_path":"3333 1273 174"},{"as_path":"6939 {64500,64501} 3333"},{"as_path":""},{"as_path":"garbage AS7018 3333"}]}]}`
	paths := ParseLookingGlass(json.RawMessage(lg))
	if len(paths) != 3 {
		t.Fatalf("got %d paths: %v", len(paths), paths)
	}
	if paths[1][1] != 64500 {
		t.Fatalf("AS_SET should collapse to its first member: %v", paths[1])
	}
	if len(paths[2]) != 2 || paths[2][0] != 7018 {
		t.Fatalf("unparsable tokens must be dropped, not guessed: %v", paths[2])
	}
}

func TestCompressPathRemovesPrependsAndAS0(t *testing.T) {
	got := CompressPath([]uint32{7018, 1299, 1299, 1299, 0, 1273, 3333, 3333})
	want := []uint32{7018, 1299, 1273, 3333}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	long := make([]uint32, 300)
	for i := range long {
		long[i] = uint32(i + 1)
	}
	if n := len(CompressPath(long)); n != maxPathLen {
		t.Fatalf("path length %d exceeds the cap %d", n, maxPathLen)
	}
}

func TestBuildASPathGraphDedupesMarksAndCounts(t *testing.T) {
	paths := ParseBGPState(json.RawMessage(realBGPState))
	g := BuildASPathGraph("193.0.0.0/21", paths, map[uint32]bool{3333: true}, "bgp-state", nowFixed())
	if g.Paths != 4 || g.PathsSeen != 4 {
		t.Fatalf("paths = %d/%d", g.Paths, g.PathsSeen)
	}
	if len(g.Origins) != 1 || g.Origins[0] != 3333 {
		t.Fatalf("origins = %v, want [3333]", g.Origins)
	}
	// 1273→3333 appears on two paths; it must be ONE edge weighted 2.
	var found bool
	for _, e := range g.Edges {
		if e.From == 1273 && e.To == 3333 {
			if e.Peers != 2 {
				t.Fatalf("1273→3333 peers = %d, want 2 (deduped with a count)", e.Peers)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("the shared adjacency is missing: %+v", g.Edges)
	}
	byASN := map[uint32]GraphNode{}
	for _, n := range g.Nodes {
		byASN[n.ASN] = n
	}
	if !byASN[3333].Origin || !byASN[3333].Tenant {
		t.Fatalf("the origin/tenant marks are missing: %+v", byASN[3333])
	}
	if byASN[3333].Vantage {
		t.Fatal("the origin must not also be marked a vantage point")
	}
	if !byASN[7018].Vantage || byASN[7018].Depth != 0 {
		t.Fatalf("collector-adjacent AS not marked: %+v", byASN[7018])
	}
	if byASN[3333].Paths != 4 {
		t.Fatalf("origin path count = %d, want 4", byASN[3333].Paths)
	}
}

func TestBuildASPathGraphCapsEdgesDeterministicallyAndDeclaresIt(t *testing.T) {
	// Build far more distinct adjacencies than the cap.
	var paths [][]uint32
	for i := 0; i < MaxGraphEdges+200; i++ {
		paths = append(paths, []uint32{uint32(100000 + i), 64500})
	}
	// One adjacency that is much more common — it must SURVIVE the cut.
	for i := 0; i < 50; i++ {
		paths = append(paths, []uint32{7018, 64500})
	}
	g := BuildASPathGraph("203.0.113.0/24", paths, nil, "bgp-state", nowFixed())
	if len(g.Edges) > MaxGraphEdges {
		t.Fatalf("edges = %d, cap is %d", len(g.Edges), MaxGraphEdges)
	}
	if !g.EdgesCapped || g.MaxEdges != MaxGraphEdges {
		t.Fatalf("the cap bit but was not declared: capped=%v max=%d", g.EdgesCapped, g.MaxEdges)
	}
	if g.Edges[0].From != 7018 || g.Edges[0].Peers != 50 {
		t.Fatalf("the strongest adjacency did not survive the cut: %+v", g.Edges[0])
	}
	// Determinism: the same input yields byte-identical structure.
	g2 := BuildASPathGraph("203.0.113.0/24", paths, nil, "bgp-state", nowFixed())
	a, _ := json.Marshal(g)
	b, _ := json.Marshal(g2)
	if string(a) != string(b) {
		t.Fatal("the graph is not deterministic — the same data would redraw differently")
	}
	// No dangling edges: every endpoint has a node.
	nodes := map[uint32]bool{}
	for _, n := range g.Nodes {
		nodes[n.ASN] = true
	}
	for _, e := range g.Edges {
		if !nodes[e.From] || !nodes[e.To] {
			t.Fatalf("edge %d→%d has no node — it would render as a link to nothing", e.From, e.To)
		}
	}
}

func TestBuildASPathGraphSingleHopStillHasANode(t *testing.T) {
	g := BuildASPathGraph("203.0.113.0/24", [][]uint32{{64500}}, nil, "bgp-state", nowFixed())
	if len(g.Nodes) != 1 || g.Nodes[0].ASN != 64500 || !g.Nodes[0].Origin {
		t.Fatalf("nodes = %+v", g.Nodes)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("edges = %+v", g.Edges)
	}
}

func TestBuildASPathGraphEmptyIsEmptyNotNull(t *testing.T) {
	g := BuildASPathGraph("203.0.113.0/24", nil, nil, "bgp-state", nowFixed())
	b, _ := json.Marshal(g)
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"nodes", "edges", "origins"} {
		if string(probe[k]) != "[]" {
			t.Fatalf("%s serialized as %s, want [] (the UI maps over it)", k, probe[k])
		}
	}
}

func TestAnnotateNamesNeverInventsAHolder(t *testing.T) {
	g := BuildASPathGraph("193.0.0.0/21", ParseBGPState(json.RawMessage(realBGPState)), nil, "bgp-state", nowFixed())
	AnnotateNames(&g, func(asn uint32) string {
		if asn == 3333 {
			return "RIPE-NCC"
		}
		return ""
	})
	for _, n := range g.Nodes {
		if n.ASN == 3333 && n.Name != "RIPE-NCC" {
			t.Fatalf("known holder not applied: %+v", n)
		}
		if n.ASN != 3333 && n.Name != "" {
			t.Fatalf("a name was invented for AS%d: %q", n.ASN, n.Name)
		}
	}
	AnnotateNames(&g, nil) // must not panic
}

// A hop the upstream wrote unreadably is a FAILURE, not an absent hop. Dropping
// it silently would splice its neighbours together and draw an adjacency that
// does not exist — a fabricated fact on an operator's screen (CLAUDE.md §10).
func TestUnreadableInteriorHopDropsThePathInsteadOfFabricatingAnAdjacency(t *testing.T) {
	lg := `{"rrcs":[{"peers":[{"as_path":"6939 garbage 3333"},{"as_path":"7018 1299 3333"}]}]}`
	paths := ParseLookingGlass(json.RawMessage(lg))
	if len(paths) != 2 {
		t.Fatalf("got %d paths: %v", len(paths), paths)
	}
	g := BuildASPathGraph("193.0.0.0/21", paths, nil, "looking-glass", nowFixed())
	if g.PathsDropped != 1 {
		t.Fatalf("paths_dropped = %d, want 1 — the damaged path was folded in or vanished silently", g.PathsDropped)
	}
	if g.Paths != 1 || g.PathsSeen != 2 {
		t.Fatalf("paths = %d/%d, want 1/2 (the healthy path still counts)", g.Paths, g.PathsSeen)
	}
	for _, e := range g.Edges {
		if e.From == 6939 && e.To == 3333 {
			t.Fatalf("a fabricated adjacency 6939→3333 was drawn across an unreadable hop: %+v", g.Edges)
		}
	}
	// The surviving path is intact — one broken path must not blank the panel.
	var kept bool
	for _, e := range g.Edges {
		if e.From == 1299 && e.To == 3333 {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("the healthy path was lost with the broken one: %+v", g.Edges)
	}
	if g.Error != "" {
		t.Errorf("a partially damaged answer must not be reported as a total failure: %q", g.Error)
	}
}

// When EVERY path the upstream offered is unreadable, the empty graph must say
// the source FAILED. An empty-but-OK payload would render as "this prefix has
// no observed paths", which is a different (and false) claim.
func TestAnAllUnreadableAnswerIsAFailedGraphNotAnEmptyOne(t *testing.T) {
	lg := `{"rrcs":[{"peers":[{"as_path":"6939 garbage 3333"},{"as_path":"7018 rubbish 3333"}]}]}`
	g := BuildASPathGraph("193.0.0.0/21", ParseLookingGlass(json.RawMessage(lg)), nil, "looking-glass", nowFixed())
	if g.Paths != 0 || g.PathsDropped != 2 {
		t.Fatalf("paths = %d, dropped = %d, want 0/2", g.Paths, g.PathsDropped)
	}
	if g.Error == "" {
		t.Fatal("an all-unreadable upstream answer rendered as an empty-but-healthy graph")
	}
	// A genuinely empty upstream is NOT an error — the two must stay distinct.
	empty := BuildASPathGraph("193.0.0.0/21", nil, nil, "looking-glass", nowFixed())
	if empty.Error != "" || empty.PathsDropped != 0 {
		t.Fatalf("an honestly empty answer was reported as a failure: %+v", empty)
	}
}

// A gap at either END of a path splices nothing, so it must not be reported as
// damage — over-reporting a failure is its own dishonesty.
func TestGapsAtThePathEdgesAreNotCountedAsDamage(t *testing.T) {
	lg := `{"rrcs":[{"peers":[{"as_path":"garbage 7018 1299 3333"},{"as_path":"7018 1299 3333 trailing"}]}]}`
	g := BuildASPathGraph("193.0.0.0/21", ParseLookingGlass(json.RawMessage(lg)), nil, "looking-glass", nowFixed())
	if g.PathsDropped != 0 || g.Paths != 2 {
		t.Fatalf("paths = %d, dropped = %d, want 2/0 — an edge gap fabricates nothing", g.Paths, g.PathsDropped)
	}
	if g.Error != "" {
		t.Errorf("error = %q, want none", g.Error)
	}
}

// AS0 is a well-formed "no AS here" (RFC 7607), not an unreadable token: it is
// dropped as before and must not be counted as an upstream failure.
func TestReservedAS0IsNotTreatedAsAnUpstreamFailure(t *testing.T) {
	paths := ParseLookingGlass(json.RawMessage(`{"rrcs":[{"peers":[{"as_path":"7018 0 3333"}]}]}`))
	g := BuildASPathGraph("193.0.0.0/21", paths, nil, "looking-glass", nowFixed())
	if g.PathsDropped != 0 || g.Paths != 1 {
		t.Fatalf("paths = %d, dropped = %d, want 1/0", g.Paths, g.PathsDropped)
	}
	if g.Error != "" {
		t.Errorf("error = %q, want none for a reserved-AS hop", g.Error)
	}
}
