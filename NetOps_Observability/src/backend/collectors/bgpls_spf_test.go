package collectors

import (
	"sort"
	"testing"
)

// graph builds an undirected adjacency map from edge pairs.
func graph(edges ...[2]string) (map[string][]string, []string) {
	adj := map[string][]string{}
	set := map[string]bool{}
	for _, e := range edges {
		adj[e[0]] = append(adj[e[0]], e[1])
		adj[e[1]] = append(adj[e[1]], e[0])
		set[e[0]], set[e[1]] = true, true
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return adj, names
}

func has(pairs []RoutingPair, from, to string) bool {
	for _, p := range pairs {
		if p.From == from && p.To == to {
			return true
		}
	}
	return false
}

// A linear path  edge1 — core1 — edge2 . Traffic to either edge flows through the
// core, so the core forwards toward BOTH edges (core→edge1 AND core→edge2), and each
// edge forwards toward the core (edge→core). The edge↔core links are therefore each
// used in BOTH directions across destinations → both ordered pairs present (the
// consumer renders that AMBIGUOUS, never an assumed direction). The KEY asymmetry the
// test pins: an edge NEVER forwards toward the far edge directly (no edge1→edge2).
func TestForwardingPairs_LinearPath(t *testing.T) {
	adj, names := graph([2]string{"edge1", "core1"}, [2]string{"core1", "edge2"})
	pairs := forwardingPairs(names, adj)

	// every node reaches every other → these next-hop facts must hold:
	if !has(pairs, "edge1", "core1") || !has(pairs, "edge2", "core1") {
		t.Fatalf("each edge must forward toward the core; got %+v", pairs)
	}
	if !has(pairs, "core1", "edge1") || !has(pairs, "core1", "edge2") {
		t.Fatalf("the core must forward toward each edge; got %+v", pairs)
	}
	// an edge's next hop toward the far edge is the CORE, never the far edge itself.
	if has(pairs, "edge1", "edge2") || has(pairs, "edge2", "edge1") {
		t.Fatalf("no direct edge→far-edge forwarding (they are not adjacent); got %+v", pairs)
	}
}

// A stub line: stub — agg — core. The stub is a leaf: it forwards toward agg for
// every non-stub destination, and it is never on the path BETWEEN two other nodes,
// so stub and core never directly forward to each other (always via agg).
func TestForwardingPairs_StubForwardsViaAggNeverDirectToCore(t *testing.T) {
	adj, names := graph([2]string{"stub", "agg"}, [2]string{"agg", "core"})
	pairs := forwardingPairs(names, adj)
	if !has(pairs, "stub", "agg") {
		t.Fatalf("stub must forward toward agg; got %+v", pairs)
	}
	// stub and core are not adjacent → no direct forwarding either way (it goes via agg).
	if has(pairs, "core", "stub") || has(pairs, "stub", "core") {
		t.Fatalf("stub↔core forwarding must route via agg, not directly; got %+v", pairs)
	}
}

// Determinism: identical graph (any insertion order) → identical sorted pairs.
func TestForwardingPairs_Deterministic(t *testing.T) {
	a1, n1 := graph([2]string{"a", "b"}, [2]string{"b", "c"}, [2]string{"c", "a"})
	a2, n2 := graph([2]string{"c", "a"}, [2]string{"b", "c"}, [2]string{"a", "b"})
	p1, p2 := forwardingPairs(n1, a1), forwardingPairs(n2, a2)
	if len(p1) != len(p2) {
		t.Fatalf("len differs: %d vs %d", len(p1), len(p2))
	}
	for i := range p1 {
		if p1[i] != p2[i] {
			t.Fatalf("order differs at %d: %+v vs %+v", i, p1[i], p2[i])
		}
	}
}

// An isolated graph with no edges yields no pairs (source abstains).
func TestForwardingPairs_Empty(t *testing.T) {
	if p := forwardingPairs(nil, map[string][]string{}); len(p) != 0 {
		t.Fatalf("empty graph must yield no pairs; got %+v", p)
	}
}
