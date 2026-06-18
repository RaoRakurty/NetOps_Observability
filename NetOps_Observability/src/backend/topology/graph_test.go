package topology

import (
	"reflect"
	"testing"
)

// buildGraph wires a small diamond with an ECMP pair so the tests exercise
// weighting, equal-cost ties, and an isolated node:
//
//	a --1-- b --1-- d        (cost-2 path a→b→d)
//	a --1-- c --1-- d        (cost-2 path a→c→d, equal cost = ECMP)
//	a --5-- d                (direct but expensive)
//	x                        (isolated; valid endpoint, no edges)
func buildGraph() *Graph {
	g := NewGraph()
	g.AddEdge("a", "b", 1)
	g.AddEdge("b", "d", 1)
	g.AddEdge("a", "c", 1)
	g.AddEdge("c", "d", 1)
	g.AddEdge("a", "d", 5)
	g.AddNode("x")
	return g
}

func TestDijkstraShortestPath(t *testing.T) {
	g := buildGraph()
	path, cost, ok := g.Dijkstra("a", "d")
	if !ok {
		t.Fatal("expected d reachable from a")
	}
	if cost != 2 {
		t.Fatalf("expected cost 2 (cheap 2-hop over direct cost-5), got %d", cost)
	}
	if len(path) != 3 || path[0] != "a" || path[2] != "d" {
		t.Fatalf("expected 3-hop a..d path, got %v", path)
	}
}

func TestDijkstraECMPDeterministic(t *testing.T) {
	// Two equal-cost paths exist (a→b→d and a→c→d). The lexicographic node-id
	// tiebreak must pick the SAME one every call so the rendered path never flaps.
	want := []string{"a", "b", "d"}
	for i := 0; i < 50; i++ {
		g := buildGraph() // rebuild each time → adjacency insertion order can't be relied on
		path, _, ok := g.Dijkstra("a", "d")
		if !ok {
			t.Fatal("expected reachable")
		}
		if !reflect.DeepEqual(path, want) {
			t.Fatalf("ECMP path not deterministic: got %v want %v", path, want)
		}
	}
}

func TestDijkstraSameSrcDst(t *testing.T) {
	g := buildGraph()
	path, cost, ok := g.Dijkstra("a", "a")
	if !ok || cost != 0 || !reflect.DeepEqual(path, []string{"a"}) {
		t.Fatalf("src==dst should be ([a],0,true), got %v %d %v", path, cost, ok)
	}
}

func TestDijkstraUnreachable(t *testing.T) {
	g := buildGraph()
	// x is a known node with no edges → unreachable, but not "unknown".
	if path, cost, ok := g.Dijkstra("a", "x"); ok || path != nil || cost != 0 {
		t.Fatalf("isolated node should be unreachable, got %v %d %v", path, cost, ok)
	}
}

func TestDijkstraUnknownEndpoint(t *testing.T) {
	g := buildGraph()
	if _, _, ok := g.Dijkstra("a", "nope"); ok {
		t.Fatal("unknown dst must return ok=false")
	}
	if _, _, ok := g.Dijkstra("nope", "d"); ok {
		t.Fatal("unknown src must return ok=false")
	}
	if _, _, ok := g.Dijkstra("", "d"); ok {
		t.Fatal("empty src must return ok=false")
	}
}

func TestAddEdgeZeroCostNormalized(t *testing.T) {
	// A zero (unknown) metric must normalize to 1, not collapse distance to 0.
	g := NewGraph()
	g.AddEdge("a", "b", 0)
	g.AddEdge("b", "c", 0)
	_, cost, ok := g.Dijkstra("a", "c")
	if !ok || cost != 2 {
		t.Fatalf("zero-cost edges should each count as 1 (total 2), got cost=%d ok=%v", cost, ok)
	}
}

func TestAddEdgeIgnoresDegenerate(t *testing.T) {
	g := NewGraph()
	g.AddEdge("a", "a", 1) // self-loop
	g.AddEdge("", "b", 1)  // empty endpoint
	g.AddEdge("c", "", 1)  // empty endpoint
	// None of those should have created a usable adjacency.
	if _, _, ok := g.Dijkstra("a", "b"); ok {
		t.Fatal("degenerate edges must not connect nodes")
	}
}

func TestWeightedPrefersCheaperLongerRoute(t *testing.T) {
	// a→d direct is cost 10; a→b→d is cost 3. Cheaper multi-hop must win.
	g := NewGraph()
	g.AddEdge("a", "d", 10)
	g.AddEdge("a", "b", 1)
	g.AddEdge("b", "d", 2)
	path, cost, ok := g.Dijkstra("a", "d")
	if !ok || cost != 3 || !reflect.DeepEqual(path, []string{"a", "b", "d"}) {
		t.Fatalf("expected cheap 2-hop (cost 3), got %v cost=%d", path, cost)
	}
}
