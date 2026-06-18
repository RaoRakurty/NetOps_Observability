// Package topology projects raw, tenant-scoped telemetry (deduped adjacencies,
// device inventory, active alerts, measured traceroute paths) into the canonical
// renderer-agnostic TopologyView the frontend consumes. It is PURE and
// dependency-injected: it imports only the standard library and never touches
// HTTP / Redis / a database. All I/O happens in the package main handler, which
// gathers inputs and hands them in as a topology.Input — so the projection logic
// (graph build, shortest-path, evidence, enrichment) is fully unit-testable with
// mock telemetry (CLAUDE.md §3 zero-trust inputs, §11 testing).
package topology

import (
	"container/heap"
	"sort"
)

// Graph is an undirected weighted graph keyed by node id. Edge cost is the IGP/TE
// metric when known, else 1 (hop count). Built from the deduped link set so that
// shortest-path computation runs over the same adjacencies the canvas renders.
type Graph struct {
	adj map[string][]gEdge
}

type gEdge struct {
	to   string
	cost uint32
}

// NewGraph returns an empty graph.
func NewGraph() *Graph { return &Graph{adj: make(map[string][]gEdge)} }

// AddNode ensures a node exists even if it has no edges (so it's a valid SPF
// endpoint and appears in the adjacency map).
func (g *Graph) AddNode(id string) {
	if id == "" {
		return
	}
	if _, ok := g.adj[id]; !ok {
		g.adj[id] = nil
	}
}

// AddEdge adds an undirected edge a—b with the given cost. A zero cost is
// normalized to 1 so an unknown metric never collapses path distance.
func (g *Graph) AddEdge(a, b string, cost uint32) {
	if a == "" || b == "" || a == b {
		return
	}
	if cost == 0 {
		cost = 1
	}
	g.adj[a] = append(g.adj[a], gEdge{to: b, cost: cost})
	g.adj[b] = append(g.adj[b], gEdge{to: a, cost: cost})
}

// pqItem is a node waiting in the Dijkstra frontier.
type pqItem struct {
	node string
	dist uint64
}

// pq is a min-heap ordered by distance, then node id — the node-id tiebreak makes
// equal-cost (ECMP) shortest paths DETERMINISTIC so the rendered path doesn't
// flap between equal alternatives across requests.
type pq []pqItem

func (p pq) Len() int { return len(p) }
func (p pq) Less(i, j int) bool {
	if p[i].dist != p[j].dist {
		return p[i].dist < p[j].dist
	}
	return p[i].node < p[j].node
}
func (p pq) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p *pq) Push(x any)   { *p = append(*p, x.(pqItem)) }
func (p *pq) Pop() any {
	old := *p
	n := len(old)
	it := old[n-1]
	*p = old[:n-1]
	return it
}

// Dijkstra returns the lowest-cost path from src to dst (inclusive of both),
// the total cost, and whether dst is reachable. The path is deterministic for
// equal-cost alternatives (lexicographic node-id tiebreak). Returns (nil, 0,
// false) when src/dst are unknown or disconnected.
func (g *Graph) Dijkstra(src, dst string) ([]string, uint64, bool) {
	if src == "" || dst == "" {
		return nil, 0, false
	}
	if _, ok := g.adj[src]; !ok {
		return nil, 0, false
	}
	if _, ok := g.adj[dst]; !ok {
		return nil, 0, false
	}
	if src == dst {
		return []string{src}, 0, true
	}

	const inf = ^uint64(0)
	dist := map[string]uint64{src: 0}
	prev := map[string]string{}
	done := map[string]bool{}

	frontier := &pq{{node: src, dist: 0}}
	heap.Init(frontier)

	for frontier.Len() > 0 {
		cur := heap.Pop(frontier).(pqItem)
		if done[cur.node] {
			continue
		}
		done[cur.node] = true
		if cur.node == dst {
			break
		}
		// Relax neighbours in a stable order so the chosen predecessor for an
		// equal-cost tie is deterministic.
		nbrs := append([]gEdge(nil), g.adj[cur.node]...)
		sort.Slice(nbrs, func(i, j int) bool {
			if nbrs[i].to != nbrs[j].to {
				return nbrs[i].to < nbrs[j].to
			}
			return nbrs[i].cost < nbrs[j].cost
		})
		for _, e := range nbrs {
			if done[e.to] {
				continue
			}
			nd := cur.dist + uint64(e.cost)
			if old, ok := dist[e.to]; !ok || nd < old || (nd == old && cur.node < prev[e.to]) {
				dist[e.to] = nd
				prev[e.to] = cur.node
				heap.Push(frontier, pqItem{node: e.to, dist: nd})
			}
		}
	}

	if _, ok := dist[dst]; !ok {
		return nil, 0, false
	}
	// Reconstruct src→dst.
	rev := []string{dst}
	for n := dst; n != src; {
		p, ok := prev[n]
		if !ok {
			return nil, 0, false
		}
		rev = append(rev, p)
		n = p
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	d := dist[dst]
	if d == inf {
		return nil, 0, false
	}
	return rev, d, true
}
