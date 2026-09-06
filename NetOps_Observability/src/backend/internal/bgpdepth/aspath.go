// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

// aspath.go — the AS-path graph (the flagship of the 91df4f62 design):
// collector vantage points → converging AS hops → the origin, as a node-link
// graph instead of a wall of path pills.
//
// Source: the RIPEstat "bgp-state" data call, verified live 2026-09-02 —
//
//	data.bgp_state[] = {"target_prefix":"193.0.0.0/21",
//	                    "source_id":"00-12.0.1.63",
//	                    "path":[7018,1299,1273,3333], "community":[…]}
//
// with "looking-glass" (as_path as a space-separated STRING) as the fallback
// when bgp-state is unavailable, so the panel degrades instead of blanking.
//
// Bounds (§9): paths, path length, nodes and edges are all capped, and every
// cap that BITES is declared in the payload — a truncated graph that does not
// say it is truncated is a lie about the topology.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxGraphEdges is the contract cap from the item spec.
	MaxGraphEdges = 500
	// maxGraphPaths bounds the paths considered before edge dedup.
	maxGraphPaths = 20_000
	// maxPathLen bounds one AS_PATH. Real paths are <20 hops; 64 is generous
	// and stops a hostile payload from building a huge chain.
	maxPathLen = 64
	// maxGraphNodes bounds the node array independently of the edge cap.
	maxGraphNodes = 600
	// ASPathCacheTTL — collector state moves slowly relative to a page view.
	ASPathCacheTTL = 2 * time.Minute
	// unreadableHop marks a hop the upstream wrote in a form we could not read.
	// AS0 is reserved (RFC 7607) and can never be a real hop, so it is an
	// unambiguous in-band marker: BuildASPathGraph drops a path that carries
	// one rather than splicing across the gap and drawing an adjacency between
	// two ASes that are not neighbours.
	unreadableHop uint32 = 0
)

// GraphNode is one AS in the graph.
type GraphNode struct {
	ASN uint32 `json:"asn"`
	// Name is filled from the RDAP/whois holder cache by the caller; absent is
	// absent — this package never invents an AS name.
	Name string `json:"name,omitempty"`
	// Depth is the SHORTEST distance from a collector peer (depth 0) to this
	// AS across all observed paths — the graph's left-to-right layer index.
	Depth int `json:"depth"`
	// Origin marks the AS that originates the prefix.
	Origin bool `json:"origin,omitempty"`
	// Tenant marks one of the caller's own ASNs (from its watchlist).
	Tenant bool `json:"tenant,omitempty"`
	// Vantage marks a collector-adjacent AS (the left edge of the graph).
	Vantage bool `json:"vantage,omitempty"`
	// Paths counts observed paths this AS appears on — the node's weight.
	Paths int `json:"paths"`
}

// GraphEdge is one observed AS adjacency, deduped across all paths.
type GraphEdge struct {
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
	// Peers is how many collector paths traverse this adjacency (link width in
	// the design). It is an OBSERVATION COUNT, not a capacity.
	Peers int `json:"peers"`
}

// ASPathGraph is the endpoint payload.
type ASPathGraph struct {
	Prefix      string      `json:"prefix"`
	Nodes       []GraphNode `json:"nodes"`
	Edges       []GraphEdge `json:"edges"`
	Origins     []uint32    `json:"origins"`
	Paths       int         `json:"paths"`        // paths actually folded in
	PathsSeen   int         `json:"paths_seen"`   // paths the upstream offered
	MaxEdges    int         `json:"max_edges"`    // the cap in force
	EdgesCapped bool        `json:"edges_capped"` // the cap BIT
	NodesCapped bool        `json:"nodes_capped"`
	// PathsDropped counts paths the upstream offered that carried a hop we
	// could not READ, and were therefore dropped instead of spliced. It is the
	// difference between "the upstream gave us nothing" and "the upstream gave
	// us something broken" (CLAUDE.md §10) — the UI shows it as a coverage gap.
	PathsDropped int       `json:"paths_dropped,omitempty"`
	Source       string    `json:"source"` // "bgp-state" | "looking-glass"
	FetchedAt    time.Time `json:"fetched_at"`
	Error        string    `json:"error,omitempty"`
}

// ParseBGPState extracts AS paths from a RIPEstat bgp-state payload.
func ParseBGPState(data json.RawMessage) [][]uint32 {
	var body struct {
		BGPState []struct {
			Path []json.RawMessage `json:"path"`
		} `json:"bgp_state"`
	}
	if json.Unmarshal(data, &body) != nil {
		return nil
	}
	out := make([][]uint32, 0, len(body.BGPState))
	for _, e := range body.BGPState {
		if len(out) >= maxGraphPaths {
			break
		}
		p := make([]uint32, 0, len(e.Path))
		for _, n := range e.Path {
			v, ok := ParseASNValue(n)
			if !ok {
				continue // a hop we cannot read is dropped, never guessed
			}
			p = append(p, v)
		}
		if len(p) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// ParseLookingGlass extracts AS paths from a RIPEstat looking-glass payload
// (as_path is a space-separated string, and may contain AS_SET "{a,b}" braces).
//
// A returned path may contain the reserved AS0 (unreadableHop) where the source
// wrote a hop we could not read. That marker is deliberate evidence, not data:
// BuildASPathGraph counts those paths in PathsDropped and refuses to fold them
// in, because splicing across the gap would invent an adjacency.
func ParseLookingGlass(data json.RawMessage) [][]uint32 {
	var body struct {
		RRCs []struct {
			Peers []struct {
				ASPath string `json:"as_path"`
			} `json:"peers"`
		} `json:"rrcs"`
	}
	if json.Unmarshal(data, &body) != nil {
		return nil
	}
	var out [][]uint32
	for _, rrc := range body.RRCs {
		for _, p := range rrc.Peers {
			if len(out) >= maxGraphPaths {
				return out
			}
			if hops := parseASPathString(p.ASPath); len(hops) > 0 {
				out = append(out, hops)
			}
		}
	}
	return out
}

// parseASPathString turns "3333 1234 {64500,64501}" into hops, taking the FIRST
// member of an AS_SET (the conventional rendering) and dropping garbage tokens.
func parseASPathString(s string) []uint32 {
	var out []uint32
	for _, tok := range strings.Fields(s) {
		tok = strings.Trim(tok, "{}()")
		if tok == "" {
			continue
		}
		tok = strings.SplitN(tok, ",", 2)[0]
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(tok), "AS"), 10, 32)
		if err != nil {
			// A token we cannot READ is a fault in the upstream, not an absent
			// hop. Mark the gap (never guess the ASN) so the graph builder can
			// count it and refuse to fabricate an adjacency across it.
			out = append(out, unreadableHop)
			if len(out) >= maxPathLen {
				break // the gap marker counts against the path bound too (§9)
			}
			continue
		}
		if v == 0 {
			// AS0 is reserved (RFC 7607) and is never a real hop: the source
			// wrote a well-formed "no AS", which is benign, not a failure.
			continue
		}
		out = append(out, uint32(v))
		if len(out) >= maxPathLen {
			break
		}
	}
	return trimUnreadableEdges(out)
}

// trimUnreadableEdges drops leading and trailing gap markers. Only an INTERIOR
// gap can fabricate an adjacency (two hops spliced together across it); a gap
// at either end splices nothing, so keeping it would over-report damage.
func trimUnreadableEdges(p []uint32) []uint32 {
	i, j := 0, len(p)
	for i < j && p[i] == unreadableHop {
		i++
	}
	for j > i && p[j-1] == unreadableHop {
		j--
	}
	return p[i:j]
}

// hasUnreadableHop reports whether a path carries a gap marker.
func hasUnreadableHop(p []uint32) bool {
	for _, a := range p {
		if a == unreadableHop {
			return true
		}
	}
	return false
}

// CompressPath removes AS_PATH prepends (consecutive repeats) and bounds the
// path length. Prepends are traffic engineering, not topology: leaving them in
// would draw a self-loop on every prepending AS.
func CompressPath(p []uint32) []uint32 {
	out := make([]uint32, 0, len(p))
	for _, a := range p {
		if a == 0 {
			continue // AS0 is reserved (RFC 7607) — never a real hop
		}
		if len(out) > 0 && out[len(out)-1] == a {
			continue
		}
		out = append(out, a)
		if len(out) >= maxPathLen {
			break
		}
	}
	return out
}

// BuildASPathGraph folds observed paths into a deduped, capped node-link graph.
// tenantASNs marks the caller's own ASNs; it is caller-supplied and never read
// from the paths themselves.
func BuildASPathGraph(prefix string, paths [][]uint32, tenantASNs map[uint32]bool, source string, now time.Time) ASPathGraph {
	g := ASPathGraph{
		Prefix: prefix, Nodes: []GraphNode{}, Edges: []GraphEdge{}, Origins: []uint32{},
		MaxEdges: MaxGraphEdges, Source: source, FetchedAt: now, PathsSeen: len(paths),
	}
	type key struct{ from, to uint32 }
	edgeCount := map[key]int{}
	nodePaths := map[uint32]int{}
	minDepth := map[uint32]int{}
	originCount := map[uint32]int{}
	vantage := map[uint32]bool{}

	for _, raw := range paths {
		if g.Paths >= maxGraphPaths {
			break
		}
		if hasUnreadableHop(raw) {
			// The upstream wrote a hop we could not read INSIDE this path.
			// Splicing across it would draw an adjacency between two ASes that
			// are not neighbours — a fabricated fact. Drop it and COUNT it.
			g.PathsDropped++
			continue
		}
		p := CompressPath(raw)
		if len(p) == 0 {
			continue
		}
		g.Paths++
		vantage[p[0]] = true
		originCount[p[len(p)-1]]++
		for i, a := range p {
			nodePaths[a]++
			if d, ok := minDepth[a]; !ok || i < d {
				minDepth[a] = i
			}
			if i > 0 {
				edgeCount[key{p[i-1], a}]++
			}
		}
	}

	// Deterministic ordering: strongest adjacency first, ties broken by the ASN
	// pair so the same data always yields the same graph (and the same cut).
	edges := make([]GraphEdge, 0, len(edgeCount))
	for k, c := range edgeCount {
		edges = append(edges, GraphEdge{From: k.from, To: k.to, Peers: c})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Peers != edges[j].Peers {
			return edges[i].Peers > edges[j].Peers
		}
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	if len(edges) > MaxGraphEdges {
		edges, g.EdgesCapped = edges[:MaxGraphEdges], true
	}
	g.Edges = edges

	// Origins are reported even if the edge cut dropped their last hop — the
	// origin is the answer to "who is announcing this", and must never vanish.
	for asn := range originCount {
		g.Origins = append(g.Origins, asn)
	}
	sort.Slice(g.Origins, func(i, j int) bool {
		if originCount[g.Origins[i]] != originCount[g.Origins[j]] {
			return originCount[g.Origins[i]] > originCount[g.Origins[j]]
		}
		return g.Origins[i] < g.Origins[j]
	})

	keep := map[uint32]bool{}
	for _, e := range edges {
		keep[e.From], keep[e.To] = true, true
	}
	for _, o := range g.Origins {
		keep[o] = true
	}
	// A single-hop path (origin only, no adjacency) still has a node.
	if len(edges) == 0 {
		for asn := range nodePaths {
			keep[asn] = true
		}
	}
	nodes := make([]GraphNode, 0, len(keep))
	for asn := range keep {
		nodes = append(nodes, GraphNode{
			ASN: asn, Depth: minDepth[asn], Paths: nodePaths[asn],
			Origin: originCount[asn] > 0, Tenant: tenantASNs[asn],
			Vantage: vantage[asn] && originCount[asn] == 0,
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		if nodes[i].Paths != nodes[j].Paths {
			return nodes[i].Paths > nodes[j].Paths
		}
		return nodes[i].ASN < nodes[j].ASN
	})
	if len(nodes) > maxGraphNodes {
		nodes, g.NodesCapped = nodes[:maxGraphNodes], true
		// Drop edges whose endpoints no longer exist: a dangling edge would be
		// rendered as a link to nothing.
		alive := map[uint32]bool{}
		for _, n := range nodes {
			alive[n.ASN] = true
		}
		kept := g.Edges[:0]
		for _, e := range g.Edges {
			if alive[e.From] && alive[e.To] {
				kept = append(kept, e)
			}
		}
		g.Edges = kept
	}
	g.Nodes = nodes
	if g.Paths == 0 && g.PathsDropped > 0 {
		// An empty graph here is NOT "this prefix has no observed paths": the
		// upstream answered and everything it said was unreadable. Say so, so
		// the panel renders a failed source instead of a quiet blank.
		g.Error = fmt.Sprintf("the upstream returned %d AS path(s) and every one carried a hop that could not be read — "+
			"no graph is drawn rather than one with fabricated adjacencies", g.PathsDropped)
	}
	return g
}

// AnnotateNames fills node names from a caller-supplied holder lookup (the
// RDAP/whois cache). A miss leaves the name EMPTY — the UI shows "AS64500",
// which is honest, rather than a placeholder that looks like a real holder.
func AnnotateNames(g *ASPathGraph, lookup func(asn uint32) string) {
	if lookup == nil {
		return
	}
	for i := range g.Nodes {
		if n := clip(strings.TrimSpace(lookup(g.Nodes[i].ASN)), 60); n != "" {
			g.Nodes[i].Name = n
		}
	}
}
