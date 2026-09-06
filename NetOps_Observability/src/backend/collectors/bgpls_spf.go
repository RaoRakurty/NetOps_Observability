// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import "sort"

// bgpls_spf.go — computes DIRECTED forwarding pairs from the (undirected) BGP-LS /
// IGP link-state graph, for the correlation engine's C7.5 routing-direction source.
//
// Direction comes from SPF toward destinations: for each destination node, the
// shortest-path tree gives every other node its NEXT HOP toward that destination.
// A node forwards toward its next hop, so (node → next hop) is a directed forwarding
// pair in which the node is UPSTREAM (it is farther from the destination, i.e.
// earlier on the path — the same "earlier hop is upstream" rule as a traceroute).
//
// METRIC: the current BGP-LS parser does not extract the IGP metric TLV, so SPF here
// is HOP-COUNT (BFS) — exact for a uniform-cost fabric (the clos lab), an
// approximation under unequal link costs. Metric-weighted SPF is a clean refinement
// once the metric TLV is parsed. A link that is a next hop in BOTH directions (it
// carries traffic toward destinations on either side) yields both ordered pairs →
// the consumer reports AMBIGUOUS, never an assumed direction.
//
// Pure + deterministic: sorted iteration throughout, so the same LSDB always yields
// the same pairs (the orientation is embedded per snapshot and must replay clean).

// RoutingPair is one directed forwarding fact: From forwards toward To (From is
// upstream). Serialized as the correlation engine's routing_direction.json contract.
type RoutingPair struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// forwardingPairs runs BFS from every destination and emits each node's next hop
// toward it as a directed (upstream → downstream) pair. `adj` is the UNDIRECTED
// link graph keyed by node name; `names` is its node set (the destinations).
func forwardingPairs(names []string, adj map[string][]string) []RoutingPair {
	pairs := map[RoutingPair]bool{}
	for _, dst := range names {
		parent := bfsParents(dst, adj)
		for node, next := range parent {
			if node != dst && next != "" && node != next {
				// `next` is one hop closer to dst, so `node` forwards toward `next`.
				pairs[RoutingPair{From: node, To: next}] = true
			}
		}
	}
	out := make([]RoutingPair, 0, len(pairs))
	for p := range pairs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

// bfsParents returns parent[x] = x's next hop toward `root` (the neighbour one hop
// closer to root on a shortest path). Deterministic: neighbours visited in sorted
// order, so ECMP ties break identically every run.
func bfsParents(root string, adj map[string][]string) map[string]string {
	parent := map[string]string{root: ""}
	queue := []string{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		neigh := append([]string(nil), adj[cur]...)
		sort.Strings(neigh)
		for _, n := range neigh {
			if _, seen := parent[n]; !seen {
				parent[n] = cur // cur is one hop closer to root → n's next hop is cur
				queue = append(queue, n)
			}
		}
	}
	return parent
}
