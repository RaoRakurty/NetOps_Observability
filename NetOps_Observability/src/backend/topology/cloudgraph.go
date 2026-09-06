package topology

// cloudgraph.go — the cloud half of the path graph (#130a).
//
// `/api/topology/view?mode=path_trace` resolved a path by Dijkstra over the
// discovered DEVICE fabric, where a cloud subnet's id was not a vertex. The
// endpoint picker therefore had to hide every cloud entity: offering one would
// have advertised a trace the backend could not run.
//
// The fix is to give the projection the cloud objects as VERTICES rather than to
// keep them off the canvas. They arrive already projected (Input.Cloud*) because
// the cloud package owns how a VPC, a subnet and a gateway are drawn; this file
// only merges them and answers the one honesty question that follows: when the
// trace fails, is the reason "no route" or "the seam was never discovered"?

import "sort"

// mergeCloud folds the caller's cloud objects into the view being built and into
// the SPF graph, returning the set of cloud node ids that survived.
//
// The rules are the canvas merge's rules, enforced server-side so the two can
// never disagree: the on-prem inventory wins every id collision (it is the
// operator's own discovery), an edge is kept only when BOTH endpoints survive,
// and a container whose parent did not come across is un-nested rather than
// dropped. Deterministic: cloud objects keep their (already sorted) order and
// the merged node/edge/group slices are re-sorted by id.
func mergeCloud(in Input, nodes *[]Node, edges *[]Edge, groups *[]Group, g *Graph, managed map[string]bool) map[string]bool {
	cloudIDs := map[string]bool{}
	if len(in.CloudNodes) == 0 {
		return cloudIDs
	}

	have := make(map[string]bool, len(*nodes))
	for _, n := range *nodes {
		have[n.ID] = true
	}
	for _, n := range in.CloudNodes {
		if n.ID == "" || have[n.ID] {
			continue // on-prem identity wins
		}
		have[n.ID] = true
		cloudIDs[n.ID] = true
		// A cloud node IS in the caller's authorized inventory — it came from a
		// route the caller was independently scoped for — so it is a legitimate
		// path endpoint and a legitimate materialized hop.
		managed[n.ID] = true
		g.AddNode(n.ID)
		*nodes = append(*nodes, n)
	}

	haveEdge := make(map[string]bool, len(*edges))
	for _, e := range *edges {
		haveEdge[e.ID] = true
	}
	for _, e := range in.CloudEdges {
		if e.ID == "" || haveEdge[e.ID] {
			continue
		}
		if !have[e.Source] || !have[e.Target] {
			continue // never a link to nowhere
		}
		haveEdge[e.ID] = true
		// Cost 1: a cloud adjacency carries no IGP metric, and the graph
		// normalizes 0 to 1 anyway. Hop count is the honest weight.
		g.AddEdge(e.Source, e.Target, 1)
		*edges = append(*edges, e)
	}

	haveGroup := make(map[string]bool, len(*groups))
	for _, gr := range *groups {
		haveGroup[gr.ID] = true
	}
	for _, gr := range in.CloudGroups {
		if gr.ID == "" || haveGroup[gr.ID] {
			continue
		}
		haveGroup[gr.ID] = true
		*groups = append(*groups, gr)
	}
	for i := range *groups {
		if p := (*groups)[i].ParentID; p != "" && !haveGroup[p] {
			(*groups)[i].ParentID = ""
		}
	}

	sort.Slice(*nodes, func(i, j int) bool { return (*nodes)[i].ID < (*nodes)[j].ID })
	sort.Slice(*edges, func(i, j int) bool { return (*edges)[i].ID < (*edges)[j].ID })
	return cloudIDs
}

// noPathState names the honest reason a path_trace resolved nothing, when there
// is one more specific than "no route over the discovered topology".
//
// THE ONLY CASE TODAY (#130b). The endpoints sit on opposite sides of the
// on-prem↔cloud divide and NOT ONE seam adjacency has been discovered to cross
// it. That is a gap in DISCOVERY — a DX/VPN gateway whose on-prem peer was never
// resolved — and it is a different thing to tell an operator than "these two are
// not connected". The alternative, inventing a hop between the WAN edge and the
// cloud gateway because the two obviously must be joined in real life, is
// precisely the token-overlap mistake the frozen path contract exists to
// prevent: a plausible line nobody observed.
//
// Returns "" for every other failure, so the caller falls back to the plain
// no-route state it has always rendered.
func noPathState(in Input, edges []Edge, cloudIDs map[string]bool) string {
	if in.SrcID == "" || in.DstID == "" || len(cloudIDs) == 0 {
		return ""
	}
	if cloudIDs[in.SrcID] == cloudIDs[in.DstID] {
		return "" // both on-prem, or both in cloud — the seam is not the reason
	}
	for _, e := range edges {
		if cloudIDs[e.Source] != cloudIDs[e.Target] {
			return "" // a seam exists; the trace failed for some other reason
		}
	}
	return PathStateNoSeam
}
