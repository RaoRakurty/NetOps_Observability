// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// summary_design.go — the DESIGN READING of a summarized network (NetClaw
// ingestion Batch 0, 2026-11-13): per-site redundancy, single points of
// failure, the protocols each device is seen to run, and what was NOT
// collected. Pure: no I/O.
//
// A network engineer reading a design asks, in order: what is at each site,
// how many ways out does each site have, which single device or link would cut
// something off if it failed, and how much of the network can I actually see.
// The fold answers each from the SAME observed view Summarize reads.
//
// HONESTY RULES (in addition to summary.go's):
//
//   - A single point of failure is computed over DISCOVERED adjacencies only.
//     A link Correlix did not discover can make a listed point redundant, so
//     the list is an INFERENCE (the caller stamps it DERIVED) and it is not
//     computed at all when there is no adjacency evidence to compute it from.
//   - Redundancy Correlix cannot see (LAG membership, first-hop redundancy such
//     as HSRP/VRRP) is never reported as absent: RedundancyNote says it is not
//     collected.
//   - Coverage says which evidence classes the reading rests on, so "no LLDP"
//     is never read as "no links".

import (
	"sort"
	"strings"
)

// Design-reading bounds. Totals always carry the true count.
const (
	SummaryMaxSites      = 20
	SummaryMaxSPOF       = 12
	SummaryMaxRedundancy = 12
	// summarySPOFMaxNodes bounds the single-point-of-failure search (it removes
	// each node and each link in turn). Above it the search is skipped and said.
	summarySPOFMaxNodes = 400
)

// SPOF kinds.
const (
	SPOFDevice = "device"
	SPOFLink   = "link"
)

// Redundancy group kinds this fold can establish from observed evidence.
const (
	RedundancyDualEdge      = "dual_edge"      // a site with two or more WAN edges
	RedundancyDualTransport = "dual_transport" // a site whose edges ride two or more transports
)

// Signal values for the design facts (the ai tool turns them into topo: signals).
const (
	SPOFPresent = "present"
	SPOFNone    = "none"
	SPOFUnknown = "unknown"

	CoverageFull    = "full"
	CoveragePartial = "partial"
)

// SiteSummary is one site read for redundancy.
type SiteSummary struct {
	Name     string
	Devices  int
	WANEdges int
	// Uplinks are discovered adjacencies from this site's devices to a device
	// in another site or outside the managed inventory.
	Uplinks int
	// Transports are the overlay transports (colours) this site's edges ride.
	Transports []string
	// SingleEdge: exactly one WAN edge. SingleTransport: the overlay was read and
	// the site's edges ride exactly one transport. Either makes it SingleHomed.
	SingleEdge      bool
	SingleTransport bool
	SingleHomed     bool
}

// SPOFItem is one single point of failure of the observed graph.
type SPOFItem struct {
	Kind string // device | link
	Name string // the device, or "A ↔ B" for a link
	// Isolates is how many managed devices lose their path to the rest of the
	// network if this fails (the smaller side of the cut).
	Isolates int
}

// RedundancyGroup is one redundancy the observed evidence establishes.
type RedundancyGroup struct {
	Kind    string // dual_edge | dual_transport
	Site    string
	Members []string // the edges (dual_edge) or the transports (dual_transport)
}

// SummaryCoverage says which evidence classes the reading rests on.
type SummaryCoverage struct {
	LinkDiscovery bool // at least one LLDP/CDP adjacency
	RoutedLinks   bool // at least one BGP-LS / IGP routed adjacency
	OverlayRead   bool // the SD-WAN overlay was read since the server started
	SitesKnown    bool // every managed device carries a site
	SPOFComputed  bool // the single-point-of-failure search ran
}

// designInput is what summarizeDesign needs from Summarize's own pass.
type designInput struct {
	devNodes []Node
	names    map[string]string
	managed  map[string]bool
	site     map[string]string
	edges    []Edge // physical / routed adjacencies touching a managed device
	pairs    []OverlayPair
	overlay  bool // the overlay was read
}

// summarizeDesign fills the design-reading fields of out.
func summarizeDesign(in designInput, out *NetworkSummary) {
	// ── protocols per device, from the adjacency evidence ───────────────────
	protos := map[string]map[string]bool{}
	addProto := func(dev, p string) {
		if !in.managed[dev] {
			return
		}
		if protos[dev] == nil {
			protos[dev] = map[string]bool{}
		}
		protos[dev][p] = true
	}
	cov := SummaryCoverage{OverlayRead: in.overlay}
	for _, e := range in.edges {
		for _, p := range edgeProtocols(e) {
			switch p {
			case "lldp", "cdp":
				cov.LinkDiscovery = true
			default:
				cov.RoutedLinks = true
			}
			addProto(e.Source, p)
			addProto(e.Target, p)
		}
	}
	devColors := map[string]map[string]bool{}
	for _, p := range in.pairs {
		for _, d := range []string{p.A, p.B} {
			addProto(d, "overlay")
			if p.Sessions > 0 {
				addProto(d, "bfd")
			}
			if devColors[d] == nil {
				devColors[d] = map[string]bool{}
			}
			for _, c := range p.Colors {
				devColors[d][c] = true
			}
		}
	}
	idxByID := map[string]int{}
	for i, d := range out.Devices {
		idxByID[d.ID] = i
	}
	for dev, set := range protos {
		if i, ok := idxByID[dev]; ok {
			out.Devices[i].Protocols = sortedSet(set)
		}
	}

	// ── sites ────────────────────────────────────────────────────────────────
	type siteAgg struct {
		devices, edges, uplinks int
		edgeNames               []string
		colors                  map[string]bool
	}
	sites := map[string]*siteAgg{}
	cov.SitesKnown = len(in.devNodes) > 0
	for _, n := range in.devNodes {
		if n.Site == "" {
			cov.SitesKnown = false
			continue
		}
		a := sites[n.Site]
		if a == nil {
			a = &siteAgg{colors: map[string]bool{}}
			sites[n.Site] = a
		}
		a.devices++
		if n.DeviceRole == DevRoleWANEdge || n.DeviceRole == DevRoleDCWANEdge {
			a.edges++
			a.edgeNames = append(a.edgeNames, in.names[n.ID])
		}
		for c := range devColors[n.ID] {
			a.colors[c] = true
		}
	}
	for _, e := range in.edges {
		src, dst := e.Source, e.Target
		for _, pair := range [][2]string{{src, dst}, {dst, src}} {
			s := in.site[pair[0]]
			if s == "" || !in.managed[pair[0]] {
				continue
			}
			if !in.managed[pair[1]] || in.site[pair[1]] != s {
				sites[s].uplinks++
			}
		}
	}
	names := make([]string, 0, len(sites))
	for s := range sites {
		names = append(names, s)
	}
	sort.Strings(names)
	var oneTransport []string
	for _, s := range names {
		a := sites[s]
		ss := SiteSummary{Name: s, Devices: a.devices, WANEdges: a.edges, Uplinks: a.uplinks, Transports: sortedSet(a.colors)}
		ss.SingleEdge = a.edges == 1
		ss.SingleTransport = in.overlay && len(ss.Transports) == 1
		ss.SingleHomed = ss.SingleEdge || ss.SingleTransport
		if ss.SingleTransport {
			oneTransport = append(oneTransport, s)
		}
		out.SiteDetails = append(out.SiteDetails, ss)
		sort.Strings(a.edgeNames)
		if a.edges >= 2 {
			out.RedundancyGroups = append(out.RedundancyGroups, RedundancyGroup{Kind: RedundancyDualEdge, Site: s, Members: a.edgeNames})
		}
		if len(ss.Transports) >= 2 {
			out.RedundancyGroups = append(out.RedundancyGroups, RedundancyGroup{Kind: RedundancyDualTransport, Site: s, Members: ss.Transports})
		}
	}
	out.SitesTotal = len(out.SiteDetails)
	if len(out.SiteDetails) > SummaryMaxSites {
		out.SiteDetails = out.SiteDetails[:SummaryMaxSites]
	}
	out.RedundancyTotal = len(out.RedundancyGroups)
	if len(out.RedundancyGroups) > SummaryMaxRedundancy {
		out.RedundancyGroups = out.RedundancyGroups[:SummaryMaxRedundancy]
	}
	out.RedundancyNote = "link aggregation (LAG) membership and first-hop redundancy (HSRP/VRRP) are not collected — redundancy of those kinds is UNKNOWN here, not absent"
	if out.Overlay != nil {
		out.Overlay.SitesOnOneTransport = oneTransport
	}

	// ── single points of failure over the observed graph ────────────────────
	adj := map[string]map[string]bool{}
	link := func(a, b string) {
		if a == b || !in.managed[a] || !in.managed[b] {
			return
		}
		if adj[a] == nil {
			adj[a] = map[string]bool{}
		}
		if adj[b] == nil {
			adj[b] = map[string]bool{}
		}
		adj[a][b], adj[b][a] = true, true
	}
	for _, e := range in.edges {
		link(e.Source, e.Target)
	}
	for _, p := range in.pairs {
		link(p.A, p.B)
	}
	switch {
	case len(adj) == 0:
		out.SPOFState = SPOFUnknown
		out.Notes = append(out.Notes, "no adjacency between managed devices was discovered, so single points of failure could not be computed")
	case len(adj) > summarySPOFMaxNodes:
		out.SPOFState = SPOFUnknown
		out.Notes = append(out.Notes, "the network is larger than the single-point-of-failure search covers in one answer, so it was not computed")
	default:
		cov.SPOFComputed = true
		out.SPOF = findSPOF(adj, in.names)
		out.SPOFTotal = len(out.SPOF)
		if len(out.SPOF) > SummaryMaxSPOF {
			out.SPOF = out.SPOF[:SummaryMaxSPOF]
		}
		out.SPOFState = SPOFNone
		if out.SPOFTotal > 0 {
			out.SPOFState = SPOFPresent
		}
	}
	out.Coverage = cov
	out.CoverageState = CoveragePartial
	if (cov.LinkDiscovery || cov.RoutedLinks || len(in.pairs) > 0) && cov.SitesKnown {
		out.CoverageState = CoverageFull
	}
}

// edgeProtocols names the protocols one adjacency was learned from: lldp/cdp
// from the edge itself, and for a BGP-LS link the IGP that originated it.
func edgeProtocols(e Edge) []string {
	var out []string
	for _, p := range strings.Split(strings.ToLower(e.Protocol), "+") {
		switch p = strings.TrimSpace(p); p {
		case "lldp", "cdp":
			out = append(out, p)
		case "bgp_ls":
			for _, ev := range e.Evidence {
				d := strings.ToLower(strings.TrimSpace(ev.Detail))
				switch {
				case strings.HasPrefix(d, "isis"):
					out = append(out, "isis")
				case strings.HasPrefix(d, "ospf"):
					out = append(out, "ospf")
				}
			}
		}
	}
	return out
}

// findSPOF returns the articulation points and bridges of the graph, each with
// how many devices it would cut off, most consequential first. The graph is
// small (bounded by summarySPOFMaxNodes), so each candidate is removed and the
// component re-walked: simple, and correct by construction.
func findSPOF(adj map[string]map[string]bool, names map[string]string) []SPOFItem {
	nodes := make([]string, 0, len(adj))
	for n := range adj {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	// cut reports how many nodes of start's component are separated from its
	// largest remaining part when `skipNode` (or the link skipA–skipB) is gone.
	component := func(start, skipNode, skipA, skipB string, seen map[string]bool) int {
		stack, size := []string{start}, 0
		seen[start] = true
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			size++
			for m := range adj[n] {
				if m == skipNode || seen[m] || (n == skipA && m == skipB) || (n == skipB && m == skipA) {
					continue
				}
				seen[m] = true
				stack = append(stack, m)
			}
		}
		return size
	}
	isolated := func(roots []string, skipNode, skipA, skipB string) int {
		seen := map[string]bool{}
		if skipNode != "" {
			seen[skipNode] = true
		}
		var sizes []int
		for _, r := range roots {
			if seen[r] {
				continue
			}
			sizes = append(sizes, component(r, skipNode, skipA, skipB, seen))
		}
		if len(sizes) < 2 {
			return 0
		}
		total, largest := 0, 0
		for _, s := range sizes {
			total += s
			if s > largest {
				largest = s
			}
		}
		return total - largest
	}
	var out []SPOFItem
	for _, v := range nodes {
		if len(adj[v]) < 2 {
			continue // a leaf is not a cut vertex; its single LINK is (below)
		}
		var nbrs []string
		for m := range adj[v] {
			nbrs = append(nbrs, m)
		}
		sort.Strings(nbrs)
		if n := isolated(nbrs, v, "", ""); n > 0 {
			out = append(out, SPOFItem{Kind: SPOFDevice, Name: names[v], Isolates: n})
		}
	}
	for _, a := range nodes {
		for b := range adj[a] {
			if b < a {
				continue
			}
			if n := isolated([]string{a, b}, "", a, b); n > 0 {
				out = append(out, SPOFItem{Kind: SPOFLink, Name: names[a] + " ↔ " + names[b], Isolates: n})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Isolates != out[j].Isolates {
			return out[i].Isolates > out[j].Isolates
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == SPOFDevice
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
