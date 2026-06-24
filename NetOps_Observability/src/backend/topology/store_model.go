package topology

import (
	"sort"
	"time"
)

// store_model.go — the PERSISTED topology graph model and its pure reconcile +
// projection logic (#77). This is the spine behind GET /api/topology/graph: a
// background reconciler folds the live OBSERVED graph (this cycle's deduped
// adjacencies + inventory) into the PERSISTED graph, and this file owns the merge
// rule. It stays in the pure topology package — no HTTP/DB/Redis — so the
// first_seen/last_seen/stale lifecycle is fully unit-testable with mock records
// (CLAUDE.md §11). The package-main store does the I/O; the merge stays here.
//
// Honesty rule (CLAUDE.md §3 zero-trust on telemetry): a node/edge that stops
// being observed is NOT deleted on the first miss — it is kept and, after a grace
// window, marked Stale. Only after a longer prune window is it dropped. A single
// missed poll must never make a real link silently disappear.

// NodeRecord is one persisted topology node. The id is the managed device id
// (stable across requests — the whole point of persistence). TenantID is the
// owning tenant ("" = global/platform-owned); it is stamped from the device, never
// from a request body.
type NodeRecord struct {
	TenantID  string    `json:"tenant_id"`
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Kind      string    `json:"kind"`
	Role      string    `json:"role,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
	Model     string    `json:"model,omitempty"`
	Site      string    `json:"site,omitempty"`
	Rack      string    `json:"rack,omitempty"`
	MgmtIP    string    `json:"mgmt_ip,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Stale     bool      `json:"stale"`
}

// EdgeRecord is one persisted topology edge. The id is deterministic (see EdgeID)
// so the same adjacency keeps the same id across reconcile cycles — required for an
// RCA overlay to bind to it. An edge's tenant is its SOURCE device's tenant.
type EdgeRecord struct {
	TenantID      string    `json:"tenant_id"`
	ID            string    `json:"id"`
	Source        string    `json:"source"`
	Target        string    `json:"target"`
	SourcePort    string    `json:"source_port,omitempty"`
	TargetPort    string    `json:"target_port,omitempty"`
	Protocol      string    `json:"protocol,omitempty"` // lldp|cdp|bgp_ls ("+"-joined when several confirm)
	IGP           string    `json:"igp,omitempty"`
	Area          string    `json:"area,omitempty"`
	Resolved      bool      `json:"resolved"`
	Bidirectional bool      `json:"bidirectional"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Stale         bool      `json:"stale"`
}

// GraphRecords is a whole persisted graph (all tenants when held by the
// reconciler; a single tenant's slice when returned by a scoped Snapshot).
type GraphRecords struct {
	Nodes []NodeRecord
	Edges []EdgeRecord
}

// KindOf returns the canonical node Kind for a device fact — the exported wrapper
// the persistence reconciler uses so a persisted NodeRecord.Kind is derived by the
// exact same rule as the live /view projection.
func KindOf(f DeviceFact) string { return nodeKind(f) }

// nodeKey / edgeKey identify a record across cycles. Tenant is part of the key so
// a node id reused across tenants (shouldn't happen, but zero-trust) never merges.
func nodeKey(tenant, id string) [2]string { return [2]string{tenant, id} }
func edgeKey(tenant, id string) [2]string { return [2]string{tenant, id} }

// Reconcile merges the OBSERVED graph into the PREVIOUS persisted graph and
// returns the new persisted graph. Pure — no I/O, deterministic ordering.
//
//   - observed record → fresh: LastSeen=now, Stale=false, mutable fields refreshed,
//     FirstSeen preserved from prev (or now for a brand-new record).
//   - previous record NOT observed this cycle:
//   - dropped if pruneAfter>0 and now-LastSeen > pruneAfter (long gone);
//   - else marked Stale if now-LastSeen > staleAfter (grace expired);
//   - else kept unchanged (transient miss inside the grace window).
//
// staleAfter<=0 falls back to 15m; pruneAfter<=0 disables pruning (stale rows are
// kept indefinitely — an operator deletes inventory explicitly).
func Reconcile(prev, observed GraphRecords, now time.Time, staleAfter, pruneAfter time.Duration) GraphRecords {
	if staleAfter <= 0 {
		staleAfter = 15 * time.Minute
	}

	prevNodes := make(map[[2]string]NodeRecord, len(prev.Nodes))
	for _, n := range prev.Nodes {
		prevNodes[nodeKey(n.TenantID, n.ID)] = n
	}
	prevEdges := make(map[[2]string]EdgeRecord, len(prev.Edges))
	for _, e := range prev.Edges {
		prevEdges[edgeKey(e.TenantID, e.ID)] = e
	}

	out := GraphRecords{
		Nodes: make([]NodeRecord, 0, len(observed.Nodes)),
		Edges: make([]EdgeRecord, 0, len(observed.Edges)),
	}
	seenNodes := make(map[[2]string]bool, len(observed.Nodes))
	seenEdges := make(map[[2]string]bool, len(observed.Edges))

	// 1. Observed records → fresh (preserving FirstSeen).
	for _, n := range observed.Nodes {
		if n.ID == "" {
			continue // zero-trust: never persist a degenerate record
		}
		k := nodeKey(n.TenantID, n.ID)
		n.FirstSeen = now
		if p, ok := prevNodes[k]; ok && !p.FirstSeen.IsZero() {
			n.FirstSeen = p.FirstSeen
		}
		n.LastSeen = now
		n.Stale = false
		out.Nodes = append(out.Nodes, n)
		seenNodes[k] = true
	}
	for _, e := range observed.Edges {
		if e.ID == "" || e.Source == "" || e.Target == "" {
			continue
		}
		k := edgeKey(e.TenantID, e.ID)
		e.FirstSeen = now
		if p, ok := prevEdges[k]; ok && !p.FirstSeen.IsZero() {
			e.FirstSeen = p.FirstSeen
		}
		e.LastSeen = now
		e.Stale = false
		out.Edges = append(out.Edges, e)
		seenEdges[k] = true
	}

	// 2. Previously-persisted records not observed this cycle → age out.
	for k, n := range prevNodes {
		if seenNodes[k] {
			continue
		}
		if pruneAfter > 0 && now.Sub(n.LastSeen) > pruneAfter {
			continue // dropped (long gone)
		}
		if now.Sub(n.LastSeen) > staleAfter {
			n.Stale = true
		}
		out.Nodes = append(out.Nodes, n)
	}
	for k, e := range prevEdges {
		if seenEdges[k] {
			continue
		}
		if pruneAfter > 0 && now.Sub(e.LastSeen) > pruneAfter {
			continue
		}
		if now.Sub(e.LastSeen) > staleAfter {
			e.Stale = true
		}
		out.Edges = append(out.Edges, e)
	}

	sortRecords(&out)
	return out
}

// sortRecords gives a stable, deterministic order (tenant, then id) so the
// persisted set and every snapshot render identically across runs.
func sortRecords(g *GraphRecords) {
	sort.Slice(g.Nodes, func(i, j int) bool {
		if g.Nodes[i].TenantID != g.Nodes[j].TenantID {
			return g.Nodes[i].TenantID < g.Nodes[j].TenantID
		}
		return g.Nodes[i].ID < g.Nodes[j].ID
	})
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].TenantID != g.Edges[j].TenantID {
			return g.Edges[i].TenantID < g.Edges[j].TenantID
		}
		return g.Edges[i].ID < g.Edges[j].ID
	})
}

// Coverage summarizes a snapshot for the /graph response — a NOC needs to know at
// a glance how complete and how fresh the persisted picture is.
type Coverage struct {
	Nodes         int `json:"nodes"`
	Edges         int `json:"edges"`
	StaleNodes    int `json:"stale_nodes"`
	StaleEdges    int `json:"stale_edges"`
	ResolvedEdges int `json:"resolved_edges"` // both endpoints managed (vs ext: boundary)
}

// Summarize computes coverage over a (already tenant-scoped) snapshot.
func (g GraphRecords) Summarize() Coverage {
	c := Coverage{Nodes: len(g.Nodes), Edges: len(g.Edges)}
	for _, n := range g.Nodes {
		if n.Stale {
			c.StaleNodes++
		}
	}
	for _, e := range g.Edges {
		if e.Stale {
			c.StaleEdges++
		}
		if e.Resolved {
			c.ResolvedEdges++
		}
	}
	return c
}

// FilterTenant returns the records visible to a (tenant, cross) principal — the
// in-memory store's scoping primitive (the pg store uses RLS instead). cross=true
// (platform owner) sees everything; otherwise an exact tenant match. Mirrors the
// sameTenant rule used by every other in-memory store.
func (g GraphRecords) FilterTenant(tenant string, cross bool) GraphRecords {
	if cross {
		return GraphRecords{Nodes: append([]NodeRecord(nil), g.Nodes...), Edges: append([]EdgeRecord(nil), g.Edges...)}
	}
	out := GraphRecords{}
	for _, n := range g.Nodes {
		if n.TenantID == tenant {
			out.Nodes = append(out.Nodes, n)
		}
	}
	for _, e := range g.Edges {
		if e.TenantID == tenant {
			out.Edges = append(out.Edges, e)
		}
	}
	return out
}

// ToView projects a persisted (tenant-scoped) snapshot into the canonical render
// contract the frontend already consumes (Node/Edge), so GET /api/topology/graph
// needs no new frontend type. This is the STRUCTURAL view: health is "unknown"
// (the persisted spine carries topology, not live state — live health/util stays
// on /api/topology/view, and folding it in is the next enrichment step). A stale
// record surfaces as change_state="stale" so the UI can mute it honestly.
func (g GraphRecords) ToView(tenant string, now time.Time) View {
	v := View{
		ViewID:      "graph-" + tenant,
		Mode:        ModeExplore,
		Scope:       Scope{TenantID: tenant},
		LayoutType:  "layered",
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Nodes:       make([]Node, 0, len(g.Nodes)),
		Edges:       make([]Edge, 0, len(g.Edges)),
		Groups:      []Group{},
		Overlays:    []string{},
	}
	for _, n := range g.Nodes {
		change := ChangeUnchanged
		if n.Stale {
			change = ChangeStale
		}
		v.Nodes = append(v.Nodes, Node{
			ID:          n.ID,
			Label:       n.Label,
			Kind:        orUnresolved(n.Kind),
			Role:        n.Role,
			Vendor:      n.Vendor,
			Model:       n.Model,
			Site:        n.Site,
			Rack:        n.Rack,
			MgmtIP:      n.MgmtIP,
			Owner:       n.Owner,
			Health:      HealthUnknown,
			Confidence:  1,
			Resolved:    true,
			FirstSeen:   rfc3339(n.FirstSeen),
			LastSeen:    rfc3339(n.LastSeen),
			ChangeState: change,
			Evidence:    []EvidenceRef{{Source: "inventory", Confidence: 1, ObservedAt: rfc3339(n.LastSeen)}},
		})
	}
	for _, e := range g.Edges {
		change := ChangeUnchanged
		if e.Stale {
			change = ChangeStale
		}
		rel := RelConnectedTo
		if isRoutedProtocol(e.Protocol) {
			rel = RelRoutedAdjacency
		}
		v.Edges = append(v.Edges, Edge{
			ID:           e.ID,
			Source:       e.Source,
			Target:       e.Target,
			SourcePort:   e.SourcePort,
			TargetPort:   e.TargetPort,
			Relationship: rel,
			Protocol:     e.Protocol,
			Status:       StatusUnknown,
			Confidence:   recordEdgeConfidence(e.Protocol),
			FirstSeen:    rfc3339(e.FirstSeen),
			LastSeen:     rfc3339(e.LastSeen),
			ChangeState:  change,
			Evidence:     recordEdgeEvidence(e),
		})
	}
	return v
}

// EnrichLive overlays live signals onto a structural persisted view (the output of
// ToView): per-node Health from active alerts — using the SAME rule as the live
// projection (AlertSeverityHealth) — falling back to OK for a fresh node with no
// alert or UNKNOWN for a stale one, plus cpu/mem/alert_count metrics. Edges are
// enriched separately by the package-main handler (interface-keyed link metrics
// need the vendor-ifname canonicalization that lives there). Pure + tested; the
// caller gathers the tenant-scoped signals.
func (v *View) EnrichLive(alertsByDevice map[string][]AlertFact, cpu, mem map[string]float64) {
	for i := range v.Nodes {
		n := &v.Nodes[i]
		al := alertsByDevice[n.ID]
		switch {
		case AlertSeverityHealth(al) != "":
			n.Health = AlertSeverityHealth(al)
		case n.ChangeState == ChangeStale:
			n.Health = HealthUnknown
		default:
			n.Health = HealthOK
		}
		n.Issues = nodeIssues(al) // why-it's-critical, same as the live projection
		m := map[string]float64{"alert_count": float64(len(al))}
		if c, ok := cpu[n.ID]; ok {
			m["cpu_pct"] = c
		}
		if mm, ok := mem[n.ID]; ok {
			m["mem_pct"] = mm
		}
		n.Metrics = m
	}
}

func orUnresolved(k string) string {
	if k == "" {
		return KindUnresolved
	}
	return k
}

// isRoutedProtocol reports whether the (possibly "+"-joined) protocol string
// includes a routed/IGP source, which makes the edge a routed adjacency rather
// than an L2 physical link.
func isRoutedProtocol(proto string) bool {
	for _, p := range splitPlus(proto) {
		if p == "bgp_ls" {
			return true
		}
	}
	return false
}

// recordEdgeConfidence: an edge confirmed by more than one protocol (e.g.
// lldp+cdp) is independently corroborated → full confidence; a single source is
// high but not certain. Mirrors the "independent observer = confirmed" rule
// (design §mapping). (The LinkFact-keyed edgeConfidence in project.go is the
// live-projection twin; this one keys off a persisted EdgeRecord's protocol.)
func recordEdgeConfidence(proto string) float64 {
	if len(splitPlus(proto)) > 1 {
		return 1
	}
	return 0.85
}

func recordEdgeEvidence(e EdgeRecord) []EvidenceRef {
	parts := splitPlus(e.Protocol)
	if len(parts) == 0 {
		return []EvidenceRef{{Source: "inventory", Confidence: 0.5, ObservedAt: rfc3339(e.LastSeen)}}
	}
	out := make([]EvidenceRef, 0, len(parts))
	for _, p := range parts {
		out = append(out, EvidenceRef{Source: p, Confidence: recordEdgeConfidence(e.Protocol), ObservedAt: rfc3339(e.LastSeen)})
	}
	return out
}

// splitPlus splits a "+"-joined protocol token ("lldp+cdp") into its parts,
// dropping empties.
func splitPlus(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '+' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
