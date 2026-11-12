// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// topology_context.go — the ONE topology model of an RCA case (RCA document v2,
// docs/design/RCA_DOCUMENT_V2_2026-11-12.md §2). The report, the path view, the
// UI and the PDF all consume this struct; it is built once per request by
// BuildTopologyContext.
//
// Before it, the document had a single topology source — the measured probe
// path — and decided "this correlation object is not path-shaped" before any
// topology store was read (P-3E0400). Here the known topology (inventory,
// LLDP/CDP/BGP-LS, the persisted reconciled graph, the SD-WAN overlay and the
// controller's sessions) is read FIRST, and the measured path becomes one
// optional layer of it.
//
// Three layers, never conflated:
//
//  1. Topology context — the 1-hop ego-graph of the affected devices, each node
//     and edge carrying its source and freshness. Capped at TopoCtxMaxNodes.
//  2. Measured fault overlay — devices and interfaces that carry attached
//     anomalous evidence. Observed; it never implies causation.
//  3. Causal overlay — from the engine's stage [5] corr_edges and the verdict:
//     verified (authoritative grounding + confirmed verdict + a direction),
//     suspected (a direction vote or a suspected verdict), unknown (no
//     direction, or a known link with no engine edge across it).
//
// NEVER INVENT: every node id, edge id and edge endpoint comes from a source
// row (inventory, a topology link row, an attached signal, a corr_edges row).
// The builder joins and filters rows; it never synthesises an adjacency
// (TestTopologyContextNeverInvents is the property test).
//
// The engine is not changed by any of this (src/correlation/CLAUDE.md): the
// overlays read what stage [5] already persists (grounding_kind,
// grounding_ref, direction_basis, direction_conf).

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ── interfaces first (CLAUDE.md §5/§7) ──────────────────────────────────────

// TopologySourceReader is the topology stores as the builder needs them. It is
// an interface because every store behind it is an external dependency (the
// device registry, the collector's neighbour tables, the Postgres-backed graph,
// the SD-WAN overlay snapshot), and because a test must drive the builder with
// crafted rows. The implementation MUST scope every row to q.OwnerTenant AND to
// the calling principal's visibility before returning it: the builder trusts
// the reader's scope and adds none of its own.
type TopologySourceReader interface {
	ReadTopology(ctx context.Context, q TopologyQuery) (TopologyRead, error)
}

// TopologyQuery is one read: the object owner's canonical tenant and the
// device ids the case is anchored on.
type TopologyQuery struct {
	OwnerTenant string
	Devices     []string
	Now         time.Time
}

// TopologyRead is what the reader found: inventory rows for the anchors and
// their resolved neighbours, the link rows that touch an anchor, and one
// TopologySourceRead per source it consulted (so "read and empty" and "could
// not be read" stay different facts).
type TopologyRead struct {
	Inventory []InventoryRow
	Links     []TopologyLinkRow
	Reads     []TopologySourceRead
}

// InventoryRow is one device record of the object owner's inventory.
type InventoryRow struct {
	ID        string
	Name      string
	Address   string
	Role      string
	Source    string // inventory source (snmp, netbox, manual, integration…)
	FirstSeen time.Time
	LastSeen  time.Time
	Stale     bool
}

// TopologyLinkRow is one adjacency row as a source states it. ID is the row's
// own id (the persisted graph's EdgeID, the overlay edge id, or the same
// EdgeID derivation for a live LLDP/CDP/BGP-LS link), so the same physical
// link read from two stores merges onto one edge.
type TopologyLinkRow struct {
	ID            string
	Sources       []string // TopoSrc* kinds that reported this row
	A, APort      string
	ALabel        string
	B, BPort      string
	BLabel        string
	BManaged      bool   // B resolves to an inventory device
	Relationship  string // physical | routing | overlay | membership
	Protocol      string // lldp | cdp | bgp_ls | sdwan_bfd | sdwan_tloc ("+"-joined when several confirm)
	Confidence    float64
	Bidirectional bool
	FirstSeen     time.Time
	LastSeen      time.Time
	Stale         bool
}

// TopologySourceRead records one consulted source and what it returned.
type TopologySourceRead struct {
	Kind   string // a TopoSrc* kind
	Status string // read | unavailable | not_configured
	Rows   int    // rows that touched an anchor
	Detail string // operator-facing; never a raw error string
}

// Source kinds. The plan's list (lldp|cdp|bgp_ls|sdwan_overlay|controller|
// inventory) plus topology_graph, the persisted reconciled graph — a store,
// not a protocol, but a distinct source with its own first/last-seen.
const (
	TopoSrcLLDP          = "lldp"
	TopoSrcCDP           = "cdp"
	TopoSrcBGPLS         = "bgp_ls"
	TopoSrcGraph         = "topology_graph"
	TopoSrcSDWANOverlay  = "sdwan_overlay"
	TopoSrcController    = "controller"
	TopoSrcInventory     = "inventory"
	TopoReadOK           = "read"
	TopoReadUnavailable  = "unavailable"
	TopoReadNotAvailable = "not_configured"
)

// States (§2 table).
const (
	TopoStateWithPath       = "topology_with_path"
	TopoStateTopologyOnly   = "topology_only"
	TopoStateDeviceOnly     = "device_only"
	TopoStateNoAssetMapping = "no_asset_mapping"
)

// Causal relations (§2 layer 3).
const (
	CausalVerified  = "verified"
	CausalSuspected = "suspected"
	CausalUnknown   = "unknown"
)

// TopoCtxMaxNodes caps the ego-graph; the rest is counted in MoreNodes.
const TopoCtxMaxNodes = 24

// topoCtxMaxEvidenceRefs bounds the evidence ids carried per mark.
const topoCtxMaxEvidenceRefs = 20

// topoCtxLiveStaleAfter: a live adjacency unseen this long reads stale — the
// same grace the reconciler gives a persisted row (topologyStaleAfter).
const topoCtxLiveStaleAfter = 15 * time.Minute

// ── the model (the JSON contract WS-B/WS-C consume) ─────────────────────────

// TopologyContext is §2's struct. Field changes against the plan, each for a
// reason: Remediation is a list (both renderers draw steps; a joined string
// would be split again); Anchors/Unmapped name the ego centre and the anchors
// the inventory does not know; MoreNodes is the "N more"; per-source Status/
// Rows let the device card say which sources were read and came back empty.
type TopologyContext struct {
	State       string           `json:"state"`
	Sources     []TopologySource `json:"sources"`
	Anchors     []string         `json:"anchors"`
	Unmapped    []string         `json:"unmapped,omitempty"`
	Nodes       []TopoCtxNode    `json:"nodes"`
	Edges       []TopoCtxEdge    `json:"edges"`
	MoreNodes   int              `json:"more_nodes"`
	Faults      []FaultMark      `json:"faults"`
	Causal      []CausalMark     `json:"causal"`
	Spine       *TopologyView    `json:"spine,omitempty"`
	Reason      string           `json:"reason"`
	Remediation []string         `json:"remediation,omitempty"`
}

// TopologySource is one consulted source as the document states it.
type TopologySource struct {
	Kind       string `json:"kind"`
	Status     string `json:"status"` // read | unavailable | not_configured
	Rows       int    `json:"rows"`
	ObservedAt string `json:"observed_at,omitempty"` // newest row last-seen (RFC 3339 UTC)
	Stale      bool   `json:"stale"`
	Freshness  string `json:"freshness"` // current | stale | empty | unavailable | not_configured
	Detail     string `json:"detail,omitempty"`
}

// TopoCtxNode is a device (or an unresolved neighbour / a WAN transport) in
// the ego-graph.
type TopoCtxNode struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Role      string `json:"role,omitempty"`
	Source    string `json:"source"` // inventory, or the link source that named it
	Anchor    bool   `json:"anchor"`
	Managed   bool   `json:"managed"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Stale     bool   `json:"stale"`
}

// TopoCtxEdge is one known adjacency between two drawn nodes.
type TopoCtxEdge struct {
	ID            string   `json:"id"`
	A             string   `json:"a"`
	APort         string   `json:"a_port,omitempty"`
	B             string   `json:"b"`
	BPort         string   `json:"b_port,omitempty"`
	Relationship  string   `json:"relationship"`
	Protocol      string   `json:"protocol,omitempty"`
	Sources       []string `json:"sources"`
	Confidence    float64  `json:"confidence,omitempty"`
	Bidirectional bool     `json:"bidirectional"`
	FirstSeen     string   `json:"first_seen,omitempty"`
	LastSeen      string   `json:"last_seen,omitempty"`
	Stale         bool     `json:"stale"`
	Freshness     string   `json:"freshness"` // current | stale | after_incident
}

// FaultMark is layer 2: an observed anomaly on a device or interface. It
// carries no causal claim.
type FaultMark struct {
	TargetType   string   `json:"target_type"` // node | interface
	TargetID     string   `json:"target_id"`   // device id, or "<device>:<port>"
	Device       string   `json:"device"`
	Port         string   `json:"port,omitempty"`
	Kinds        []string `json:"kinds"`
	PeakSeverity string   `json:"peak_severity"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// CausalMark is layer 3: one engine edge (or one known link the engine has no
// edge across) with its causal reading.
type CausalMark struct {
	From          string   `json:"from"`
	FromType      string   `json:"from_type"`
	FromKind      string   `json:"from_kind,omitempty"`
	To            string   `json:"to"`
	ToType        string   `json:"to_type"`
	ToKind        string   `json:"to_kind,omitempty"`
	Relation      string   `json:"relation"` // verified | suspected | unknown
	Directed      bool     `json:"directed"`
	Basis         string   `json:"basis"`
	DirectionConf float64  `json:"direction_conf"`
	EvidenceRefs  []string `json:"evidence_refs"`
}

// TopologyContextInput is the case side of the build: the object meta, the
// attached signals (MergeTimelineEvidence has stamped `attached`), the
// corr_edges rows, the verdict tier, and the existing measured spine.
type TopologyContextInput struct {
	OwnerTenant string
	Meta        map[string]any
	Signals     []map[string]any
	Edges       []map[string]any
	Verdict     string
	Spine       *TopologyView
	Now         time.Time
}

// ── builder ─────────────────────────────────────────────────────────────────

// BuildTopologyContext reads the topology sources through reader (nil = none
// wired) and assembles the context. A reader error is never a finding: the
// sources it could not read are stated as unavailable.
func BuildTopologyContext(ctx context.Context, reader TopologySourceReader, in TopologyContextInput) TopologyContext {
	anchors := topoCtxAnchors(in.Meta, in.Signals)
	var read TopologyRead
	var readErr error
	if reader == nil {
		readErr = errTopologyReaderAbsent
	} else if len(anchors) > 0 {
		read, readErr = reader.ReadTopology(ctx, TopologyQuery{OwnerTenant: in.OwnerTenant, Devices: anchors, Now: in.Now})
	}
	return AssembleTopologyContext(in, read, readErr)
}

type topoCtxErr string

func (e topoCtxErr) Error() string { return string(e) }

const errTopologyReaderAbsent = topoCtxErr("topology sources are not wired on this deployment")

// AssembleTopologyContext is the pure half: deterministic in its inputs, no
// I/O. Exported so the two endpoints and the tests share one derivation.
func AssembleTopologyContext(in TopologyContextInput, read TopologyRead, readErr error) TopologyContext {
	tc := TopologyContext{Anchors: topoCtxAnchors(in.Meta, in.Signals)}
	if in.Spine != nil && in.Spine.Available {
		sp := *in.Spine
		sp.Hops = append([]SpineHopView(nil), in.Spine.Hops...)
		topoCtxStampSpineWindow(&sp, in.Meta)
		tc.Spine = &sp
	}
	windowEnd, hasWindowEnd := parseChTS(asString(in.Meta["window_end"]))

	// inventory by id, then by name/address (an anchor spelled by name maps to
	// the inventory row's id — the source row's id, never the spelling).
	byID := map[string]InventoryRow{}
	byAlias := map[string]string{}
	for _, d := range read.Inventory {
		if d.ID == "" {
			continue
		}
		byID[d.ID] = d
		for _, k := range []string{d.Name, d.Address} {
			if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
				if _, dup := byAlias[k]; !dup {
					byAlias[k] = d.ID
				}
			}
		}
	}
	resolve := func(id string) (string, bool) {
		if _, ok := byID[id]; ok {
			return id, true
		}
		if rid, ok := byAlias[strings.ToLower(strings.TrimSpace(id))]; ok {
			return rid, true
		}
		return "", false
	}
	anchorSet := map[string]bool{}
	var anchorIDs []string
	for _, a := range tc.Anchors {
		if rid, ok := resolve(a); ok {
			if !anchorSet[rid] {
				anchorSet[rid] = true
				anchorIDs = append(anchorIDs, rid)
			}
		} else {
			tc.Unmapped = append(tc.Unmapped, a)
		}
	}
	sort.Strings(anchorIDs)

	// layer 1: links touching an anchor, oriented anchor-first, merged by id.
	edges := topoCtxEdgesFrom(read.Links, anchorSet, in.Now, windowEnd, hasWindowEnd)

	// node cap: anchors first, then neighbours by degree, managed, id.
	nodes, kept, more := topoCtxNodes(anchorIDs, edges, byID, read.Links)
	tc.MoreNodes = more
	tc.Nodes = nodes
	for _, e := range edges {
		if kept[e.A] && kept[e.B] {
			tc.Edges = append(tc.Edges, e)
		}
	}

	// layer 2 + 3.
	tc.Faults = topoCtxFaults(in.Signals)
	tc.Causal = topoCtxCausal(in, tc.Faults, tc.Edges)

	if len(tc.Anchors) > 0 || readErr != nil {
		tc.Sources = topoCtxSources(read, readErr, tc.Edges, len(anchorIDs))
	} else {
		tc.Sources = []TopologySource{} // nothing to anchor on: no source was consulted
	}

	// state + reason + remediation.
	switch {
	case readErr != nil && len(tc.Anchors) > 0 && len(read.Inventory) == 0 && tc.Spine == nil:
		tc.State = TopoStateNoAssetMapping
		tc.Reason = "The topology sources could not be read when this report was generated, so the affected " +
			topoCtxCount(len(tc.Anchors), "entity", "entities") + " (" + topoCtxList(tc.Anchors, 4) +
			") could not be placed in the network. This is a data-availability gap, not a finding."
		tc.Remediation = []string{"Regenerate this report once the inventory and topology services are reachable."}
	case tc.Spine != nil:
		tc.State = TopoStateWithPath
		tc.Reason = "A measured path is attached to this case"
		if len(tc.Edges) > 0 {
			tc.Reason += ", and the known topology around the affected devices is drawn with it."
		} else {
			tc.Reason += "; no known adjacency was found around the affected devices, so only the measured path is drawn."
		}
	case len(tc.Edges) > 0:
		tc.State = TopoStateTopologyOnly
		tc.Reason = "No measured path is attached to this case. The topology drawn is the known adjacency around the affected " +
			topoCtxCount(len(anchorIDs), "device", "devices") + " from " + topoCtxSourceWords(tc.Sources) +
			"; the causal path across it is unverified."
		tc.Remediation = []string{"To verify the causal path, add an active path test toward the affected service so a measured path can be attached."}
	case len(anchorIDs) > 0:
		tc.State = TopoStateDeviceOnly
		tc.Reason = topoCtxList(anchorIDs, 4) + " " + topoCtxIsAre(len(anchorIDs)) +
			" in the inventory, but no neighbour or path data was found for " + topoCtxItThem(len(anchorIDs)) + "."
		tc.Remediation = topoCtxDeviceRemediation(tc.Sources, anchorIDs, byID)
	default:
		tc.State = TopoStateNoAssetMapping
		if len(tc.Anchors) == 0 {
			tc.Reason = "No device or interface is attached to this case, so there is nothing to place in the network topology."
			tc.Remediation = []string{"If this case concerns a network device, map the affected entity to an inventory device (Devices, or the integration's device matching) so its topology can be drawn."}
		} else {
			tc.Reason = "The affected " + topoCtxCount(len(tc.Anchors), "entity", "entities") + " (" + topoCtxList(tc.Anchors, 4) +
				") " + topoCtxIsAre(len(tc.Anchors)) + " not in the device inventory, so no topology can be anchored to " + topoCtxItThem(len(tc.Anchors)) + "."
			tc.Remediation = []string{
				"Add the device to the inventory, or match it to an existing device (Devices → discovery, or the SD-WAN / NMS integration's device matching).",
				"Check that the name the telemetry uses for it (" + topoCtxList(tc.Anchors, 2) + ") matches the inventory name or management address.",
			}
		}
	}
	if len(tc.Unmapped) > 0 && tc.State != TopoStateNoAssetMapping {
		tc.Reason += " Not in the inventory: " + topoCtxList(tc.Unmapped, 4) + "."
	}
	if tc.Nodes == nil {
		tc.Nodes = []TopoCtxNode{}
	}
	if tc.Edges == nil {
		tc.Edges = []TopoCtxEdge{}
	}
	if tc.Faults == nil {
		tc.Faults = []FaultMark{}
	}
	if tc.Causal == nil {
		tc.Causal = []CausalMark{}
	}
	if tc.Anchors == nil {
		tc.Anchors = []string{}
	}
	return tc
}

// topoCtxStampSpineWindow classifies the measured path's temporal role against
// the CASE WINDOW (meta window_start/window_end) — inputs both endpoints hold,
// so the report and the path view stamp the same spine identically. A role the
// caller already set is kept.
func topoCtxStampSpineWindow(sp *TopologyView, meta map[string]any) {
	if sp.RelationToIncident != "" || sp.ObservedAt == "" {
		return
	}
	obs, ok := parseChTS(strings.TrimSuffix(sp.ObservedAt, " UTC"))
	if !ok {
		sp.RelationToIncident = "unknown"
		return
	}
	ws, okS := parseChTS(asString(meta["window_start"]))
	we, okE := parseChTS(asString(meta["window_end"]))
	switch {
	case okS && obs.Before(ws):
		sp.RelationToIncident = "pre_incident"
		sp.TemporalNote = "This path was measured BEFORE the case window began — historical context, not incident-time evidence."
	case okE && obs.After(we):
		sp.RelationToIncident = "post_recovery_validation"
		sp.TemporalNote = "This path was measured AFTER the case window's last evidence — it shows the later state and cannot establish incident-time root cause."
	case okS:
		sp.RelationToIncident = "incident_time"
	default:
		sp.RelationToIncident = "unknown"
	}
}

// topoCtxAnchors: the devices the case is about — the object's affected
// devices plus the device part of every attached device/interface signal.
// Both are source rows (corr_objects.affected, the archived signal slice).
func topoCtxAnchors(meta map[string]any, sigs []map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || id == "<nil>" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	if a := asString(meta["affected"]); a != "" && a != "{}" {
		var af struct {
			Devices    []string `json:"devices"`
			Interfaces []string `json:"interfaces"`
		}
		if json.Unmarshal([]byte(a), &af) == nil {
			for _, d := range af.Devices {
				add(d)
			}
			for _, i := range af.Interfaces {
				if dev, _, ok := strings.Cut(i, ":"); ok {
					add(dev)
				}
			}
		}
	}
	for _, s := range topoCtxAttached(sigs) {
		switch asString(s["entity_type"]) {
		case "device":
			add(asString(s["entity_id"]))
		case "interface":
			if dev, _, ok := strings.Cut(asString(s["entity_id"]), ":"); ok {
				add(dev)
			}
		}
	}
	sort.Strings(out)
	return out
}

// topoCtxAttached: the attached, non-clear signals (the evidence the engine
// used), exactly as BuildPathView selects them.
func topoCtxAttached(sigs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, s := range sigs {
		if b, _ := s["attached"].(bool); !b {
			continue
		}
		if strings.HasSuffix(asString(s["kind"]), "_clear") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// topoCtxEdgesFrom joins the link rows into edges: rows touching an anchor
// only, oriented so A is the anchor side (a swap, never an invention), and
// merged by the row id (the same physical link from the live tables and the
// persisted graph shares one EdgeID).
func topoCtxEdgesFrom(rows []TopologyLinkRow, anchors map[string]bool, now, windowEnd time.Time, hasWindowEnd bool) []TopoCtxEdge {
	type agg struct {
		e         TopoCtxEdge
		first     time.Time
		last      time.Time
		allStale  bool
		sourceSet map[string]bool
	}
	byID := map[string]*agg{}
	var order []string
	for _, r := range rows {
		if r.ID == "" || r.A == "" || r.B == "" || r.A == r.B {
			continue
		}
		if !anchors[r.A] && !anchors[r.B] {
			continue
		}
		if !anchors[r.A] {
			r.A, r.B = r.B, r.A
			r.APort, r.BPort = r.BPort, r.APort
			r.ALabel, r.BLabel = r.BLabel, r.ALabel
		}
		stale := r.Stale
		if !stale && !r.LastSeen.IsZero() && !now.IsZero() && now.Sub(r.LastSeen) > topoCtxLiveStaleAfter {
			stale = true
		}
		g, ok := byID[r.ID]
		if !ok {
			g = &agg{e: TopoCtxEdge{ID: r.ID, A: r.A, APort: r.APort, B: r.B, BPort: r.BPort,
				Relationship: r.Relationship, Protocol: r.Protocol, Confidence: r.Confidence, Bidirectional: r.Bidirectional},
				allStale: true, sourceSet: map[string]bool{}}
			byID[r.ID] = g
			order = append(order, r.ID)
		}
		if g.e.APort == "" {
			g.e.APort = r.APort
		}
		if g.e.BPort == "" {
			g.e.BPort = r.BPort
		}
		if g.e.Protocol == "" {
			g.e.Protocol = r.Protocol
		}
		if r.Confidence > g.e.Confidence {
			g.e.Confidence = r.Confidence
		}
		g.e.Bidirectional = g.e.Bidirectional || r.Bidirectional
		if !r.FirstSeen.IsZero() && (g.first.IsZero() || r.FirstSeen.Before(g.first)) {
			g.first = r.FirstSeen
		}
		if r.LastSeen.After(g.last) {
			g.last = r.LastSeen
		}
		g.allStale = g.allStale && stale
		for _, s := range r.Sources {
			if s != "" {
				g.sourceSet[s] = true
			}
		}
	}
	sort.Strings(order)
	out := make([]TopoCtxEdge, 0, len(order))
	for _, id := range order {
		g := byID[id]
		e := g.e
		e.Sources = []string{}
		for s := range g.sourceSet {
			e.Sources = append(e.Sources, s)
		}
		sort.Strings(e.Sources)
		e.FirstSeen = topoCtxTS(g.first)
		e.LastSeen = topoCtxTS(g.last)
		e.Stale = g.allStale
		switch {
		case hasWindowEnd && !g.first.IsZero() && g.first.After(windowEnd):
			e.Freshness = "after_incident"
		case e.Stale:
			e.Freshness = "stale"
		default:
			e.Freshness = "current"
		}
		out = append(out, e)
	}
	return out
}

// topoCtxNodes builds the capped node set. Anchors are always drawn first;
// neighbours are ranked by how many drawn edges reach them, then managed
// before unresolved, then id — deterministic.
func topoCtxNodes(anchorIDs []string, edges []TopoCtxEdge, inv map[string]InventoryRow, rows []TopologyLinkRow) ([]TopoCtxNode, map[string]bool, int) {
	labelOf := map[string]string{}
	managedOf := map[string]bool{}
	sourceOf := map[string]string{}
	for _, r := range rows {
		if r.BLabel != "" && labelOf[r.B] == "" {
			labelOf[r.B] = r.BLabel
		}
		if r.ALabel != "" && labelOf[r.A] == "" {
			labelOf[r.A] = r.ALabel
		}
		if r.BManaged {
			managedOf[r.B] = true
		}
		if len(r.Sources) > 0 {
			for _, id := range []string{r.A, r.B} {
				if sourceOf[id] == "" {
					sourceOf[id] = r.Sources[0]
				}
			}
		}
	}
	degree := map[string]int{}
	for _, e := range edges {
		degree[e.B]++
	}
	var neigh []string
	seen := map[string]bool{}
	for _, a := range anchorIDs {
		seen[a] = true
	}
	for _, e := range edges {
		if !seen[e.B] {
			seen[e.B] = true
			neigh = append(neigh, e.B)
		}
	}
	isManaged := func(id string) bool { _, ok := inv[id]; return ok || managedOf[id] }
	sort.Slice(neigh, func(i, j int) bool {
		a, b := neigh[i], neigh[j]
		if degree[a] != degree[b] {
			return degree[a] > degree[b]
		}
		if isManaged(a) != isManaged(b) {
			return isManaged(a)
		}
		return a < b
	})
	kept := map[string]bool{}
	var out []TopoCtxNode
	more := 0
	mk := func(id string, anchor bool) TopoCtxNode {
		n := TopoCtxNode{ID: id, Anchor: anchor}
		if d, ok := inv[id]; ok {
			n.Label = orDefault(d.Name, id)
			n.Role = d.Role
			n.Source = TopoSrcInventory
			n.Managed = true
			n.FirstSeen = topoCtxTS(d.FirstSeen)
			n.LastSeen = topoCtxTS(d.LastSeen)
			n.Stale = d.Stale
			return n
		}
		n.Label = orDefault(labelOf[id], strings.TrimPrefix(id, "ext:"))
		n.Managed = managedOf[id]
		n.Source = orDefault(sourceOf[id], "link")
		if strings.HasPrefix(id, "wan:") {
			n.Role = "wan_transport"
		}
		return n
	}
	for _, a := range anchorIDs {
		if len(out) >= TopoCtxMaxNodes {
			more++
			continue
		}
		kept[a] = true
		out = append(out, mk(a, true))
	}
	for _, id := range neigh {
		if len(out) >= TopoCtxMaxNodes {
			more++
			continue
		}
		kept[id] = true
		out = append(out, mk(id, false))
	}
	return out, kept, more
}

// topoCtxFaults is layer 2: one mark per device/interface carrying attached
// anomalous evidence.
func topoCtxFaults(sigs []map[string]any) []FaultMark {
	type agg struct {
		m     FaultMark
		kinds map[string]bool
		refs  map[string]bool
		peak  int
	}
	by := map[string]*agg{}
	for _, s := range topoCtxAttached(sigs) {
		et := asString(s["entity_type"])
		eid := strings.TrimSpace(asString(s["entity_id"]))
		if eid == "" {
			continue
		}
		var m FaultMark
		switch et {
		case "device":
			m = FaultMark{TargetType: "node", TargetID: eid, Device: eid}
		case "interface":
			dev, port, ok := strings.Cut(eid, ":")
			if !ok || dev == "" || port == "" {
				continue
			}
			m = FaultMark{TargetType: "interface", TargetID: eid, Device: dev, Port: port}
		default:
			continue
		}
		key := m.TargetType + "|" + m.TargetID
		g, ok := by[key]
		if !ok {
			g = &agg{m: m, kinds: map[string]bool{}, refs: map[string]bool{}, peak: -1}
			by[key] = g
		}
		if k := asString(s["kind"]); k != "" {
			g.kinds[k] = true
		}
		if id := asString(s["signal_id"]); id != "" {
			g.refs[id] = true
		}
		if r := topoCtxSevRank(asString(s["severity"])); r > g.peak {
			g.peak = r
		}
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]FaultMark, 0, len(keys))
	for _, k := range keys {
		g := by[k]
		m := g.m
		m.Kinds = topoCtxSortedKeys(g.kinds)
		m.EvidenceRefs = topoCtxCap(topoCtxSortedKeys(g.refs), topoCtxMaxEvidenceRefs)
		m.PeakSeverity = topoCtxSevName(g.peak)
		out = append(out, m)
	}
	return out
}

func topoCtxSevRank(s string) int {
	switch strings.ToLower(s) {
	case "info":
		return 0
	case "warn", "warning":
		return 1
	case "high":
		return 2
	case "crit", "critical":
		return 3
	}
	return -1
}

func topoCtxSevName(r int) string {
	switch r {
	case 0:
		return "info"
	case 1:
		return "warn"
	case 2:
		return "high"
	case 3:
		return "crit"
	}
	return "unknown"
}

// topoCtxNodeKey parses a stage [5] node key "<entity_type>:<entity_id>:<kind>"
// (the entity id may itself hold colons: "<device>:<port>").
func topoCtxNodeKey(k string) (etype, eid, kind string, ok bool) {
	first := strings.Index(k, ":")
	last := strings.LastIndex(k, ":")
	if first <= 0 || last <= first+1 || last == len(k)-1 {
		return "", "", "", false
	}
	return k[:first], k[first+1 : last], k[last+1:], true
}

func topoCtxTargetType(etype string) string {
	if etype == "device" {
		return "node"
	}
	return etype
}

// topoCtxCausal is layer 3. One mark per corr_edges row (the engine's own
// edges), plus an "unknown" mark for each drawn adjacency that touches a
// faulted device and that no engine edge crosses.
func topoCtxCausal(in TopologyContextInput, faults []FaultMark, edges []TopoCtxEdge) []CausalMark {
	verdict := strings.ToLower(strings.TrimSpace(in.Verdict))
	authRefs := topoCtxAuthoritativeRefs(in.Meta)
	refsFor := map[string][]string{} // "<etype>|<eid>|<kind>" → signal ids
	for _, s := range topoCtxAttached(in.Signals) {
		key := asString(s["entity_type"]) + "|" + asString(s["entity_id"]) + "|" + asString(s["kind"])
		if id := asString(s["signal_id"]); id != "" {
			refsFor[key] = append(refsFor[key], id)
		}
	}
	var out []CausalMark
	crossDevice := map[string]bool{} // unordered device pairs an engine edge joins
	for _, row := range in.Edges {
		fT, fID, fK, ok1 := topoCtxNodeKey(asString(row["from_node"]))
		tT, tID, tK, ok2 := topoCtxNodeKey(asString(row["to_node"]))
		if !ok1 || !ok2 {
			continue
		}
		basis := strings.TrimSpace(asString(row["direction_basis"]))
		conf := asFloat(row["direction_conf"])
		directed := basis != "" && basis != "none" && conf > 0
		gk := asString(row["grounding_kind"])
		gref := asString(row["grounding_ref"])
		authoritative := topoCtxAuthoritative(gk, gref, authRefs)
		rel := CausalUnknown
		switch {
		case basis == "" || basis == "none":
			rel = CausalUnknown
		case authoritative && verdict == "confirmed" && directed:
			rel = CausalVerified
		case conf > 0 || verdict == "suspected" || verdict == "confirmed":
			rel = CausalSuspected
		}
		refs := append(append([]string{}, refsFor[fT+"|"+fID+"|"+fK]...), refsFor[tT+"|"+tID+"|"+tK]...)
		sort.Strings(refs)
		m := CausalMark{
			From: fID, FromType: topoCtxTargetType(fT), FromKind: fK,
			To: tID, ToType: topoCtxTargetType(tT), ToKind: tK,
			Relation: rel, Directed: directed, DirectionConf: conf,
			Basis:        topoCtxCausalBasis(basis, conf, gk, gref, authoritative),
			EvidenceRefs: topoCtxCap(topoCtxDedup(refs), topoCtxMaxEvidenceRefs),
		}
		out = append(out, m)
		if da, db := topoCtxDeviceOf(fT, fID), topoCtxDeviceOf(tT, tID); da != "" && db != "" && da != db {
			crossDevice[topoCtxPair(da, db)] = true
		}
	}
	faulted := map[string]bool{}
	for _, f := range faults {
		faulted[f.Device] = true
	}
	for _, e := range edges {
		if !faulted[e.A] && !faulted[e.B] {
			continue
		}
		if crossDevice[topoCtxPair(e.A, e.B)] {
			continue
		}
		labels := make([]string, 0, len(e.Sources))
		for _, s := range e.Sources {
			labels = append(labels, strings.TrimPrefix(topoCtxSourceLabel(s), "the "))
		}
		out = append(out, CausalMark{
			From: e.A, FromType: "node", To: e.B, ToType: "node",
			Relation: CausalUnknown, Basis: "known link (" + strings.Join(labels, ", ") + "); no evidence was joined across it",
			EvidenceRefs: []string{},
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := topoCtxRelRank(a.Relation), topoCtxRelRank(b.Relation); ra != rb {
			return ra < rb
		}
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.FromKind != b.FromKind {
			return a.FromKind < b.FromKind
		}
		return a.ToKind < b.ToKind
	})
	return out
}

func topoCtxRelRank(r string) int {
	switch r {
	case CausalVerified:
		return 0
	case CausalSuspected:
		return 1
	}
	return 2
}

func topoCtxDeviceOf(etype, eid string) string {
	switch etype {
	case "device":
		return eid
	case "interface":
		if dev, _, ok := strings.Cut(eid, ":"); ok {
			return dev
		}
	}
	return ""
}

func topoCtxPair(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
}

// topoCtxAuthoritativeRefs reads the engine's own statement of which grounding
// refs were authoritative (hypotheses.grounding_context.path_graph.relations):
// "shared:<x>" is rank 1 for a resource identity and rank 7 for a coincident
// token, and only the relation record tells them apart.
func topoCtxAuthoritativeRefs(meta map[string]any) map[string]bool {
	out := map[string]bool{}
	h := asString(meta["hypotheses"])
	if h == "" {
		return out
	}
	var hd struct {
		GroundingContext struct {
			PathGraph struct {
				Relations []struct {
					Ref           string `json:"ref"`
					Authoritative bool   `json:"authoritative"`
				} `json:"relations"`
			} `json:"path_graph"`
		} `json:"grounding_context"`
	}
	if json.Unmarshal([]byte(h), &hd) != nil {
		return out
	}
	for _, r := range hd.GroundingContext.PathGraph.Relations {
		if r.Ref != "" && r.Authoritative {
			out[r.Ref] = true
		}
	}
	return out
}

// topoCtxAuthoritative: the engine's relation record first; otherwise only the
// prefixes that are rank ≤5 by construction (an L2/L3 adjacency, a path-hop
// relation). Anything else (route:, a bare shared token) is not.
func topoCtxAuthoritative(kind, ref string, auth map[string]bool) bool {
	if auth[ref] {
		return true
	}
	return kind == "topo" && (strings.HasPrefix(ref, "adj:") || strings.HasPrefix(ref, "path:"))
}

// topoCtxCausalBasis words an engine edge's basis for an operator: how the two
// observations were joined, and what (if anything) gave the link a direction.
// Plain words only — the document carries no engine vocabulary (the phase-2
// jargon gate); the raw values stay in the edge row and in DirectionConf.
func topoCtxCausalBasis(basis string, conf float64, gk, gref string, authoritative bool) string {
	var join string
	switch {
	case strings.HasPrefix(gref, "adj:"):
		join = "joined across a known link"
	case strings.HasPrefix(gref, "path:"):
		join = "joined on a measured path"
	case strings.HasPrefix(gref, "route:"):
		join = "joined by an inferred route"
	case gk == "seam":
		join = "joined at a provider boundary"
	case strings.HasPrefix(gref, "shared:") && authoritative:
		join = "observed on the same device"
	case strings.HasPrefix(gref, "shared:"):
		join = "joined by a shared name only"
	default:
		join = "joined by the engine"
	}
	if authoritative {
		join += " (authoritative)"
	} else {
		join += " (not authoritative)"
	}
	if basis == "" || basis == "none" {
		return "no direction: the two only occurred together; " + join
	}
	var votes []string
	for _, v := range strings.Split(basis, "+") {
		switch strings.TrimSpace(v) {
		case "onset_order":
			votes = append(votes, "onset order")
		case "layer_prior":
			votes = append(votes, "layer order")
		case "topology":
			votes = append(votes, "topology direction")
		case "mixed":
			votes = append(votes, "conflicting votes")
		default:
			votes = append(votes, strings.ReplaceAll(strings.TrimSpace(v), "_", " "))
		}
	}
	return fmt.Sprintf("direction from %s (direction confidence %.2f); %s", strings.Join(votes, " and "), conf, join)
}

// topoCtxSources states every consulted source with its status and freshness.
func topoCtxSources(read TopologyRead, readErr error, edges []TopoCtxEdge, anchorsFound int) []TopologySource {
	newest := map[string]time.Time{}
	nonStale := map[string]bool{}
	drawn := map[string]int{}
	for _, e := range edges {
		t, perr := time.Parse(time.RFC3339, e.LastSeen)
		if perr != nil {
			t = time.Time{} // no last-seen on this edge (topoCtxTS wrote ""): it cannot be the newest
		}
		for _, s := range e.Sources {
			drawn[s]++
			if t.After(newest[s]) {
				newest[s] = t
			}
			if !e.Stale {
				nonStale[s] = true
			}
		}
	}
	var out []TopologySource
	if readErr != nil && len(read.Reads) == 0 {
		return []TopologySource{{Kind: TopoSrcInventory, Status: TopoReadUnavailable, Freshness: "unavailable", Detail: readErr.Error()}}
	}
	out = append(out, TopologySource{Kind: TopoSrcInventory, Status: TopoReadOK, Rows: anchorsFound, Freshness: topoCtxFreshWord(anchorsFound > 0, true)})
	for _, r := range read.Reads {
		if r.Kind == TopoSrcInventory {
			continue
		}
		s := TopologySource{Kind: r.Kind, Status: r.Status, Rows: r.Rows, Detail: r.Detail}
		switch r.Status {
		case TopoReadUnavailable:
			s.Freshness = "unavailable"
		case TopoReadNotAvailable:
			s.Freshness = "not_configured"
		default:
			if t := newest[r.Kind]; !t.IsZero() {
				s.ObservedAt = topoCtxTS(t)
			}
			s.Stale = drawn[r.Kind] > 0 && !nonStale[r.Kind]
			switch {
			case r.Rows == 0:
				s.Freshness = "empty"
			case s.Stale:
				s.Freshness = "stale"
			default:
				s.Freshness = "current"
			}
		}
		out = append(out, s)
	}
	return out
}

func topoCtxFreshWord(rows, ok bool) string {
	if !ok {
		return "unavailable"
	}
	if rows {
		return "current"
	}
	return "empty"
}

// topoCtxDeviceRemediation words the device card's next steps from what was
// actually read: an empty LLDP/CDP read, an empty overlay, an unreadable source.
func topoCtxDeviceRemediation(sources []TopologySource, anchors []string, inv map[string]InventoryRow) []string {
	var out []string
	st := map[string]TopologySource{}
	for _, s := range sources {
		st[s.Kind] = s
	}
	devs := topoCtxList(anchors, 3)
	l2Empty := (st[TopoSrcLLDP].Status == TopoReadOK && st[TopoSrcLLDP].Rows == 0) || (st[TopoSrcCDP].Status == TopoReadOK && st[TopoSrcCDP].Rows == 0)
	if l2Empty {
		out = append(out, "Enable LLDP or CDP on "+devs+" and its neighbours, and make sure the neighbour tables are polled (LLDP-MIB / CISCO-CDP-MIB), so its adjacency can be discovered.")
	}
	sdwan := false
	for _, a := range anchors {
		r := strings.ToLower(inv[a].Role)
		if strings.Contains(r, "wan") || strings.Contains(r, "sdwan") || strings.Contains(r, "edge") {
			sdwan = true
		}
	}
	ov, okOv := st[TopoSrcSDWANOverlay]
	if sdwan || (okOv && ov.Status == TopoReadOK && ov.Rows == 0) {
		out = append(out, "If "+devs+" is an SD-WAN edge, connect the SD-WAN Manager integration (or make the SD-WAN MIB readable) so its tunnels are drawn — the topology map's SD-WAN notices list edges without tunnel data.")
	}
	out = append(out, "Confirm topology discovery covers this device's network (Features and Discovery settings), then regenerate this report.")
	for _, s := range sources {
		if s.Status == TopoReadUnavailable {
			out = append(out, topoCtxSourceLabel(s.Kind)+" could not be read when this report was generated — an adjacency may exist; regenerate the report once it is reachable.")
		}
	}
	return out
}

// TopologyContextForHash returns a copy with the wall-clock-driven fields
// blanked — node/edge last-seen and source observed-at move on every poll and
// reconcile cycle without the analysis changing, and hashed they would mint a
// new revision per view (the same class as Evidence.LastObservation). Stale
// flags and freshness classes stay: a link going stale IS a change. The input
// is not mutated (fresh slices).
func TopologyContextForHash(tc TopologyContext) TopologyContext {
	cp := tc
	cp.Nodes = append([]TopoCtxNode(nil), tc.Nodes...)
	for i := range cp.Nodes {
		cp.Nodes[i].LastSeen = ""
	}
	cp.Edges = append([]TopoCtxEdge(nil), tc.Edges...)
	for i := range cp.Edges {
		cp.Edges[i].LastSeen = ""
	}
	cp.Sources = append([]TopologySource(nil), tc.Sources...)
	for i := range cp.Sources {
		cp.Sources[i].ObservedAt = ""
	}
	return cp
}

// ── small wording helpers ───────────────────────────────────────────────────

func topoCtxSourceLabel(kind string) string {
	switch kind {
	case TopoSrcLLDP:
		return "LLDP"
	case TopoSrcCDP:
		return "CDP"
	case TopoSrcBGPLS:
		return "BGP-LS"
	case TopoSrcGraph:
		return "the persisted topology graph"
	case TopoSrcSDWANOverlay:
		return "the SD-WAN overlay"
	case TopoSrcController:
		return "the SD-WAN controller"
	case TopoSrcInventory:
		return "the inventory"
	}
	return kind
}

// topoCtxSourceWords lists the sources that contributed drawn rows.
func topoCtxSourceWords(sources []TopologySource) string {
	var parts []string
	for _, s := range sources {
		if s.Kind != TopoSrcInventory && s.Status == TopoReadOK && s.Rows > 0 {
			parts = append(parts, topoCtxSourceLabel(s.Kind))
		}
	}
	if len(parts) == 0 {
		return "the inventory"
	}
	return strings.Join(parts, ", ")
}

func topoCtxList(ids []string, max int) string {
	if len(ids) <= max {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:max], ", ") + fmt.Sprintf(" and %d more", len(ids)-max)
}

func topoCtxCount(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func topoCtxIsAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func topoCtxItThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

func topoCtxTS(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func topoCtxSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func topoCtxDedup(in []string) []string {
	out := make([]string, 0, len(in))
	for i, s := range in {
		if i > 0 && s == in[i-1] {
			continue
		}
		out = append(out, s)
	}
	return out
}

func topoCtxCap(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}
