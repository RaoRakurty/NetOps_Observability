// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// topology_context_test.go — RCA document v2 §7 (Go): the four topology
// states, the no-invention property, the P-3E0400 regression (device_only, no
// "not path-shaped"), the causal marks against the fixture's corr_edges, the
// hash normalisation, and the per-state HTML goldens (the HTML is the PDF
// input; no PDF byte snapshot).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fakeTopoReader is a crafted TopologySourceReader: it returns its rows and
// records the query it was asked.
type fakeTopoReader struct {
	read TopologyRead
	err  error
	got  []TopologyQuery
}

func (f *fakeTopoReader) ReadTopology(_ context.Context, q TopologyQuery) (TopologyRead, error) {
	f.got = append(f.got, q)
	return f.read, f.err
}

var topoNow = time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)

func allReadsEmpty() []TopologySourceRead {
	var out []TopologySourceRead
	for _, k := range []string{TopoSrcLLDP, TopoSrcCDP, TopoSrcBGPLS, TopoSrcGraph, TopoSrcSDWANOverlay, TopoSrcController} {
		out = append(out, TopologySourceRead{Kind: k, Status: TopoReadOK})
	}
	return out
}

func topoSig(id, etype, eid, kind, sev string) map[string]any {
	return map[string]any{"signal_id": id, "entity_type": etype, "entity_id": eid, "kind": kind, "severity": sev, "attached": true}
}

func topoEdgeRow(from, to, basis string, conf float64) map[string]any {
	return map[string]any{"from_node": from, "to_node": to, "grounding_kind": "topo", "grounding_ref": "adj:r1--r2",
		"direction_basis": basis, "direction_conf": conf}
}

func topoMeta(verdict, affected string) map[string]any {
	return map[string]any{"tenant_id": "acme", "verdict_tier": verdict, "affected": affected,
		"window_start": "2026-11-12T04:50:00Z", "window_end": "2026-11-12T04:55:00Z"}
}

// twoRouterRead: r1 (anchor) — r2 over LLDP (live + persisted, one link), and
// r1 — ext:isp-pe (unresolved) over CDP, stale in the graph.
func twoRouterRead() TopologyRead {
	return TopologyRead{
		Inventory: []InventoryRow{
			{ID: "r1", Name: "core-r1", Role: "core_router", Source: "snmp", LastSeen: topoNow.Add(-time.Minute)},
			{ID: "r2", Name: "core-r2", Role: "core_router", Source: "snmp", LastSeen: topoNow.Add(-time.Minute)},
		},
		Links: []TopologyLinkRow{
			{ID: "r1|Gi1--r2|Gi2", Sources: []string{TopoSrcLLDP}, A: "r1", APort: "Gi1", B: "r2", BPort: "Gi2", BManaged: true,
				Relationship: "physical", Protocol: "lldp", Bidirectional: true, LastSeen: topoNow.Add(-2 * time.Minute)},
			{ID: "r1|Gi1--r2|Gi2", Sources: []string{TopoSrcGraph}, A: "r2", APort: "Gi2", B: "r1", BPort: "Gi1", BManaged: true,
				Relationship: "physical", Protocol: "lldp", FirstSeen: topoNow.Add(-48 * time.Hour), LastSeen: topoNow.Add(-time.Minute)},
			{ID: "r1|Gi3--ext:isp-pe|", Sources: []string{TopoSrcGraph}, A: "r1", APort: "Gi3", B: "ext:isp-pe", BLabel: "isp-pe",
				Relationship: "physical", Protocol: "cdp", FirstSeen: topoNow.Add(-72 * time.Hour), LastSeen: topoNow.Add(-6 * time.Hour), Stale: true},
		},
		Reads: append(allReadsEmpty()[:0:0], []TopologySourceRead{
			{Kind: TopoSrcLLDP, Status: TopoReadOK, Rows: 1},
			{Kind: TopoSrcCDP, Status: TopoReadOK, Rows: 0},
			{Kind: TopoSrcBGPLS, Status: TopoReadOK, Rows: 0},
			{Kind: TopoSrcGraph, Status: TopoReadOK, Rows: 2},
			{Kind: TopoSrcSDWANOverlay, Status: TopoReadNotAvailable},
			{Kind: TopoSrcController, Status: TopoReadNotAvailable},
		}...),
	}
}

func buildTopo(t *testing.T, in TopologyContextInput, r *fakeTopoReader) TopologyContext {
	t.Helper()
	if in.Now.IsZero() {
		in.Now = topoNow
	}
	if r == nil {
		return BuildTopologyContext(context.Background(), nil, in)
	}
	return BuildTopologyContext(context.Background(), r, in)
}

// ── the four states ─────────────────────────────────────────────────────────

func TestTopologyContextStateTopologyOnly(t *testing.T) {
	r := &fakeTopoReader{read: twoRouterRead()}
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Verdict: "suspected",
		Meta:    topoMeta("suspected", `{"devices":["r1"]}`),
		Signals: []map[string]any{topoSig("s1", "interface", "r1:Gi1", "if_metric_anomaly", "crit")},
	}, r)
	if tc.State != TopoStateTopologyOnly {
		t.Fatalf("state = %q, want topology_only (%s)", tc.State, tc.Reason)
	}
	if len(r.got) != 1 || r.got[0].OwnerTenant != "acme" || strings.Join(r.got[0].Devices, ",") != "r1" {
		t.Fatalf("reader query = %+v, want owner acme anchored on r1", r.got)
	}
	if len(tc.Edges) != 2 {
		t.Fatalf("edges = %+v, want the merged LLDP link + the stale CDP link", tc.Edges)
	}
	var lldp, cdp TopoCtxEdge
	for _, e := range tc.Edges {
		if e.B == "r2" {
			lldp = e
		} else {
			cdp = e
		}
	}
	// merged: both sources, anchor-first orientation, first_seen from the graph.
	if lldp.A != "r1" || lldp.APort != "Gi1" || lldp.BPort != "Gi2" || strings.Join(lldp.Sources, ",") != "lldp,topology_graph" ||
		lldp.FirstSeen == "" || lldp.Stale || lldp.Freshness != "current" || !lldp.Bidirectional {
		t.Fatalf("merged LLDP edge wrong: %+v", lldp)
	}
	if !cdp.Stale || cdp.Freshness != "stale" {
		t.Fatalf("CDP edge must read stale: %+v", cdp)
	}
	if !strings.Contains(tc.Reason, "unverified") {
		t.Fatalf("topology_only must mark the causal path unverified: %q", tc.Reason)
	}
	if tc.Spine != nil {
		t.Fatal("no spine was given; none may appear")
	}
	// the unresolved neighbour is drawn with the label its row states, unmanaged.
	var ext TopoCtxNode
	for _, n := range tc.Nodes {
		if n.ID == "ext:isp-pe" {
			ext = n
		}
	}
	if ext.Label != "isp-pe" || ext.Managed || ext.Source != TopoSrcGraph {
		t.Fatalf("unresolved neighbour = %+v", ext)
	}
	// a known link from a faulted device that the engine joined nothing across
	// is a causal "unknown" (§2 layer 3).
	unknownLinks := 0
	for _, m := range tc.Causal {
		if m.FromKind == "" && m.Relation == CausalUnknown {
			unknownLinks++
		}
	}
	if unknownLinks != 2 {
		t.Fatalf("want 2 unknown topology-link marks, got %d: %+v", unknownLinks, tc.Causal)
	}
}

func TestTopologyContextStateWithPath(t *testing.T) {
	spine := &TopologyView{Available: true, VantageID: "v1", ObservedAt: "2026-11-12 04:52:00",
		Hops: []SpineHopView{{Index: 1, Label: "core-r1", State: "responding"}, {Index: 2, Label: "", State: "unknown"}}}
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Verdict: "confirmed",
		Meta: topoMeta("confirmed", `{"devices":["r1"]}`), Spine: spine,
	}, &fakeTopoReader{read: twoRouterRead()})
	if tc.State != TopoStateWithPath || tc.Spine == nil || len(tc.Edges) == 0 {
		t.Fatalf("state = %q spine=%v edges=%d", tc.State, tc.Spine != nil, len(tc.Edges))
	}
	if tc.Spine.RelationToIncident != "incident_time" {
		t.Fatalf("a path measured inside the case window is incident-time evidence, got %q", tc.Spine.RelationToIncident)
	}
	if spine.RelationToIncident != "" {
		t.Fatal("the builder must not mutate the caller's spine")
	}
	// a spine with no adjacency is still "with path" — and says so.
	tc = buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("confirmed", `{"devices":["r1"]}`), Spine: spine},
		&fakeTopoReader{read: TopologyRead{Inventory: twoRouterRead().Inventory[:1], Reads: allReadsEmpty()}})
	if tc.State != TopoStateWithPath || !strings.Contains(tc.Reason, "only the measured path") {
		t.Fatalf("spine-only: %q %q", tc.State, tc.Reason)
	}
}

func TestTopologyContextStateDeviceOnly(t *testing.T) {
	read := TopologyRead{
		Inventory: []InventoryRow{{ID: "edge-1", Name: "edge-1", Role: "wan_edge", Source: "snmp", LastSeen: topoNow}},
		Reads:     allReadsEmpty(),
	}
	read.Reads[3] = TopologySourceRead{Kind: TopoSrcGraph, Status: TopoReadUnavailable, Detail: "the persisted topology graph could not be read"}
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Verdict: "suspected",
		Meta:    topoMeta("suspected", `{"devices":["edge-1"],"interfaces":["edge-1:Gi3"]}`),
		Signals: []map[string]any{topoSig("s1", "interface", "edge-1:Gi3", "if_metric_anomaly", "high")},
	}, &fakeTopoReader{read: read})
	if tc.State != TopoStateDeviceOnly {
		t.Fatalf("state = %q, want device_only (%s)", tc.State, tc.Reason)
	}
	if len(tc.Nodes) != 1 || !tc.Nodes[0].Anchor || tc.Nodes[0].Role != "wan_edge" || tc.Nodes[0].Source != TopoSrcInventory {
		t.Fatalf("device card node = %+v", tc.Nodes)
	}
	rem := strings.Join(tc.Remediation, " | ")
	for _, want := range []string{"LLDP or CDP", "SD-WAN Manager integration", "could not be read"} {
		if !strings.Contains(rem, want) {
			t.Fatalf("device_only remediation lacks %q: %s", want, rem)
		}
	}
	var graph TopologySource
	for _, s := range tc.Sources {
		if s.Kind == TopoSrcGraph {
			graph = s
		}
	}
	if graph.Status != TopoReadUnavailable || graph.Freshness != "unavailable" {
		t.Fatalf("an unreadable source must stay unavailable, never empty: %+v", graph)
	}
}

func TestTopologyContextStateNoAssetMapping(t *testing.T) {
	// anchors exist, inventory does not know them.
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme",
		Meta: topoMeta("suspected", `{"devices":["ghost-7"]}`),
	}, &fakeTopoReader{read: TopologyRead{Reads: allReadsEmpty()}})
	if tc.State != TopoStateNoAssetMapping || !strings.Contains(tc.Reason, "not in the device inventory") ||
		len(tc.Unmapped) != 1 || tc.Unmapped[0] != "ghost-7" || len(tc.Remediation) == 0 {
		t.Fatalf("unmapped anchor: %+v", tc)
	}
	// no device or interface attached at all (a cloud/app case).
	r := &fakeTopoReader{}
	tc = buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"apps":["portal"]}`),
		Signals: []map[string]any{topoSig("s1", "app", "portal", "app_error_rate_high", "crit")}}, r)
	if tc.State != TopoStateNoAssetMapping || !strings.Contains(tc.Reason, "No device or interface") {
		t.Fatalf("no anchor: %q %q", tc.State, tc.Reason)
	}
	if len(r.got) != 0 || len(tc.Sources) != 0 {
		t.Fatalf("with nothing to anchor on, no topology store may be read or claimed as read: %+v", tc.Sources)
	}
	// the sources could not be read: a data-availability error, never "not in inventory".
	tc = buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["r1"]}`)},
		&fakeTopoReader{err: errors.New("dial tcp: refused")})
	if tc.State != TopoStateNoAssetMapping || !strings.Contains(tc.Reason, "could not be read") || strings.Contains(tc.Reason, "not in the device inventory") {
		t.Fatalf("reader failure: %q %q", tc.State, tc.Reason)
	}
	if len(tc.Sources) != 1 || tc.Sources[0].Status != TopoReadUnavailable {
		t.Fatalf("reader failure sources = %+v", tc.Sources)
	}
	// no reader wired is the same honest answer.
	tc = buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["r1"]}`)}, nil)
	if tc.State != TopoStateNoAssetMapping || !strings.Contains(tc.Reason, "could not be read") {
		t.Fatalf("nil reader: %q %q", tc.State, tc.Reason)
	}
}

func TestTopologyContextNodeCapCountsTheRest(t *testing.T) {
	read := TopologyRead{Inventory: []InventoryRow{{ID: "hub", Name: "hub"}}, Reads: allReadsEmpty()}
	for i := 0; i < 40; i++ {
		read.Links = append(read.Links, TopologyLinkRow{ID: fmt.Sprintf("l%02d", i), Sources: []string{TopoSrcLLDP},
			A: "hub", B: fmt.Sprintf("ext:n%02d", i), Relationship: "physical", Protocol: "lldp"})
	}
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["hub"]}`)}, &fakeTopoReader{read: read})
	if len(tc.Nodes) != TopoCtxMaxNodes || tc.MoreNodes != 40-(TopoCtxMaxNodes-1) {
		t.Fatalf("nodes=%d more=%d, want %d and %d", len(tc.Nodes), tc.MoreNodes, TopoCtxMaxNodes, 40-(TopoCtxMaxNodes-1))
	}
	drawn := map[string]bool{}
	for _, n := range tc.Nodes {
		drawn[n.ID] = true
	}
	for _, e := range tc.Edges {
		if !drawn[e.A] || !drawn[e.B] {
			t.Fatalf("edge %s reaches an undrawn node", e.ID)
		}
	}
	if !tc.Nodes[0].Anchor {
		t.Fatal("anchors are drawn first")
	}
}

// ── never invent (property) ─────────────────────────────────────────────────

// TestTopologyContextNeverInvents drives the builder with many random row sets
// and checks the §2 rule: every node id, edge id + endpoint pair, fault target
// and causal endpoint comes from a source row.
func TestTopologyContextNeverInvents(t *testing.T) {
	rng := rand.New(rand.NewSource(20261112)) // #nosec G404 -- deterministic test data
	devs := []string{"a", "b", "c", "d", "e", "f"}
	pick := func() string { return devs[rng.Intn(len(devs))] }
	for iter := 0; iter < 400; iter++ {
		var read TopologyRead
		inv := map[string]bool{}
		for _, d := range devs {
			if rng.Intn(3) > 0 {
				read.Inventory = append(read.Inventory, InventoryRow{ID: d, Name: "n-" + d})
				inv[d] = true
			}
		}
		type pair struct{ a, b string }
		rowPairs := map[string][]pair{}
		for i := rng.Intn(12); i > 0; i-- {
			a, b := pick(), pick()
			if rng.Intn(4) == 0 {
				b = "ext:x" + b
			}
			id := fmt.Sprintf("row-%d", rng.Intn(8))
			read.Links = append(read.Links, TopologyLinkRow{ID: id, Sources: []string{TopoSrcLLDP}, A: a, B: b, Relationship: "physical",
				LastSeen: topoNow.Add(-time.Duration(rng.Intn(40)) * time.Minute)})
			rowPairs[id] = append(rowPairs[id], pair{a, b})
		}
		read.Reads = allReadsEmpty()
		var sigs []map[string]any
		sigEntities := map[string]bool{}
		for i := rng.Intn(5); i > 0; i-- {
			d := pick()
			if rng.Intn(2) == 0 {
				sigs = append(sigs, topoSig(fmt.Sprintf("s%d", i), "device", d, "device_alarm", "warn"))
				sigEntities[d] = true
			} else {
				sigs = append(sigs, topoSig(fmt.Sprintf("s%d", i), "interface", d+":Gi1", "if_metric_anomaly", "crit"))
				sigEntities[d+":Gi1"] = true
			}
		}
		var edges []map[string]any
		edgeEntities := map[string]bool{}
		for i := rng.Intn(4); i > 0; i-- {
			a, b := pick(), pick()
			edges = append(edges, topoEdgeRow("device:"+a+":device_alarm", "interface:"+b+":Gi1:if_metric_anomaly", []string{"none", "onset_order+layer_prior"}[rng.Intn(2)], float64(rng.Intn(2))*0.8))
			edgeEntities[a], edgeEntities[b+":Gi1"] = true, true
		}
		aff := fmt.Sprintf(`{"devices":[%q,%q]}`, pick(), pick())
		tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", aff), Signals: sigs, Edges: edges, Verdict: "suspected"},
			&fakeTopoReader{read: read})

		rowEndpoint := map[string]bool{}
		for _, l := range read.Links {
			rowEndpoint[l.A], rowEndpoint[l.B] = true, true
		}
		for _, n := range tc.Nodes {
			if !inv[n.ID] && !rowEndpoint[n.ID] {
				t.Fatalf("iter %d: INVENTED node %q (not in inventory, not a link endpoint)", iter, n.ID)
			}
		}
		for _, e := range tc.Edges {
			ok := false
			for _, p := range rowPairs[e.ID] {
				if (p.a == e.A && p.b == e.B) || (p.a == e.B && p.b == e.A) {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("iter %d: INVENTED edge %s %s--%s (no source row with that id and endpoints)", iter, e.ID, e.A, e.B)
			}
		}
		for _, f := range tc.Faults {
			if !sigEntities[f.TargetID] {
				t.Fatalf("iter %d: INVENTED fault target %q", iter, f.TargetID)
			}
		}
		for _, m := range tc.Causal {
			if m.FromKind == "" { // a topology-link mark: both ends a drawn edge's endpoints
				found := false
				for _, e := range tc.Edges {
					if (e.A == m.From && e.B == m.To) || (e.A == m.To && e.B == m.From) {
						found = true
					}
				}
				if !found {
					t.Fatalf("iter %d: INVENTED link mark %s→%s", iter, m.From, m.To)
				}
				continue
			}
			if !edgeEntities[m.From] || !edgeEntities[m.To] {
				t.Fatalf("iter %d: INVENTED causal mark %s→%s", iter, m.From, m.To)
			}
		}
	}
}

// ── P-3E0400 (the regression case) ──────────────────────────────────────────

type p3Fixture struct {
	meta    map[string]any
	edges   []map[string]any
	signals []map[string]any
	report  Report
}

// loadP3E0400 loads the captured fixture. It carries no per-signal rows, so
// the six attached signals are rebuilt from what it does carry: the entity and
// kind in each corr_edges node key (6 distinct nodes = signal_count 6) and the
// signal ids the path view's annotations name, in their emitted order. The
// severities are not asserted anywhere.
func loadP3E0400(t *testing.T) p3Fixture {
	t.Helper()
	var detail struct {
		Edges  []map[string]any `json:"edges"`
		Object map[string]any   `json:"object"`
	}
	b, err := os.ReadFile("testdata/p3e0400/detail.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &detail); err != nil {
		t.Fatal(err)
	}
	var rep Report
	b, err = os.ReadFile("testdata/p3e0400/rca-report.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	const dev = "cedge-60-07ae8615"
	sigs := []map[string]any{
		topoSig("eaf787e3-cc25-5575-90ed-0c2522175d21", "interface", dev+":Gi3", "if_metric_anomaly", "warn"),
		topoSig("0fe46927-309b-51ea-a649-a689c32096c6", "device", dev, "device_resource_anomaly", "high"),
		topoSig("3258effc-b2c0-5b23-a872-c9b03c145c3c", "interface", dev+":Gi4", "if_metric_anomaly", "crit"),
		topoSig("24907e4f-fd67-52ca-bd55-761c243a1d70", "interface", dev+":Tu2", "if_metric_anomaly", "warn"),
		topoSig("f078d629-8ce1-5ec0-bf4d-823a94324936", "interface", dev+":Tu1", "if_metric_anomaly", "crit"),
		topoSig("6929a382-062a-5b3c-b999-cd8ceb0376e5", "device", dev, "device_alarm", "warn"),
	}
	return p3Fixture{meta: detail.Object, edges: detail.Edges, signals: sigs, report: rep}
}

// p3Reader is what the lab held for the device on 2026-11-12: an inventory row
// and no adjacency in any source (trackers 334/349/366).
func p3Reader() *fakeTopoReader {
	return &fakeTopoReader{read: TopologyRead{
		Inventory: []InventoryRow{{ID: "cedge-60-07ae8615", Name: "cedge-60-07ae8615", Role: "wan_edge", Source: "snmp", LastSeen: topoNow}},
		Reads:     allReadsEmpty(),
	}}
}

func p3Context(t *testing.T, f p3Fixture) TopologyContext {
	t.Helper()
	// the spine the lab answered: no measured path.
	spine := &TopologyView{Available: false, Reason: "this correlation object is not path-shaped (no measured path entity is attached)"}
	return buildTopo(t, TopologyContextInput{OwnerTenant: "global", Meta: f.meta, Signals: f.signals, Edges: f.edges,
		Verdict: asString(f.meta["verdict_tier"]), Spine: spine}, p3Reader())
}

func TestTopologyContextP3E0400IsDeviceOnly(t *testing.T) {
	f := loadP3E0400(t)
	tc := p3Context(t, f)
	if tc.State != TopoStateDeviceOnly {
		t.Fatalf("P-3E0400 state = %q, want device_only (%s)", tc.State, tc.Reason)
	}
	if strings.Contains(tc.Reason, "path-shaped") {
		t.Fatalf("the section verdict must never be the spine's reason: %q", tc.Reason)
	}
	if len(tc.Faults) != 5 { // the device + Gi3, Gi4, Tu1, Tu2
		t.Fatalf("faults = %+v", tc.Faults)
	}
	// causal marks against the fixture's corr_edges: device_resource_anomaly →
	// Gi4/Tu1/Tu2 carry onset_order+layer_prior 0.8 under a suspected verdict →
	// suspected and directed; every direction_basis "none" row → unknown.
	if len(tc.Causal) != len(f.edges) {
		t.Fatalf("one causal mark per corr_edges row (no topology links here): %d vs %d", len(tc.Causal), len(f.edges))
	}
	byPair := map[string]CausalMark{}
	for _, m := range tc.Causal {
		byPair[m.From+"|"+m.FromKind+"→"+m.To+"|"+m.ToKind] = m
	}
	for _, e := range f.edges {
		fT, fID, fK, _ := topoCtxNodeKey(asString(e["from_node"]))
		tT, tID, tK, _ := topoCtxNodeKey(asString(e["to_node"]))
		_, _ = fT, tT
		m, ok := byPair[fID+"|"+fK+"→"+tID+"|"+tK]
		if !ok {
			t.Fatalf("no mark for edge %v → %v", e["from_node"], e["to_node"])
		}
		want := CausalUnknown
		if asString(e["direction_basis"]) != "none" {
			want = CausalSuspected
		}
		if m.Relation != want {
			t.Fatalf("%s→%s relation = %q, want %q", fID, tID, m.Relation, want)
		}
		if (want == CausalSuspected) != m.Directed {
			t.Fatalf("%s→%s directed = %v", fID, tID, m.Directed)
		}
		if len(m.EvidenceRefs) != 2 {
			t.Fatalf("%s→%s evidence refs = %v, want both endpoint signals", fID, tID, m.EvidenceRefs)
		}
	}
	suspected := 0
	for _, m := range tc.Causal {
		if m.Relation == CausalSuspected {
			suspected++
			if m.From != "cedge-60-07ae8615" || m.FromKind != "device_resource_anomaly" || m.ToType != "interface" {
				t.Fatalf("suspected mark must be resource_anomaly → interface: %+v", m)
			}
		}
		if m.Relation == CausalVerified {
			t.Fatalf("a suspected case can never carry a verified link: %+v", m)
		}
	}
	if suspected != 3 {
		t.Fatalf("want 3 suspected marks (→ Gi4, Tu1, Tu2), got %d", suspected)
	}
}

func TestTopologyContextP3E0400HTMLHasNoPathShapedVerdict(t *testing.T) {
	f := loadP3E0400(t)
	rep := f.report
	rep.TopologyContext = p3Context(t, f)
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	if strings.Contains(doc, "path-shaped") {
		t.Fatal(`P-3E0400 must never render "not path-shaped"`)
	}
	for _, want := range []string{
		"Network topology &amp; causality — sources: inventory only",
		"device only — no neighbour or path data",
		"Device diagnostic — cedge-60-07ae8615",
		"Read and empty", "What would complete this picture", "? unknown", "suspected",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("P-3E0400 HTML lacks %q", want)
		}
	}
	if strings.Contains(doc, "(measured)</h2>") {
		t.Fatal(`the heading drops "(measured)"`)
	}
	if strings.Contains(doc, "<script") {
		t.Fatal("the PDF input must carry no script")
	}
	if out := os.Getenv("RCA_EMIT_HTML_P3E0400"); out != "" {
		if err := os.WriteFile(out, html, 0o644); err != nil { // #nosec G306 -- test artifact
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %d bytes to %s", len(html), out)
	}
}

// ── determinism + hash ──────────────────────────────────────────────────────

func TestTopologyContextIsDeterministic(t *testing.T) {
	f := loadP3E0400(t)
	a, _ := json.Marshal(p3Context(t, f))
	b, _ := json.Marshal(p3Context(t, f))
	if !bytes.Equal(a, b) {
		t.Fatal("the builder must be deterministic in its inputs")
	}
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["r1"]}`)}, &fakeTopoReader{read: twoRouterRead()})
	read2 := twoRouterRead()
	for i, j := 0, len(read2.Links)-1; i < j; i, j = i+1, j-1 {
		read2.Links[i], read2.Links[j] = read2.Links[j], read2.Links[i]
	}
	tc2 := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["r1"]}`)}, &fakeTopoReader{read: read2})
	x, _ := json.Marshal(tc)
	y, _ := json.Marshal(tc2)
	if !bytes.Equal(x, y) {
		t.Fatalf("row order must not change the output:\n%s\n%s", x, y)
	}
}

func TestTopologyContextForHashBlanksOnlyClockFields(t *testing.T) {
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["r1"]}`)}, &fakeTopoReader{read: twoRouterRead()})
	h := TopologyContextForHash(tc)
	for _, n := range h.Nodes {
		if n.LastSeen != "" {
			t.Fatal("node last_seen must be normalised")
		}
	}
	for i, e := range h.Edges {
		if e.LastSeen != "" || e.Stale != tc.Edges[i].Stale || e.Freshness != tc.Edges[i].Freshness || e.FirstSeen != tc.Edges[i].FirstSeen {
			t.Fatalf("only last_seen is normalised on edges: %+v vs %+v", e, tc.Edges[i])
		}
	}
	if tc.Nodes[0].LastSeen == "" || tc.Edges[0].LastSeen == "" {
		t.Fatal("TopologyContextForHash must not mutate its input")
	}
	// a poll moving last_seen does not move the report's analysis hash.
	read := twoRouterRead()
	for i := range read.Links {
		read.Links[i].LastSeen = read.Links[i].LastSeen.Add(30 * time.Second)
	}
	read.Inventory[0].LastSeen = read.Inventory[0].LastSeen.Add(30 * time.Second)
	moved := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["r1"]}`)}, &fakeTopoReader{read: read})
	r1, r2 := Report{TopologyContext: tc}, Report{TopologyContext: moved}
	i1, err1 := ComputeReportIntegrity(r1)
	i2, err2 := ComputeReportIntegrity(r2)
	if err1 != nil || err2 != nil || i1.AnalysisSnapshotHash != i2.AnalysisSnapshotHash {
		t.Fatalf("a last-seen move must not mint a new analysis snapshot: %v %v %s %s", err1, err2, i1.AnalysisSnapshotHash, i2.AnalysisSnapshotHash)
	}
	h1, _ := renderTopoPartial(t, tc)
	h2, _ := renderTopoPartial(t, moved)
	if h1 != h2 {
		t.Fatal("the rendered section must not print a wall-clock last-seen (the revision register dedupes by content)")
	}
}

// ── HTML goldens per state ──────────────────────────────────────────────────

func renderTopoPartial(t *testing.T, tc TopologyContext) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	if err := rcaReportTmpl.ExecuteTemplate(&buf, "topologyContext", tc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// TestTopologyContextHTMLGoldens pins the section's HTML per state. Refresh
// with RCA_UPDATE_TOPOCTX_GOLDEN=1 after an intended change and review the diff.
func TestTopologyContextHTMLGoldens(t *testing.T) {
	spine := &TopologyView{Available: true, VantageID: "v1", ObservedAt: "2026-11-12 04:52:00",
		Hops: []SpineHopView{{Index: 1, Label: "core-r1", Kind: "lan", State: "responding", Fault: "suspected"}, {Index: 2, Kind: "unknown", State: "unknown"}}}
	sigs := []map[string]any{
		topoSig("s1", "interface", "r1:Gi1", "if_metric_anomaly", "crit"),
		topoSig("s2", "device", "r1", "device_resource_anomaly", "high"),
		topoSig("s3", "device", "r2", "bgp_adjacency_change", "warn"),
	}
	edges := []map[string]any{
		topoEdgeRow("device:r1:device_resource_anomaly", "interface:r1:Gi1:if_metric_anomaly", "onset_order+layer_prior", 0.8),
		topoEdgeRow("interface:r1:Gi1:if_metric_anomaly", "device:r2:bgp_adjacency_change", "onset_order+layer_prior", 0.8),
	}
	f := loadP3E0400(t)
	cases := map[string]TopologyContext{
		"topology_with_path": buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Verdict: "confirmed", Meta: topoMeta("confirmed", `{"devices":["r1"]}`),
			Signals: sigs, Edges: edges, Spine: spine}, &fakeTopoReader{read: twoRouterRead()}),
		"topology_only": buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Verdict: "suspected", Meta: topoMeta("suspected", `{"devices":["r1"]}`),
			Signals: sigs, Edges: edges}, &fakeTopoReader{read: twoRouterRead()}),
		"device_only": p3Context(t, f),
		"no_asset_mapping": buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["ghost-7"]}`)},
			&fakeTopoReader{read: TopologyRead{Reads: allReadsEmpty()}}),
	}
	for state, tc := range cases {
		t.Run(state, func(t *testing.T) {
			if tc.State != state {
				t.Fatalf("fixture for %s built state %q", state, tc.State)
			}
			got, err := renderTopoPartial(t, tc)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if strings.Contains(got, "path-shaped") || strings.Contains(got, "<script") {
				t.Fatal("the section never renders the spine's reason and never carries a script")
			}
			// the phase-2 jargon gate applies to this section too.
			for _, banned := range []string{"sig.ent.", "modality", "onset_order", "layer_prior", "shared:", "adj:"} {
				if strings.Contains(got, banned) {
					t.Fatalf("%s section carries engine vocabulary %q", state, banned)
				}
			}
			if m := regexp.MustCompile(`(?i)\bsignals?\b`).FindString(got); m != "" {
				t.Fatalf("%s section carries the word %q", state, m)
			}
			path := filepath.Join("testdata", "topoctx", state+".golden.html")
			if os.Getenv("RCA_UPDATE_TOPOCTX_GOLDEN") != "" {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path) // #nosec G304 -- fixed testdata path
			if err != nil {
				t.Fatalf("read golden (refresh with RCA_UPDATE_TOPOCTX_GOLDEN=1): %v", err)
			}
			if got != string(want) {
				t.Fatalf("%s HTML drifted from %s (refresh with RCA_UPDATE_TOPOCTX_GOLDEN=1 and review the diff)", state, path)
			}
		})
	}
}

// TestTopologyContextHTMLStateWords: each state is carried by a WORD (the
// page reads in grayscale print), and the at-a-glance brief renders too.
func TestTopologyContextHTMLStateWords(t *testing.T) {
	for state, word := range map[string]string{
		TopoStateWithPath: "topology with measured path", TopoStateTopologyOnly: "known topology, no measured path",
		TopoStateDeviceOnly: "device only", TopoStateNoAssetMapping: "no asset mapping",
	} {
		if !strings.Contains(topoStateLabel(state), word) {
			t.Fatalf("%s label = %q", state, topoStateLabel(state))
		}
	}
	var buf bytes.Buffer
	tc := buildTopo(t, TopologyContextInput{OwnerTenant: "acme", Meta: topoMeta("suspected", `{"devices":["r1"]}`),
		Signals: []map[string]any{topoSig("s1", "interface", "r1:Gi1", "if_metric_anomaly", "crit")}}, &fakeTopoReader{read: twoRouterRead()})
	if err := rcaReportTmpl.ExecuteTemplate(&buf, "topologyContextBrief", tc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<svg") || !strings.Contains(buf.String(), "known topology, no measured path") {
		t.Fatalf("brief: %s", buf.String())
	}
	// the zero value (no HTTP layer built it) renders an honest line, no panic.
	buf.Reset()
	if err := rcaReportTmpl.ExecuteTemplate(&buf, "topologyContext", TopologyContext{}); err != nil || !strings.Contains(buf.String(), "not built") {
		t.Fatalf("zero value: %v %s", err, buf.String())
	}
}
