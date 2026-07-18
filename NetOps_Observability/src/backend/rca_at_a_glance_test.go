package main

// rca_at_a_glance_test.go — #113 point 2: the RCA document's FIRST section must
// show where it happened · what possibly happened · possible owner(s) · the
// network causality path with broken areas in red. The section composes only
// claims the report already makes ("possibly because of X" when unconfirmed,
// "Possible owner(s)" until a root cause is identified) and the HTML renders it
// before the management summary, with the path graph on page 1.

import (
	"strings"
	"testing"
)

func TestAtAGlanceUnconfirmedReadsPossibly(t *testing.T) {
	meta := testMeta("open", "suspected", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.5, "suspected",
			[]string{"bgp_adjacency_change"}, []string{"probe_loss"}, nil, "isp", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	g := rep.AtAGlance
	if !strings.HasPrefix(g.What, "Possibly because of ") {
		t.Fatalf("unconfirmed cause must read 'possibly because of X', got %q", g.What)
	}
	if strings.Contains(strings.ToLower(g.What), "not identified") {
		t.Fatalf("bare 'not identified' is banned in the first section: %q", g.What)
	}
	if g.OwnersLabel != "Possible owner(s)" {
		t.Fatalf("unconfirmed owner label = %q, want Possible owner(s)", g.OwnersLabel)
	}
	if len(g.Owners) == 0 {
		t.Fatal("owners must never be empty — at minimum the NOC triage fallback")
	}
	// the ISP hypothesis names a candidate — it must appear as a possible owner
	found := false
	for _, o := range g.Owners {
		if strings.Contains(o, "ISP / carrier") {
			found = true
		}
	}
	if !found {
		t.Fatalf("hypothesis-named candidate missing from owners: %v", g.Owners)
	}
	if g.Where == "" {
		t.Fatal("where must always carry a statement (scope or honest absence)")
	}
}

func TestAtAGlanceNoHypothesisIsHonest(t *testing.T) {
	meta := testMeta("open", "undetermined", "undetermined", nil)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	g := rep.AtAGlance
	if !strings.Contains(g.What, "No cause hypothesis has supporting evidence yet") {
		t.Fatalf("evidence-free case must state the absence honestly, got %q", g.What)
	}
	if g.OwnersLabel != "Possible owner(s)" || len(g.Owners) == 0 ||
		!strings.Contains(g.Owners[0], "NOC triage") {
		t.Fatalf("ownerless case must fall back to NOC triage: %q %v", g.OwnersLabel, g.Owners)
	}
}

func TestAtAGlanceLocalizedSeamIsTheWhere(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.92, "confirmed",
			[]string{"ipsec_tunnel_status", "probe_loss"}, nil, nil, "netops", false))
	meta["hypotheses"] = strings.Replace(asString(meta["hypotheses"]), `"ranking"`,
		`"grounding_context":{"seams":[{"seam_id":"dallas-dx-1","tenant_id":"t1","seam_type":"IPSEC"}]},"ranking"`, 1)
	sigs := []map[string]any{
		testSig("ipsec_tunnel_status", "control_plane", "vpn-edge", "device", "vpn-edge", "crit", "2026-07-12 18:12:00", true,
			map[string]any{"attrs": `{"seam_id":"dallas-dx-1"}`}),
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.0.0.1", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	g := rep.AtAGlance
	if g.WhereBasis != "localization" || !strings.Contains(g.Where, "dallas-dx-1") {
		t.Fatalf("localized case must place WHERE at the seam: basis=%q where=%q", g.WhereBasis, g.Where)
	}
	// confirmed CONDITION but root cause not identified → owners stay "possible"
	if g.OwnersLabel != "Possible owner(s)" {
		t.Fatalf("owners label = %q — a confirmed condition never confirms the owner", g.OwnersLabel)
	}
}

func TestAtAGlanceHTMLIsFirstSectionWithRedPath(t *testing.T) {
	meta := testMeta("open", "suspected", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.5, "suspected",
			[]string{"bgp_adjacency_change"}, nil, nil, "isp", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	rep.Topology = rcaTopologyView{
		Available: true, VantageID: "v1", ObservedAt: "2026-07-12 18:12:00",
		Hops: []rcaSpineHopView{
			{Index: 1, Label: "edge-1", Kind: "vantage", State: "responding"},
			{Index: 2, Label: "wan-r2", Kind: "wan", State: "down", Fault: "broken"},
		},
	}
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	glance := strings.Index(doc, "Incident at a glance")
	mgmt := strings.Index(doc, "Management summary")
	if glance < 0 || mgmt < 0 || glance > mgmt {
		t.Fatalf("at-a-glance must be the FIRST section (glance@%d mgmt@%d)", glance, mgmt)
	}
	firstPage := doc[:strings.Index(doc, `<div class="pagebreak"`)]
	if !strings.Contains(firstPage, "<svg") {
		t.Fatal("the causality path graph must render on page 1")
	}
	// The broken hop renders RED (#dc2626) on page 1 — the owner's hard ask.
	if !strings.Contains(firstPage, "#dc2626") {
		t.Fatal("broken path area must render red on page 1")
	}
	for _, want := range []string{"Where it happened", "What possibly happened", "Possible owner(s)"} {
		if !strings.Contains(doc[glance:mgmt], want) {
			t.Fatalf("first section missing %q", want)
		}
	}
}

func TestAtAGlanceHTMLHonestWhenNoPath(t *testing.T) {
	meta := testMeta("open", "undetermined", "undetermined", nil)
	rep := buildTestReport(t, meta, []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
	})
	rep.Topology = rcaTopologyView{Available: false, Reason: "No measured path is attached to this case — the topology is omitted, not inferred."}
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	glance := strings.Index(doc, "Incident at a glance")
	mgmt := strings.Index(doc, "Management summary")
	if glance < 0 || !strings.Contains(doc[glance:mgmt], "omitted, not inferred") {
		t.Fatal("absent path must render its honest reason in the first section")
	}
}
