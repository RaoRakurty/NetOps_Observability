// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P-7EE84E: the RCA ego-graph must never overlap, at the screen's text size
// (14px bold labels) or at this document's (9px). These tests pin the rule in
// rca_report_topology_layout.go; pathModel.ts is held to the same positions by
// the shared golden testdata/topoctx/ego_layout.golden.json.

// printFootprint is what THIS document draws around a node (topoEgoSVG):
// label 9px bold at r+11, role 7.5px at r+21, mark 7.5px bold at r-5 — with
// its own truncation limits — measured with conservative per-char advances.
func printFootprint(label, role, mark string, anchor bool) topoFootprint {
	r := 14.0
	if anchor {
		r = 18
	}
	halfW := math.Max(r, 5.6*float64(topoRuneCount(label, 22))/2)
	if role != "" {
		halfW = math.Max(halfW, 4.2*float64(topoRuneCount(role, 26))/2)
	}
	if mark != "" {
		halfW = math.Max(halfW, 4.65*float64(topoRuneCount(mark, 51))/2)
	}
	f := topoFootprint{halfW: halfW, above: r, below: r + 11 + 2.5}
	if mark != "" {
		f.above = r + 5 + 7.5
	}
	if role != "" {
		f.below = r + 21 + 2
	}
	return f
}

// assertClean fails when any two node footprints intersect, or one leaves the
// picture, for the given footprint function.
func assertClean(t *testing.T, name string, tc TopologyContext, w, h float64, pos map[string][2]float64,
	foot func(label, role, mark string, anchor bool) topoFootprint) {
	t.Helper()
	type nb struct {
		id string
		b  topoBox
	}
	var boxes []nb
	for _, n := range tc.Nodes {
		p, ok := pos[n.ID]
		if !ok {
			t.Fatalf("%s: node %s has no position", name, n.ID)
		}
		b := topoEgoBox(p, foot(n.Label, topoEgoRole(n), topoEgoMarkText(tc, n.ID), n.Anchor))
		if b.x0 < -0.01 || b.y0 < -0.01 || b.x1 > w+0.01 || b.y1 > h+0.01 {
			t.Errorf("%s: %s leaves the %gx%g picture: %+v", name, n.ID, w, h, b)
		}
		boxes = append(boxes, nb{n.ID, b})
	}
	for i := range boxes {
		for j := i + 1; j < len(boxes); j++ {
			if topoBoxesOverlap(boxes[i].b, boxes[j].b, 0) {
				t.Errorf("%s: %s and %s overlap: %+v %+v", name, boxes[i].id, boxes[j].id, boxes[i].b, boxes[j].b)
			}
		}
	}
}

// genEgoContext builds a context with `anchors` anchors and `neigh` neighbours,
// labels and roles at (or past) the truncation limits, every anchor linked to
// every neighbour, and — when marks — anomalous interfaces on the anchors and
// on every third neighbour.
func genEgoContext(anchors, neigh int, marks bool) TopologyContext {
	tc := TopologyContext{State: TopoStateTopologyOnly}
	for i := 0; i < anchors; i++ {
		id := fmt.Sprintf("anchor-%d", i)
		tc.Nodes = append(tc.Nodes, TopoCtxNode{ID: id, Label: fmt.Sprintf("core-router-%02d-very-long-hostname", i), Role: "dc_spine_border_router_x", Source: "inventory", Anchor: true, Managed: true})
		tc.Anchors = append(tc.Anchors, id)
		if marks {
			tc.Faults = append(tc.Faults,
				FaultMark{TargetType: "interface", TargetID: id + ":GigabitEthernet0/0/1", Device: id, Port: "GigabitEthernet0/0/1", Kinds: []string{"link_down"}, PeakSeverity: "crit"},
				FaultMark{TargetType: "interface", TargetID: id + ":TenGigE0/1/0/3", Device: id, Port: "TenGigE0/1/0/3", Kinds: []string{"if_errors"}, PeakSeverity: "warn"})
		}
	}
	for i := 0; i < neigh; i++ {
		id := fmt.Sprintf("n-%d", i)
		managed := i%5 != 0
		role := "wan_edge_router_branch_x"
		if !managed {
			role = ""
		}
		tc.Nodes = append(tc.Nodes, TopoCtxNode{ID: id, Label: fmt.Sprintf("branch-site-%02d-edge-router", i), Role: role, Source: "lldp", Managed: managed})
		if marks && i%3 == 0 {
			tc.Faults = append(tc.Faults, FaultMark{TargetType: "interface", TargetID: id + ":Tunnel100", Device: id, Port: "Tunnel100", Kinds: []string{"tunnel_down"}, PeakSeverity: "high"})
		}
	}
	for a := 0; a < anchors; a++ {
		for i := 0; i < neigh; i++ {
			tc.Edges = append(tc.Edges, TopoCtxEdge{ID: fmt.Sprintf("e-%d-%d", a, i), A: fmt.Sprintf("anchor-%d", a), B: fmt.Sprintf("n-%d", i), Relationship: "l3", Sources: []string{"lldp"}, Freshness: "current"})
		}
	}
	if anchors == 0 && neigh > 1 {
		tc.Edges = append(tc.Edges, TopoCtxEdge{ID: "e-n", A: "n-0", B: "n-1", Relationship: "l3", Sources: []string{"lldp"}, Freshness: "current"})
	}
	return tc
}

// labEgoContext is shaped like the lab's SD-WAN estate (P-7EE84E was raised
// on it): two faulted edges as anchors, 14 neighbours — controllers and other
// edges — with the hostnames and roles the lab reports.
func labEgoContext() TopologyContext {
	tc := TopologyContext{State: TopoStateWithPath}
	add := func(id, label, role string, anchor, managed bool) {
		tc.Nodes = append(tc.Nodes, TopoCtxNode{ID: id, Label: label, Role: role, Source: "inventory", Anchor: anchor, Managed: managed})
		if anchor {
			tc.Anchors = append(tc.Anchors, id)
		}
	}
	add("cedge-81-dde8d64d", "cEDGE-81", "wan_edge", true, true)
	add("vedge-51-79fbba30", "vEdge-51", "wan_edge", true, true)
	for _, n := range [][3]string{
		{"vsmart-1", "vSmart", "controller"}, {"vbond-1", "vBond", "orchestrator"}, {"vmanage-1", "vManage", "manager"},
		{"cedge-40-fdf7b64f", "cEDGE-40", "wan_edge"}, {"cedge-60-07ae8615", "cEDGE-60", "wan_edge"},
		{"cedge-80-b0afc197", "cEDGE-80", "wan_edge"}, {"vedge-52-bf77ee2c", "vEdge-52", "wan_edge"},
		{"vedge-20-02efdcad", "vEdge-20", "wan_edge"}, {"vedge-100-3efc4148", "vEdge-100", "wan_edge"},
		{"isp-a", "ISP-A internet transport", "carrier"}, {"isp-b", "ISP-B MPLS transport", "carrier"},
		{"dc-core-1", "dc-core-1.lab.correlix.local", "dc_core"}, {"fw-1", "branch-fw-81", "firewall"},
		{"ext-1", "203.0.113.7", ""},
	} {
		add(n[0], n[1], n[2], false, n[0] != "ext-1")
	}
	for _, d := range []string{"cedge-81-dde8d64d", "vedge-51-79fbba30"} {
		tc.Faults = append(tc.Faults,
			FaultMark{TargetType: "interface", TargetID: d + ":GigabitEthernet2", Device: d, Port: "GigabitEthernet2", Kinds: []string{"link_down"}, PeakSeverity: "crit"},
			FaultMark{TargetType: "interface", TargetID: d + ":Tunnel100002", Device: d, Port: "Tunnel100002", Kinds: []string{"tunnel_down"}, PeakSeverity: "high"})
	}
	tc.Faults = append(tc.Faults, FaultMark{TargetType: "interface", TargetID: "vsmart-1:eth1", Device: "vsmart-1", Port: "eth1", Kinds: []string{"bfd_down"}, PeakSeverity: "warn"})
	for i, n := range tc.Nodes {
		if n.Anchor {
			continue
		}
		a := tc.Anchors[i%2]
		tc.Edges = append(tc.Edges, TopoCtxEdge{ID: "e-" + n.ID, A: a, B: n.ID, Relationship: "overlay", Sources: []string{"vmanage"}, Freshness: "current"})
	}
	tc.Edges = append(tc.Edges, TopoCtxEdge{ID: "e-anchors", A: tc.Anchors[0], B: tc.Anchors[1], Relationship: "overlay", Sources: []string{"vmanage"}, Freshness: "current"})
	return tc
}

func TestEgoLayoutNeverOverlapsAtEitherTextScale(t *testing.T) {
	for anchors := 0; anchors <= 6; anchors++ {
		for neigh := 1; neigh <= 30; neigh++ {
			for _, marks := range []bool{false, true} {
				tc := genEgoContext(anchors, neigh, marks)
				name := fmt.Sprintf("anchors=%d neigh=%d marks=%v", anchors, neigh, marks)
				w, h, pos := topoEgoGeometry(tc)
				if w != topoEgoW {
					t.Fatalf("%s: width %g — the picture must stay %g wide so no renderer shrinks its text", name, w, topoEgoW)
				}
				assertClean(t, name+" [screen]", tc, w, h, pos, topoEgoFootprint)
				assertClean(t, name+" [print]", tc, w, h, pos, printFootprint)
			}
		}
	}
}

// The print text always fits inside the screen footprint — the reason ONE
// geometry is clean at both scales.
func TestPrintFootprintFitsInsideScreenFootprint(t *testing.T) {
	long := strings.Repeat("W", 40)
	for _, anchor := range []bool{false, true} {
		for _, label := range []string{"a", "cEDGE-81", long} {
			for _, role := range []string{"", "wan edge", long} {
				for _, mark := range []string{"", "anomalous: Gi2", "anomalous: " + long} {
					s, p := topoEgoFootprint(label, role, mark, anchor), printFootprint(label, role, mark, anchor)
					if p.halfW > s.halfW || p.above > s.above || p.below > s.below {
						t.Errorf("print footprint %+v exceeds screen %+v (label=%q role=%q mark=%q)", p, s, label, role, mark)
					}
				}
			}
		}
	}
}

// oldEgoGeometry is the pre-P-7EE84E fixed-slot layout, kept here only to show
// the lab context really did collide on screen.
func oldEgoGeometry(tc TopologyContext) (float64, float64, map[string][2]float64) {
	const w = 760.0
	var anchors, neigh []TopoCtxNode
	for _, n := range tc.Nodes {
		if n.Anchor {
			anchors = append(anchors, n)
		} else {
			neigh = append(neigh, n)
		}
	}
	h := 250.0
	if len(neigh) > 8 {
		h = 330
	}
	pos := map[string][2]float64{}
	spacing := math.Min(140, 560/math.Max(1, float64(len(anchors))))
	for i, a := range anchors {
		pos[a.ID] = [2]float64{w/2 + (float64(i)-float64(len(anchors)-1)/2)*spacing, h / 2}
	}
	var top, bottom []TopoCtxNode
	for i, n := range neigh {
		if i%2 == 0 {
			top = append(top, n)
		} else {
			bottom = append(bottom, n)
		}
	}
	for _, row := range []struct {
		nodes []TopoCtxNode
		y     float64
	}{{top, 40}, {bottom, h - 52}} {
		for j, n := range row.nodes {
			pos[n.ID] = [2]float64{50 + (w-100)*(float64(j)+0.5)/float64(len(row.nodes)), row.y}
		}
	}
	return w, h, pos
}

func TestLabShapedEgoIsCleanAndTheOldSlotsWereNot(t *testing.T) {
	tc := labEgoContext()
	w, h, pos := topoEgoGeometry(tc)
	assertClean(t, "lab [screen]", tc, w, h, pos, topoEgoFootprint)
	assertClean(t, "lab [print]", tc, w, h, pos, printFootprint)

	// The regression: the old fixed slots overlapped at the screen's text size.
	_, _, old := oldEgoGeometry(tc)
	collisions := 0
	for i, a := range tc.Nodes {
		for _, b := range tc.Nodes[i+1:] {
			ba := topoEgoBox(old[a.ID], topoEgoFootprint(a.Label, topoEgoRole(a), topoEgoMarkText(tc, a.ID), a.Anchor))
			bb := topoEgoBox(old[b.ID], topoEgoFootprint(b.Label, topoEgoRole(b), topoEgoMarkText(tc, b.ID), b.Anchor))
			if topoBoxesOverlap(ba, bb, 0) {
				collisions++
			}
		}
	}
	if collisions == 0 {
		t.Fatal("the lab fixture no longer reproduces P-7EE84E on the old layout — the regression test lost its teeth")
	}
}

// The lab's device panels: the device name and its port boxes never collide.
func TestDevicePanelBoxesHoldTheirText(t *testing.T) {
	tc := labEgoContext()
	var b strings.Builder
	topoDeviceSVG(&b, tc, tc.Nodes[0])
	if !strings.Contains(b.String(), `width="240" height="54"`) {
		t.Fatalf("device box is not 240 wide — a 24-char 14px bold name (≈209px) needs it:\n%s", b.String())
	}
	if got := topoEgoLabelCh * 24; got+2*8 > 240 {
		t.Fatalf("a 24-char screen device name (%gpx + padding) no longer fits the 240px box", got)
	}
}

// ── parity golden shared with pathModel.ts ──────────────────────────────────

type egoLayoutCase struct {
	Name    string                `json:"name"`
	Context TopologyContext       `json:"context"`
	W       float64               `json:"w"`
	H       float64               `json:"h"`
	Pos     map[string][2]float64 `json:"pos"`
}

func egoParityCases() []egoLayoutCase {
	cases := []egoLayoutCase{{Name: "lab-sdwan", Context: labEgoContext()}}
	for _, g := range []struct{ a, n int }{{1, 3}, {1, 12}, {0, 5}, {2, 8}, {3, 16}, {6, 24}} {
		cases = append(cases, egoLayoutCase{Name: fmt.Sprintf("gen-a%d-n%d", g.a, g.n), Context: genEgoContext(g.a, g.n, true)})
	}
	return cases
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func TestEgoLayoutParityGolden(t *testing.T) {
	cases := egoParityCases()
	for i := range cases {
		w, h, pos := topoEgoGeometry(cases[i].Context)
		cases[i].W, cases[i].H = round2(w), round2(h)
		cases[i].Pos = map[string][2]float64{}
		for id, p := range pos {
			cases[i].Pos[id] = [2]float64{round2(p[0]), round2(p[1])}
		}
	}
	got, err := json.MarshalIndent(map[string]any{
		"_comment": "P-7EE84E parity golden: rca_report_topology_layout.go and pathModel.ts egoGeometry must produce these positions. Refresh with RCA_UPDATE_TOPOCTX_GOLDEN=1 go test ./internal/rca/ -run TestEgoLayoutParityGolden.",
		"cases":    cases,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "topoctx", "ego_layout.golden.json")
	if os.Getenv("RCA_UPDATE_TOPOCTX_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (refresh with RCA_UPDATE_TOPOCTX_GOLDEN=1): %v", err)
	}
	if string(want) != string(got) {
		t.Fatalf("ego layout drifted from %s — refresh with RCA_UPDATE_TOPOCTX_GOLDEN=1, review, and keep pathModel.ts in step", path)
	}
}
