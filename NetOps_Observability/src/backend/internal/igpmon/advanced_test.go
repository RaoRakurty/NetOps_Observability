// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package igpmon

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// advanced_test.go — the four depth blocks (LSDB, areas, SPF runs, timers).
//
// Every test here is written around the SAME property: a block that was
// measured shows the measurement, and a block that was not shows null with a
// note that names the series and its transport. The blocks are exercised
// independently — one collected and three absent, in every combination the
// per-block flags allow — because the failure this package exists to prevent is
// precisely the one where a partly-collected surface renders as a whole one.

// blockOf pulls one response block out as a decoded map.
func blockOf(t *testing.T, body map[string]any, key string) map[string]any {
	t.Helper()
	blk, ok := body[key].(map[string]any)
	if !ok {
		t.Fatalf("response has no %q block: %v", key, body[key])
	}
	return blk
}

// numOrNil renders a JSON number field as *int so a test can tell 0 from null.
func numOrNil(t *testing.T, v any) *int {
	t.Helper()
	if v == nil {
		return nil
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("field is not a number: %#v", v)
	}
	n := int(f)
	return &n
}

// seedISISDepth programs the harness with one device's worth of every IS-IS
// depth series, using the exact canonical label sets the gnmic chain emits
// (proven against the lab fabric in tests/test_gnmi_correlation_lane.py).
func seedISISDepth(h *harness, ids []string) {
	h.samples[seriesQuery(ProtoISIS.LSDBMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "spine1", "vrf": "default", "isis_level": "L2"}, Value: 6},
		{Labels: map[string]string{"device": "spine1", "vrf": "default", "isis_level": "L1"}, Value: 2},
	}
	h.samples[seriesQuery(ProtoISIS.SPFMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "spine1", "vrf": "default", "isis_level": "L2"}, Value: 10},
	}
	h.samples[seriesQuery(ProtoISIS.AreaMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "spine1", "vrf": "default", "area": "49.0001"}, Value: 1},
		{Labels: map[string]string{"device": "spine1", "vrf": "default", "area": "49.0002"}, Value: 1},
		// A repeat of the same area from a second instance is one membership,
		// not two.
		{Labels: map[string]string{"device": "spine1", "vrf": "default", "area": "49.0001"}, Value: 1},
	}
	h.samples[seriesQuery(ProtoISIS.HoldMetric(), ids)] = []Sample{
		{Labels: map[string]string{
			"device": "spine1", "isis_neighbor": "0100.0000.0011",
			"ifName": "ethernet-1/1.0", "isis_level": "L2"}, Value: 27},
	}
}

// ── all four present ────────────────────────────────────────────────────────

func TestAdvancedBlocksReportEveryCollectedSource(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("spine1", "spine1", "acme")
	ids := []string{"spine1"}
	seedISISDepth(h, ids)

	w, body := h.get("/api/protocols/isis/health?device=spine1")
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d", w.Code)
	}
	cov := coverageOf(t, body)
	if !cov.LSDB || !cov.Areas || !cov.SPFRuns || !cov.Timers {
		t.Fatalf("coverage = %+v, want all four depth sources collected", cov)
	}

	lsdb := blockOf(t, body, "lsdb")
	if got := numOrNil(t, lsdb["lsp_count"]); got == nil || *got != 8 {
		t.Errorf("lsdb.lsp_count = %v, want 8 (L1 2 + L2 6)", lsdb["lsp_count"])
	}
	if lsdb["scope_label"] != "isis_level" {
		t.Errorf("lsdb.scope_label = %v, want isis_level", lsdb["scope_label"])
	}
	// by_scope must keep the per-level split: a router with 6 L2 LSPs and 2 L1
	// is a different animal from one with 8 in a single level.
	var scopes []ScopeCount
	raw, err := json.Marshal(lsdb["by_scope"])
	if err != nil {
		t.Fatalf("marshal by_scope: %v", err)
	}
	if err := json.Unmarshal(raw, &scopes); err != nil {
		t.Fatalf("decode by_scope: %v", err)
	}
	want := []ScopeCount{{Scope: "L1", Count: 2}, {Scope: "L2", Count: 6}}
	if !reflect.DeepEqual(scopes, want) {
		t.Errorf("lsdb.by_scope = %+v, want %+v", scopes, want)
	}

	areas := blockOf(t, body, "areas")
	gotAreas, _ := areas["areas"].([]any)
	if len(gotAreas) != 2 || gotAreas[0] != "49.0001" || gotAreas[1] != "49.0002" {
		t.Errorf("areas.areas = %v, want the two distinct areas, sorted", areas["areas"])
	}

	spf := blockOf(t, body, "spf_runs")
	if got := numOrNil(t, spf["runs"]); got == nil || *got != 10 {
		t.Errorf("spf_runs.runs = %v, want 10", spf["runs"])
	}

	timers := blockOf(t, body, "timers")
	if timers["scope_kind"] != "adjacency" {
		t.Errorf("timers.scope_kind = %v, want adjacency (IS-IS is per-neighbour)", timers["scope_kind"])
	}
	rows, _ := timers["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("timers.rows = %v, want one adjacency", timers["rows"])
	}
	row, _ := rows[0].(map[string]any)
	if row["scope"] != "0100.0000.0011" || row["ifname"] != "ethernet-1/1.0" {
		t.Errorf("timer row identity = %v", row)
	}
	if got := numOrNil(t, row["hold_seconds"]); got == nil || *got != 27 {
		t.Errorf("timer row hold_seconds = %v, want 27", row["hold_seconds"])
	}
}

// The hold timer belongs to an ADJACENCY, so it must also arrive on the
// adjacency row itself — an operator reading one line should not have to
// cross-reference a second table to see the countdown for that neighbour.
func TestAdjacencyRowCarriesItsHoldTimerAndNeverInventsOne(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("spine1", "spine1", "acme")
	ids := []string{"spine1"}
	h.samples[seriesQuery(ProtoISIS.AdjMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "spine1", "isis_neighbor": "0100.0000.0011"}, Value: 3},
		{Labels: map[string]string{"device": "spine1", "isis_neighbor": "0100.0000.0012"}, Value: 3},
	}
	// Only the FIRST adjacency has a hold sample.
	h.samples[seriesQuery(ProtoISIS.HoldMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "spine1", "isis_neighbor": "0100.0000.0011"}, Value: 27},
	}
	w, body := h.get("/api/protocols/isis/adjacencies?device=spine1")
	if w.Code != http.StatusOK {
		t.Fatalf("adjacencies = %d", w.Code)
	}
	rows, _ := body["adjacencies"].([]any)
	if len(rows) != 2 {
		t.Fatalf("adjacencies = %v, want 2", body["adjacencies"])
	}
	byPeer := map[string]map[string]any{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		peer, _ := m["peer"].(string)
		byPeer[peer] = m
	}
	if got := numOrNil(t, byPeer["0100.0000.0011"]["hold_seconds"]); got == nil || *got != 27 {
		t.Errorf("the adjacency WITH a hold sample = %v, want 27", byPeer["0100.0000.0011"]["hold_seconds"])
	}
	// The one with no sample must be null. A 0 here reads as "expiring now".
	if got := numOrNil(t, byPeer["0100.0000.0012"]["hold_seconds"]); got != nil {
		t.Errorf("the adjacency with NO hold sample = %v, want null — never 0", *got)
	}
}

// ── each block absent, independently ────────────────────────────────────────

// TestEachDepthBlockIsAbsentOnItsOwn collects exactly ONE of the four sources
// and asserts the other three still say "not collected" with their own note.
// The four probes are independent reads; a shared flag would let one collected
// source vouch for three that were never wired.
func TestEachDepthBlockIsAbsentOnItsOwn(t *testing.T) {
	cases := []struct {
		name    string
		metric  string
		block   string
		field   string
		flag    func(Coverage) bool
		otherNo []string
	}{
		{"lsdb", ProtoISIS.LSDBMetric(), "lsdb", "lsp_count",
			func(c Coverage) bool { return c.LSDB }, []string{"areas", "spf_runs", "timers"}},
		{"areas", ProtoISIS.AreaMetric(), "areas", "areas",
			func(c Coverage) bool { return c.Areas }, []string{"lsdb", "spf_runs", "timers"}},
		{"spf", ProtoISIS.SPFMetric(), "spf_runs", "runs",
			func(c Coverage) bool { return c.SPFRuns }, []string{"lsdb", "areas", "timers"}},
		{"timers", ProtoISIS.HoldMetric(), "timers", "rows",
			func(c Coverage) bool { return c.Timers }, []string{"lsdb", "areas", "spf_runs"}},
	}
	fields := map[string]string{
		"lsdb": "lsp_count", "areas": "areas", "spf_runs": "runs", "timers": "rows",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.seedDevice("spine1", "spine1", "acme")
			ids := []string{"spine1"}
			h.samples[seriesQuery(tc.metric, ids)] = []Sample{
				{Labels: map[string]string{
					"device": "spine1", "isis_level": "L2", "area": "49.0001",
					"isis_neighbor": "0100.0000.0011"}, Value: 5},
			}
			w, body := h.get("/api/protocols/isis/health?device=spine1")
			if w.Code != http.StatusOK {
				t.Fatalf("health = %d", w.Code)
			}
			cov := coverageOf(t, body)
			if !tc.flag(cov) {
				t.Errorf("%s was collected but its coverage flag is false: %+v", tc.name, cov)
			}
			if blk := blockOf(t, body, tc.block); blk[tc.field] == nil {
				t.Errorf("%s block reports null despite a collected series: %v", tc.block, blk)
			}
			for _, other := range tc.otherNo {
				blk := blockOf(t, body, other)
				if blk[fields[other]] != nil {
					t.Errorf("%s.%s = %v, want null — that source was never collected",
						other, fields[other], blk[fields[other]])
				}
				if note, _ := blk["note"].(string); note == "" {
					t.Errorf("%s is absent with NO note; an absent source must say why", other)
				}
			}
		})
	}
}

// Absence notes must name the SERIES and its transport, so a reader can act on
// them (wire that collector) instead of merely being told "no data".
func TestDepthAbsenceNotesNameTheSeriesAndItsSource(t *testing.T) {
	for _, tc := range []struct {
		proto Proto
		block string
		want  []string
	}{
		{ProtoISIS, "lsdb", []string{"device_isis_lsp_count", "gNMI"}},
		{ProtoISIS, "areas", []string{"device_isis_area", "oper-area-id"}},
		{ProtoISIS, "spf_runs", []string{"device_isis_spf_runs_total", "gNMI"}},
		{ProtoISIS, "timers", []string{"device_isis_adj_hold_seconds", "countdown"}},
		{ProtoOSPF, "lsdb", []string{"device_ospf_lsdb_count", "ospfAreaLsaCount"}},
		{ProtoOSPF, "areas", []string{"device_ospf_area", "ospfAreaTable"}},
		{ProtoOSPF, "spf_runs", []string{"device_ospf_spf_runs_total", "ospfSpfRuns"}},
		// The OSPF timer note must state the SHAPE limit: OSPF-MIB has no
		// per-neighbour timer column at all, which is why the block is
		// per-interface and can never become per-adjacency.
		{ProtoOSPF, "timers", []string{"device_ospf_if_hello_seconds", "ospfNbrTable has no hello or dead column"}},
	} {
		h := newHarness(t)
		h.seedDevice("leaf1", "leaf1", "acme")
		_, body := h.get("/api/protocols/" + string(tc.proto) + "/health?device=leaf1")
		note, _ := blockOf(t, body, tc.block)["note"].(string)
		for _, want := range tc.want {
			if !strings.Contains(note, want) {
				t.Errorf("%s/%s note %q does not mention %q", tc.proto, tc.block, note, want)
			}
		}
	}
}

// ── OSPF timers: two columns, one interface ─────────────────────────────────

func TestOSPFTimersJoinHelloAndDeadPerInterface(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("edge1", "edge1", "acme")
	ids := []string{"edge1"}
	h.samples[seriesQuery(ProtoOSPF.HelloMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "edge1", "index": "10.0.0.1.0"}, Value: 10},
		// An interface that answered hello but not dead: a real half-row.
		{Labels: map[string]string{"device": "edge1", "index": "10.0.0.5.0"}, Value: 30},
	}
	h.samples[seriesQuery(ProtoOSPF.DeadMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "edge1", "index": "10.0.0.1.0"}, Value: 40},
	}
	w, body := h.get("/api/protocols/ospf/health?device=edge1")
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d", w.Code)
	}
	if !coverageOf(t, body).Timers {
		t.Fatal("OSPF timers were collected but coverage.timers is false")
	}
	timers := blockOf(t, body, "timers")
	if timers["scope_kind"] != "interface" {
		t.Errorf("scope_kind = %v, want interface (OSPF-MIB timers are per ospfIfTable row)", timers["scope_kind"])
	}
	rows, _ := timers["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v, want one per interface", timers["rows"])
	}
	byScope := map[string]map[string]any{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		s, _ := m["scope"].(string)
		byScope[s] = m
	}
	full := byScope["10.0.0.1.0"]
	if got := numOrNil(t, full["hello_seconds"]); got == nil || *got != 10 {
		t.Errorf("hello_seconds = %v, want 10", full["hello_seconds"])
	}
	if got := numOrNil(t, full["dead_seconds"]); got == nil || *got != 40 {
		t.Errorf("dead_seconds = %v, want 40", full["dead_seconds"])
	}
	// The half-row keeps its measured hello and a MISSING dead — not a dead of
	// 0, and not a dead inferred as 4x hello.
	half := byScope["10.0.0.5.0"]
	if got := numOrNil(t, half["hello_seconds"]); got == nil || *got != 30 {
		t.Errorf("half-row hello_seconds = %v, want 30", half["hello_seconds"])
	}
	if _, present := half["dead_seconds"]; present {
		t.Errorf("half-row invented a dead interval: %v", half["dead_seconds"])
	}
}

// ── the area info series: label, never value ────────────────────────────────

// The area series is an INFO series: its value is a placeholder (1 on the gNMI
// lane, the OSPF-MIB RowStatus on the SNMP one). Reading it as a measurement
// would turn a constant into a metric, so membership is taken from the LABEL
// only and a sample with no area label is not membership evidence at all.
func TestAreaMembershipComesFromTheLabelNotTheValue(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("edge1", "edge1", "acme")
	ids := []string{"edge1"}
	h.samples[seriesQuery(ProtoOSPF.AreaMetric(), ids)] = []Sample{
		{Labels: map[string]string{"device": "edge1", "area": "0.0.0.0"}, Value: 1},
		{Labels: map[string]string{"device": "edge1", "area": "0.0.0.1"}, Value: 3}, // RowStatus notReady
		{Labels: map[string]string{"device": "edge1"}, Value: 1},                    // no area → no membership
	}
	_, body := h.get("/api/protocols/ospf/health?device=edge1")
	areas, _ := blockOf(t, body, "areas")["areas"].([]any)
	if len(areas) != 2 || areas[0] != "0.0.0.0" || areas[1] != "0.0.0.1" {
		t.Errorf("areas = %v, want both labelled areas regardless of the placeholder value", areas)
	}
}

// A sample with no device label cannot be attributed and must not inflate a
// total — the same rule the adjacency and LSDB reads have always applied.
func TestUnattributableDepthSamplesAreNotCounted(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("spine1", "spine1", "acme")
	ids := []string{"spine1"}
	h.samples[seriesQuery(ProtoISIS.LSDBMetric(), ids)] = []Sample{
		{Labels: map[string]string{"isis_level": "L2"}, Value: 999}, // no device
	}
	_, body := h.get("/api/protocols/isis/health?device=spine1")
	if coverageOf(t, body).LSDB {
		t.Error("an unattributable sample was reported as LSDB coverage")
	}
	if blockOf(t, body, "lsdb")["lsp_count"] != nil {
		t.Errorf("lsp_count = %v, want null", blockOf(t, body, "lsdb")["lsp_count"])
	}
}

// ── the summary roll-up ─────────────────────────────────────────────────────

func TestSummaryCarriesTheDepthPerDevice(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("spine1", "spine1", "acme")
	// Fleet-wide reads carry no device selector.
	h.samples[seriesQuery(ProtoISIS.AdjMetric(), nil)] = []Sample{
		{Labels: map[string]string{"device": "spine1", "isis_neighbor": "n1"}, Value: 3},
		{Labels: map[string]string{"device": "spine2", "isis_neighbor": "n2"}, Value: 3},
	}
	// Only spine1 reports an LSDB count. spine2 must stay null, NOT 0.
	h.samples[seriesQuery(ProtoISIS.LSDBMetric(), nil)] = []Sample{
		{Labels: map[string]string{"device": "spine1", "isis_level": "L2"}, Value: 6},
	}
	_, body := h.get("/api/protocols/isis/summary")
	devices, _ := body["devices"].([]any)
	byDev := map[string]map[string]any{}
	for _, d := range devices {
		m, _ := d.(map[string]any)
		name, _ := m["device"].(string)
		byDev[name] = m
	}
	if got := numOrNil(t, byDev["spine1"]["lsp_count"]); got == nil || *got != 6 {
		t.Errorf("spine1 lsp_count = %v, want 6", byDev["spine1"]["lsp_count"])
	}
	if got := numOrNil(t, byDev["spine2"]["lsp_count"]); got != nil {
		t.Errorf("spine2 lsp_count = %d, want null — that device reported no LSDB series", *got)
	}
}

// AttachAdvanced is pure, so the "a device known only to the depth probes is
// still a device" rule is pinned without a transport.
func TestAttachAdvancedAppendsDevicesKnownOnlyToTheDepthProbes(t *testing.T) {
	base := []DeviceSummary{{Device: "spine1", Flaps: 2}}
	got := AttachAdvanced(base,
		map[string]int{"spine1": 6, "spine9": 4},
		map[string]int{"spine9": 11},
		map[string][]string{"spine9": {"49.0001"}})
	if len(got) != 2 {
		t.Fatalf("devices = %+v, want spine1 plus the depth-only spine9", got)
	}
	if got[0].Device != "spine1" || got[0].LSPCount == nil || *got[0].LSPCount != 6 {
		t.Errorf("spine1 = %+v", got[0])
	}
	if got[0].SPFRuns != nil || got[0].Areas != nil {
		t.Errorf("spine1 gained depth it never reported: %+v", got[0])
	}
	nine := got[1]
	if nine.Device != "spine9" || nine.LSPCount == nil || *nine.LSPCount != 4 ||
		nine.SPFRuns == nil || *nine.SPFRuns != 11 ||
		!reflect.DeepEqual(nine.Areas, []string{"49.0001"}) {
		t.Errorf("spine9 = %+v", nine)
	}
	// It reported no adjacency evidence, so those stay null.
	if nine.Adjacencies != nil || nine.DownAdjacencies != nil {
		t.Errorf("a depth-only device was given adjacency counts: %+v", nine)
	}
}

// ── the metric names themselves ─────────────────────────────────────────────

// The canonical names are the contract with the two collectors (the gnmic
// canon-names table and the SNMP standard profile). Pinning them here means a
// rename on either side fails a test instead of silently emptying a panel.
func TestDepthMetricNamesAreTheCanonicalContract(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{ProtoISIS.LSDBMetric(), "device_isis_lsp_count"},
		{ProtoISIS.AreaMetric(), "device_isis_area"},
		{ProtoISIS.SPFMetric(), "device_isis_spf_runs_total"},
		{ProtoISIS.HoldMetric(), "device_isis_adj_hold_seconds"},
		{ProtoOSPF.LSDBMetric(), "device_ospf_lsdb_count"},
		{ProtoOSPF.AreaMetric(), "device_ospf_area"},
		{ProtoOSPF.SPFMetric(), "device_ospf_spf_runs_total"},
		{ProtoOSPF.HelloMetric(), "device_ospf_if_hello_seconds"},
		{ProtoOSPF.DeadMetric(), "device_ospf_if_dead_seconds"},
	} {
		if tc.got != tc.want {
			t.Errorf("canonical name = %q, want %q", tc.got, tc.want)
		}
	}
	// The shapes that do NOT exist stay empty rather than aliasing the other
	// protocol's series — an OSPF "hold" that silently returned the IS-IS name
	// would query a series OSPF can never have.
	if ProtoOSPF.HoldMetric() != "" {
		t.Errorf("OSPF has no per-neighbour hold series, got %q", ProtoOSPF.HoldMetric())
	}
	if ProtoISIS.HelloMetric() != "" || ProtoISIS.DeadMetric() != "" {
		t.Errorf("IS-IS has no per-interface hello/dead series, got %q/%q",
			ProtoISIS.HelloMetric(), ProtoISIS.DeadMetric())
	}
	if ProtoOSPF.ScopeLabel() != "area" || ProtoISIS.ScopeLabel() != "isis_level" {
		t.Errorf("scope labels = %q/%q", ProtoOSPF.ScopeLabel(), ProtoISIS.ScopeLabel())
	}
}
