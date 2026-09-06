// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSplitGapToken(t *testing.T) {
	cases := []struct{ in, sig, clause string }{
		{"ospf_adjacency_loss: needs second-modality observer", "ospf_adjacency_loss", "second-modality observer"},
		{"bgp_session_down: single observer", "bgp_session_down", "single observer"},
		{"freeform note without colon", "uncategorized", "freeform note without colon"},
		{"  ", "", ""},
	}
	for _, c := range cases {
		sig, clause := splitGapToken(c.in)
		if sig != c.sig || clause != c.clause {
			t.Errorf("splitGapToken(%q) = (%q,%q), want (%q,%q)", c.in, sig, clause, c.sig, c.clause)
		}
	}
}

func TestClusterUndetermined(t *testing.T) {
	base := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	objs := []undeterminedObj{
		// Three incidents that all almost-hit the same nearest signature → one cluster.
		{CorrelationID: "a", WindowStart: base, EvidenceMissing: []string{"ospf_adjacency_loss: needs second observer"}, EntityTypes: []string{"device"}, SignalCount: 2},
		{CorrelationID: "b", WindowStart: base.Add(time.Hour), EvidenceMissing: []string{"ospf_adjacency_loss: needs second observer"}, EntityTypes: []string{"device", "interface"}, SignalCount: 4},
		{CorrelationID: "c", WindowStart: base.Add(2 * time.Hour), EvidenceMissing: []string{"ospf_adjacency_loss: needs fate-shared pair"}, EntityTypes: []string{"device"}, SignalCount: 3},
		// A different, less-frequent shape.
		{CorrelationID: "d", WindowStart: base.Add(3 * time.Hour), EvidenceMissing: []string{"bgp_session_down: single observer"}, EntityTypes: []string{"path"}, SignalCount: 1},
		// No evidence tokens → falls back to the affected-entity shape, never dropped.
		{CorrelationID: "e", WindowStart: base, EvidenceMissing: nil, EntityTypes: []string{"site"}, SignalCount: 1},
	}

	clusters := clusterUndetermined(objs, 0)
	if len(clusters) != 3 {
		t.Fatalf("expected 3 clusters, got %d: %+v", len(clusters), clusters)
	}

	// Most-frequent first: the ospf cluster (3) leads.
	top := clusters[0]
	if top.Count != 3 {
		t.Fatalf("top cluster count = %d, want 3", top.Count)
	}
	if len(top.NearestSignatures) != 1 || top.NearestSignatures[0] != "ospf_adjacency_loss" {
		t.Errorf("top nearest signatures = %v, want [ospf_adjacency_loss]", top.NearestSignatures)
	}
	// Examples capped at 3, last-seen is the most recent member, entity-type union.
	if len(top.Examples) != 3 {
		t.Errorf("examples = %v, want 3", top.Examples)
	}
	if top.LastSeen != base.Add(2*time.Hour).Format(time.RFC3339) {
		t.Errorf("last_seen = %q, want %v", top.LastSeen, base.Add(2*time.Hour))
	}
	if !eqStrSet(top.EntityTypes, []string{"device", "interface"}) {
		t.Errorf("entity types = %v, want device+interface", top.EntityTypes)
	}
	// avg signals = (2+4+3)/3 = 3.0
	if top.AvgSignals != 3.0 {
		t.Errorf("avg signals = %v, want 3.0", top.AvgSignals)
	}
	// The most common gap clause leads top_gaps (two "needs second observer").
	if len(top.TopGaps) == 0 || top.TopGaps[0].Clause != "second observer" || top.TopGaps[0].Count != 2 {
		t.Errorf("top gap = %+v, want {second observer, 2}", top.TopGaps)
	}

	// The token-less object survives as its own shape cluster.
	var siteShape *undeterminedCluster
	for i := range clusters {
		if clusters[i].Fingerprint == "shape:site" {
			siteShape = &clusters[i]
		}
	}
	if siteShape == nil || siteShape.Count != 1 {
		t.Fatalf("token-less object must form a shape cluster, got %+v", clusters)
	}

	// topN truncates.
	if got := clusterUndetermined(objs, 1); len(got) != 1 {
		t.Errorf("topN=1 should return 1 cluster, got %d", len(got))
	}
}

func TestEntityTypesFromAffected(t *testing.T) {
	got := entityTypesFromAffected(`{"devices":["r1"],"interfaces":["r1/Et1"],"paths":[]}`)
	if !eqStrSet(got, []string{"device", "interface"}) {
		t.Errorf("entity types = %v, want device+interface", got)
	}
	if got := entityTypesFromAffected(""); len(got) != 0 {
		t.Errorf("empty affected → no types, got %v", got)
	}
	if got := entityTypesFromAffected("not json"); len(got) != 0 {
		t.Errorf("bad json → no types, got %v", got)
	}
}

func eqStrSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

// ── #80 SQL contract (the 502-for-its-whole-life bug) ────────────────────────

// TestUndeterminedFrequencySQLDoesNotShadowTypedColumns is the hermetic half of
// the live shape check: the projection must not alias a converted expression
// back onto the column it was converted from, because ClickHouse resolves a
// SELECT alias inside the WHERE and ORDER BY of the SAME query. The endpoint
// shipped doing exactly that and answered
//
//	Code: 386 … no supertype for types String, DateTime (NO_COMMON_TYPE)
//
// for every caller, on every window, empty or not. Reverting either alias fails
// this test.
func TestUndeterminedFrequencySQLDoesNotShadowTypedColumns(t *testing.T) {
	sql := undeterminedFrequencySQL("604800")

	for _, shadow := range []string{"AS correlation_id\n", "AS correlation_id,", "AS window_start\n", "AS window_start,"} {
		if strings.Contains(sql, shadow) {
			t.Errorf("projection re-aliases a converted expression onto its own typed column (%q) — the WHERE/ORDER BY then bind the String:\n%s", strings.TrimSpace(shadow), sql)
		}
	}
	if !strings.Contains(sql, "AS correlation_id_s") || !strings.Contains(sql, "AS window_start_iso") {
		t.Errorf("the projection must use non-shadowing result names (correlation_id_s / window_start_iso):\n%s", sql)
	}
	// The predicate and the sort must both bind the RAW DateTime64 column. They
	// move together: a window bound and an ordering in different domains steps
	// over rows silently, which is worse than the exception.
	if !strings.Contains(sql, "AND window_start >= now() - INTERVAL 604800 SECOND") {
		t.Errorf("the window predicate must bind the raw window_start column:\n%s", sql)
	}
	if !strings.Contains(sql, "ORDER BY window_start DESC") {
		t.Errorf("ORDER BY must bind the raw window_start column:\n%s", sql)
	}
	// Bounded by construction (§9 / #100 read budgets).
	if !strings.Contains(sql, "LIMIT 5000") {
		t.Errorf("the scan must stay hard-capped:\n%s", sql)
	}
}

// TestUndeterminedFrequencyHandlerReadsTheRenamedColumns is the endpoint
// regression: a fake ClickHouse answers with the result columns the fixed SQL
// projects, and the handler must cluster them. If the row scan is left reading
// the OLD names, every field decodes to its zero value and the endpoint serves
// a 200 full of empty clusters — a silent failure, worse than the 502.
func TestUndeterminedFrequencyHandlerReadsTheRenamedColumns(t *testing.T) {
	var gotSQL string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSQL = string(b)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
			{
				"correlation_id_s": "11111111-1111-4111-8111-111111111111",
				"window_start_iso": "2026-08-31T19:08:28.982Z",
				"evidence_missing": `["sig.ent.fabric.isis-adjacency-flap: needs isis_adjacency_change"]`,
				"affected":         `{"interfaces":["mlx-1:Gi0/51"]}`,
				"signal_count":     1,
			},
			{
				"correlation_id_s": "22222222-2222-4222-8222-222222222222",
				"window_start_iso": "2026-08-31T18:00:00.000Z",
				"evidence_missing": `["sig.ent.fabric.isis-adjacency-flap: needs isis_adjacency_change"]`,
				"affected":         `{"devices":["mlx-2"]}`,
				"signal_count":     3,
			},
		}})
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)

	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, body := do(t, srv, "GET", "/api/correlations/undetermined-frequency?since=604800s&top=12", admin, nil)
	if st != http.StatusOK {
		t.Fatalf("status %d: %s", st, body)
	}
	var resp struct {
		Total    int                   `json:"total_undetermined"`
		Clusters []undeterminedCluster `json:"clusters"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if resp.Total != 2 {
		t.Fatalf("total_undetermined = %d, want 2 — the scan did not read the rows", resp.Total)
	}
	if len(resp.Clusters) != 1 {
		t.Fatalf("expected the two rows to share one gap-shape cluster, got %d: %+v", len(resp.Clusters), resp.Clusters)
	}
	c := resp.Clusters[0]
	if c.Count != 2 {
		t.Errorf("cluster count = %d, want 2", c.Count)
	}
	if len(c.Examples) != 2 || c.Examples[0] != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("correlation ids did not decode — the scan is reading the wrong result column: %+v", c.Examples)
	}
	if c.LastSeen != "2026-08-31T19:08:28Z" {
		t.Errorf("last_seen = %q — the window timestamp did not decode from window_start_iso", c.LastSeen)
	}
	if c.AvgSignals != 2 {
		t.Errorf("avg_signals = %v, want 2", c.AvgSignals)
	}
	if len(c.EntityTypes) != 2 {
		t.Errorf("entity types did not decode from `affected`: %+v", c.EntityTypes)
	}
	if !strings.Contains(gotSQL, "AS window_start_iso") || strings.Contains(gotSQL, "AS window_start\n") {
		t.Errorf("the handler sent a shadowing projection:\n%s", gotSQL)
	}
}
