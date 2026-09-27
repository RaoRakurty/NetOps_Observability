// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
)

var sumCat = catalog.MustLoad()

func TestSummaryOfOneSeries(t *testing.T) {
	rs := &ResultSet{Metric: "cpu_util_pct", Series: []OutSeries{{Entity: map[string]string{"device": "edge-1"},
		Points: []Point{{T: 1, V: 40}, {T: 2, V: 90}, {T: 3, V: 50}}}}}
	got := Summarize(sumCat, &ast.AST{Type: ast.MetricSeries}, rs)
	for _, want := range []string{"edge-1", "latest 50%", "peak 90%", "average 60%"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q lacks %q", got, want)
		}
	}
}

func TestUnmeasuredIsNotZero(t *testing.T) {
	got := Summarize(sumCat, &ast.AST{Type: ast.MetricSeries}, &ResultSet{Metric: "circuit_loss_pct"})
	if !strings.Contains(got, "not the same as a value of zero") || strings.Contains(got, " 0%") {
		t.Fatalf("an empty metric answer must say nothing was measured: %q", got)
	}
}

func TestTopKRowsAreRankedAndTruncationSaid(t *testing.T) {
	var rows []Row
	for i := 0; i < 7; i++ {
		rows = append(rows, Row{"device": "d" + string(rune('a'+i)), "value": float64(90 - i)})
	}
	got := Summarize(sumCat, &ast.AST{Type: ast.MetricTopK}, &ResultSet{Metric: "mem_util_pct", Rows: rows, Truncated: true})
	if !strings.Contains(got, "da 90%") || !strings.Contains(got, "and 2 more") || !strings.Contains(got, "More results exist") {
		t.Fatalf("got %q", got)
	}
}

func TestCompareRowsShowTheDelta(t *testing.T) {
	got := Summarize(sumCat, &ast.AST{Type: ast.CompareWindows}, &ResultSet{Metric: "circuit_latency_ms",
		Rows: []Row{{"circuit": "c1", "value": 40.0, "previous": 30.0, "delta": 10.0}, {"circuit": "c2", "value": 20.0, "delta": -5.0}}})
	if !strings.Contains(got, "c1 40 ms (+10 ms vs before)") || !strings.Contains(got, "c2 20 ms (-5 ms vs before)") {
		t.Fatalf("got %q", got)
	}
}

func TestChangeAndIncidentLists(t *testing.T) {
	at := time.Date(2026, 9, 27, 9, 5, 0, 0, time.UTC)
	got := Summarize(sumCat, &ast.AST{Type: ast.ChangeList}, &ResultSet{Truncated: true, Rows: []Row{
		{"time": at, "type": "CONFIG_CHANGE", "object": "edge-1", "actor": "alice", "summary": "acl edit"}}})
	if !strings.Contains(got, "1 change (more exist") || !strings.Contains(got, "Sep 27 09:05 UTC · CONFIG_CHANGE on edge-1 · by alice — acl edit") {
		t.Fatalf("changes: %q", got)
	}
	got = Summarize(sumCat, &ast.AST{Type: ast.IncidentList}, &ResultSet{Rows: []Row{
		{"display_id": "INC-7", "title": "WAN loss", "state": "open", "verdict_tier": "confirmed"}}})
	if !strings.Contains(got, "INC-7 WAN loss (open, confirmed)") {
		t.Fatalf("incidents: %q", got)
	}
	if got := Summarize(sumCat, &ast.AST{Type: ast.ChangeList}, &ResultSet{}); got != "No changes match in this window." {
		t.Fatalf("empty list: %q", got)
	}
}

func TestPlannerNotesAreKept(t *testing.T) {
	got := Summarize(sumCat, &ast.AST{Type: ast.IncidentList}, &ResultSet{Notes: []string{"2 devices could not be placed in a site."}})
	if !strings.Contains(got, "could not be placed") {
		t.Fatalf("notes dropped: %q", got)
	}
}
