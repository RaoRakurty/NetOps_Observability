// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import "testing"

// The grammar reads through the shared normaliser: a name written with other
// separators, an accent, a number word or typographic quotes compile exactly
// as the plain question does.
func TestCompilerUsesTheSharedNormaliser(t *testing.T) {
	plain := run(t, "show cpu on edge-1", cx)
	if plain.AST == nil {
		t.Fatalf("baseline must compile: %+v", plain)
	}
	for _, q := range []string{"show cpu on edge1", "Show CPU on EDGE_1", "show cpu on “edge-1”"} {
		r := run(t, q, cx)
		if r.AST == nil || r.AST.Hash() != plain.AST.Hash() {
			t.Errorf("%q must compile like the plain question: %+v", q, r)
		}
	}
	top := run(t, "top five devices by cpu", cx)
	if top.AST == nil || top.AST.Limit != 5 {
		t.Errorf("a number word is a number: %+v", top)
	}
}

// One window, one query: "past 60m" and "the last hour" are the same window.
func TestWholeHoursAreWrittenInHours(t *testing.T) {
	for _, q := range []string{"cpu on edge-1 past 60m", "cpu on edge-1 last 60 minutes", "cpu on edge-1 last 120 mins"} {
		r := run(t, q, cx)
		if r.AST == nil || (r.AST.Time.Last != "1h" && r.AST.Time.Last != "2h") {
			t.Errorf("%q window = %+v", q, r.AST)
		}
	}
	if r := run(t, "cpu on edge-1 last 90 minutes", cx); r.AST == nil || r.AST.Time.Last != "90m" {
		t.Errorf("a window that is not whole hours keeps its minutes: %+v", r.AST)
	}
}

// "worst … per device" is the extreme OF each device (max), not a ranking of
// devices; a number or "top" still ranks.
func TestWorstPerGroupIsTheGroupsExtreme(t *testing.T) {
	r := run(t, "worst cpu per device last hour", cx)
	if r.AST == nil || r.AST.Type != "metric_series" || r.AST.Agg != "max" || len(r.AST.GroupBy) != 1 {
		t.Fatalf("worst per device = %+v", r.AST)
	}
	if r := run(t, "top 3 cpu per device last hour", cx); r.AST == nil || r.AST.Type != "metric_topk" {
		t.Errorf("a number still ranks: %+v", r.AST)
	}
}
