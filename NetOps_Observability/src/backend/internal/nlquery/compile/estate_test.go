// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// estate_test.go — N-H6 step 3 phrasings: the estate-wide "what is unusual
// right now for this time of week" compiles to seasonal_outliers; the
// one-metric yes/no question and the peer comparison stay where they were.

import (
	"reflect"
	"testing"

	"netops/backend/internal/nlquery/ast"
)

func TestEstateQuestionsCompileToSeasonalOutliers(t *testing.T) {
	traffic := []ast.Filter{{Field: ast.FilterMetric, Op: "in", Values: []string{"if_in_bps", "if_out_bps"}}}
	for _, c := range []struct {
		q       string
		target  string
		metric  string
		filters []ast.Filter
		above   bool
		refs    []string
	}{
		{q: "what's abnormal right now for this time of week"},
		{q: "what is abnormal right now for this time of week?"},
		{q: "which interfaces are unusually busy for this time of day", target: "interface", filters: traffic, above: true},
		{q: "anything unusual compared with a normal Tuesday morning"},
		{q: "is anything unusual for this time of week"},
		{q: "any devices behaving abnormally for the time of day", target: "device"},
		{q: "which circuits have unusual latency for this time of week", target: "circuit", metric: "circuit_latency_ms"},
		{q: "anything unusual on edge-1 for this time of week", refs: []string{"device:edge-1"}},
		{q: "what's unusually high right now compared to a typical weekday afternoon", above: true},
	} {
		r := run(t, c.q, cx)
		if r.AST == nil {
			t.Errorf("%q: not compiled (%+v)", c.q, r)
			continue
		}
		a := r.AST
		if a.Type != ast.SeasonalOutliers || a.Target != c.target || a.Metric != c.metric || !reflect.DeepEqual(a.Filters, c.filters) {
			t.Errorf("%q: %+v, want seasonal_outliers target=%q metric=%q filters=%v", c.q, a, c.target, c.metric, c.filters)
		}
		if (a.Predicate != nil) != c.above || a.Predicate != nil && a.Predicate.Op != "above_baseline" {
			t.Errorf("%q: predicate %+v, want above-only=%v", c.q, a.Predicate, c.above)
		}
		if a.Time.Kind != "" {
			t.Errorf("%q: the estate answer has no window of its own, got %+v", c.q, a.Time)
		}
		var ids []string
		for _, rf := range a.Refs {
			ids = append(ids, rf.ID)
		}
		if !reflect.DeepEqual(ids, c.refs) {
			t.Errorf("%q: refs %v, want %v", c.q, ids, c.refs)
		}
		if r.Intent != "unusual_now" {
			t.Errorf("%q: intent %q", c.q, r.Intent)
		}
	}
}

func TestEstateLeavesOtherQuestionsAlone(t *testing.T) {
	// The one-metric yes/no question stays the baseline filter.
	r := run(t, "is cpu on edge-1 unusual for this time of week", cx)
	if r.AST == nil || r.AST.Type != ast.MetricFilter {
		t.Fatalf("one-metric question = %+v", r.AST)
	}
	// "normal for this time" is the compare, not the estate list.
	r = run(t, "is cpu on edge-1 normal for this time of week", cx)
	if r.AST == nil || r.AST.Type != ast.CompareWindows {
		t.Fatalf("normal-for-this-time = %+v", r.AST)
	}
	for _, q := range []string{
		"is there anything unusual about edge-1 compared to the other edges", // a peer comparison: no time of day
		"what was abnormal yesterday for this time of week",                  // not "now"
		"which circuits are unusually busy for this time of day",             // no traffic metric is rolled up for circuits
	} {
		if r := run(t, q, cx); r.AST != nil && r.AST.Type == ast.SeasonalOutliers {
			t.Errorf("%q compiled to the estate answer: %+v", q, r.AST)
		}
	}
}
