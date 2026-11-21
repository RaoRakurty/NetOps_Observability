// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package explain

// estate_test.go — the estate-wide seasonal question reads in its own words:
// what is ranked, the tier wording, the judged hour (never a chosen window),
// the direction asked for and the metric filter.

import (
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
)

func TestExplainSeasonalOutliers(t *testing.T) {
	cat := catalog.MustLoad()
	q := &ast.AST{V: 1, Type: ast.SeasonalOutliers, Target: "interface", Limit: 10,
		Predicate: &ast.Predicate{Op: "above_baseline"},
		Filters:   []ast.Filter{{Field: ast.FilterMetric, Op: "in", Values: []string{"if_in_bps", "if_out_bps"}}}}
	e := Explain(cat, q, nil)
	text := e.Summary
	for _, p := range e.Parts {
		text += "\n" + p.Facet + ": " + p.Text
	}
	for _, want := range []string{
		"Ranks the interfaces furthest from their usual level for the time right now",
		"for this time of week when at least 3 earlier weeks exist, for this time of day when at least 5 earlier days do",
		"series with less history are counted, not ranked",
		"lists the top 10",
		"Time window: the latest closed hour the hourly seasonal history holds.",
		"Keeps only series at least 3 robust deviations above their usual level.",
		"filters: Only these metrics:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("explanation lacks %q:\n%s", want, text)
		}
	}
	for _, p := range e.Parts {
		if p.Facet == FacetLimit {
			t.Errorf("the top-k is said in what, not again as a limit: %+v", p)
		}
	}
	both := Explain(cat, &ast.AST{V: 1, Type: ast.SeasonalOutliers, Limit: 10}, nil)
	joined := both.Summary
	for _, p := range both.Parts {
		joined += "\n" + p.Text
	}
	if !strings.Contains(joined, "Ranks the series furthest") || !strings.Contains(joined, "above or below their usual level") {
		t.Errorf("no-target explanation:\n%s", joined)
	}
	if strings.Contains(strings.ToLower(joined), "monday") || strings.Contains(strings.ToLower(joined), "tuesday") {
		t.Errorf("never a weekday:\n%s", joined)
	}
}
