// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package modelc

// estate_test.go — the model is offered the estate-wide seasonal query type
// (N-H6 step 3) with exactly the metrics the roll-up keeps, and a compiled
// estate answer is held to the metric the question named.

import (
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/seasonal"
)

func TestPromptOffersSeasonalOutliersWithTheRolledMetrics(t *testing.T) {
	p := SystemPrompt()
	if !strings.Contains(p, `"seasonal_outliers"`) {
		t.Fatal("the system prompt does not offer seasonal_outliers")
	}
	for _, m := range seasonal.EstateMetrics("") {
		if !strings.Contains(p, m) {
			t.Errorf("the system prompt does not list rolled-up metric %s", m)
		}
	}
	if intentFor(ast.SeasonalOutliers) != "unusual_now" {
		t.Errorf("intent %q", intentFor(ast.SeasonalOutliers))
	}
}

func TestEstateKindMustReadTheNamedMetric(t *testing.T) {
	named := namedKinds{metrics: map[string]bool{"cpu_util_pct": true}}
	for _, c := range []struct {
		q    ast.AST
		want bool
	}{
		{ast.AST{Type: ast.SeasonalOutliers, Metric: "cpu_util_pct"}, true},
		{ast.AST{Type: ast.SeasonalOutliers, Filters: []ast.Filter{{Field: ast.FilterMetric, Op: "in", Values: []string{"mem_util_pct", "cpu_util_pct"}}}}, true},
		{ast.AST{Type: ast.SeasonalOutliers, Metric: "mem_util_pct"}, false},
		{ast.AST{Type: ast.SeasonalOutliers}, false},
	} {
		q := c.q
		if got := consistentKind(named, &q); got != c.want {
			t.Errorf("%+v: consistent=%v, want %v", c.q, got, c.want)
		}
	}
}
