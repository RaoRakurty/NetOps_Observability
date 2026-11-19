// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// seasonal_test.go — N-H6 phrasings: a question about a value's usual level
// for the time of week/day compiles to compare_windows against the same window
// a week ago (whose rows carry the seasonal reference); "unusual … for this
// time of week" stays the above_baseline filter; neither leaves "for this time
// of week" unexplained.

import (
	"testing"

	"netops/backend/internal/nlquery/ast"
)

func TestSeasonalNormQuestionsCompareWithLastWeek(t *testing.T) {
	for _, q := range []string{
		"is cpu on edge-1 normal for this time of week",
		"is cpu on edge-1 normal for this time of day?",
		"cpu on edge-1 — is that usual for this time of week",
		"is the cpu on edge-1 typical for the time",
	} {
		r := run(t, q, cx)
		if r.AST == nil {
			t.Errorf("%q: not compiled (%+v)", q, r)
			continue
		}
		if r.AST.Type != ast.CompareWindows || r.AST.CompareTo == nil || r.AST.CompareTo.Offset != "7d" {
			t.Errorf("%q: %+v, want compare_windows against the same window 7d earlier", q, r.AST)
		}
		if len(r.AST.Refs) != 1 || r.AST.Refs[0].ID != "device:edge-1" {
			t.Errorf("%q: refs %+v", q, r.AST.Refs)
		}
	}
}

func TestUnusualForThisTimeStaysTheBaselineFilter(t *testing.T) {
	r := run(t, "is cpu on edge-1 unusual for this time of week", cx)
	if r.AST == nil || r.AST.Type != ast.MetricFilter || r.AST.Predicate == nil || r.AST.Predicate.Op != "above_baseline" {
		t.Fatalf("unusual-for-this-time = %+v (%+v)", r.AST, r)
	}
	if r.AST.CompareTo != nil {
		t.Fatalf("an above_baseline filter must not become a compare: %+v", r.AST)
	}
}
