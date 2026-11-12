// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiscore

import (
	"strings"
	"testing"
)

func TestRoutingIsCountedByPathAndReason(t *testing.T) {
	m := NewMetrics(Price{})
	m.ObserveRouting("model", "deterministic_miss")
	m.ObserveRouting("model", "deterministic_miss")
	m.ObserveRouting("model_unavailable", "compound_uncovered")
	m.ObserveRouting("model", "made_up_reason") // dropped, never bucketed
	m.ObserveRouting("elsewhere", "covered")    // dropped
	if n := m.RoutingCount("model", "deterministic_miss"); n != 2 {
		t.Fatalf("model/deterministic_miss = %d, want 2", n)
	}
	if n := m.RoutingCount("model_unavailable", "compound_uncovered"); n != 1 {
		t.Fatalf("model_unavailable/compound_uncovered = %d, want 1", n)
	}
	if n := m.RoutingCount("model", "made_up_reason"); n != 0 {
		t.Fatal("an unknown reason must be dropped")
	}
	out := render(m)
	for _, want := range []string{
		"# TYPE netops_ai_routing_total counter",
		`netops_ai_routing_total{path="model",reason="deterministic_miss"} 2`,
		`netops_ai_routing_total{path="deterministic",reason="covered"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition is missing %q", want)
		}
	}
	var nilM *Metrics
	nilM.ObserveRouting("model", "covered") // nil-safe
}
