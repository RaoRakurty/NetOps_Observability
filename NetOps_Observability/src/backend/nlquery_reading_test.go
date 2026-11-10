// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_reading_test.go — the own-layer understanding (tracker 337 hybrid NLU
// plan A2/A5) end to end through /api/ai/query/compile: a misspelt vocabulary
// word is repaired AND disclosed; a misspelt NAME is only offered, from the
// caller's own scope (§3a: another tenant's near-identical name is never a
// candidate, with or without ?as_tenant=).

import (
	"strings"
	"testing"
)

func TestReadingsAreDisclosed(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, _ := nlqAPIFixture(t)
	code, out := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"shwo cpu on edge-a for the last hour"}`)
	if code != 200 || out["ast"] == nil {
		t.Fatalf("a misspelt vocabulary word must still compile: %d %v", code, out)
	}
	rs := nlqJSON(out["readings"])
	if !strings.Contains(rs, `"from":"shwo"`) || !strings.Contains(rs, `"to":"show"`) || !strings.Contains(rs, `"kind":"typo"`) {
		t.Fatalf("the repair must be disclosed: %v", out["readings"])
	}
	_, plain := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	if plain["readings"] != nil {
		t.Fatalf("nothing repaired, nothing disclosed: %v", plain["readings"])
	}
}

func TestFuzzyNameNeverCrossesTenantsAPI(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, b := nlqAPIFixture(t)
	q := `{"question":"show cpu on edgge-a for the last hour"}`
	code, out := nlqAPI(t, s, a, "/api/ai/query/compile", q)
	if code != 200 || out["ast"] != nil || out["unparsed"] != true {
		t.Fatalf("a fuzzy name is never applied: %d %v", code, out)
	}
	if dym := nlqJSON(out["did_you_mean"]); !strings.Contains(dym, "device:dev-a") || !strings.Contains(dym, `"needs_confirmation":true`) {
		t.Fatalf("tenant A must be offered its own edge-a, confirm-only: %v", out["did_you_mean"])
	}
	// The chip: labelled with A's own name for it, asking the question with the
	// candidate's id written in.
	if asks := nlqJSON(out["did_you_mean_asks"]); !strings.Contains(asks, `"label":"edge-a"`) || !strings.Contains(asks, "show cpu on device:dev-a for the last hour") {
		t.Fatalf("did-you-mean chip: %v", out["did_you_mean_asks"])
	}
	// Picking the chip asks a question that compiles — in the caller's scope.
	_, picked := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on device:dev-a for the last hour"}`)
	if !strings.Contains(nlqJSON(picked["ast"]), "device:dev-a") {
		t.Fatalf("the chip's question must compile to the candidate: %v", picked)
	}
	_, stolen := nlqAPI(t, s, b, "/api/ai/query/compile", `{"question":"show cpu on device:dev-a for the last hour"}`)
	if stolen["ast"] != nil && strings.Contains(nlqJSON(stolen["ast"]), "dev-a") {
		t.Fatalf("a chip question replayed by another tenant must not resolve: %v", stolen)
	}
	b.ActingTenant = a.Tenant
	for _, path := range []string{"/api/ai/query/compile", "/api/ai/query/compile?as_tenant=" + a.Tenant} {
		code, out := nlqAPI(t, s, b, path, q)
		if code != 200 || out["ast"] != nil {
			t.Fatalf("%s: %d %v", path, code, out)
		}
		if strings.Contains(nlqJSON(out), "dev-a") || strings.Contains(nlqJSON(out), "edge-a\"") {
			t.Fatalf("%s: tenant B was offered tenant A's device: %v", path, out)
		}
	}
}
