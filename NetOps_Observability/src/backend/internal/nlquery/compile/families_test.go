// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import (
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/lex"
)

func hasFilter(q *ast.AST, field, value string) bool {
	for _, f := range q.Filters {
		if f.Field == field && len(f.Values) == 1 && f.Values[0] == value {
			return true
		}
	}
	return false
}

func readingOf(r Result, kind string) *lex.Reading {
	for i := range r.Readings {
		if r.Readings[i].Kind == kind {
			return &r.Readings[i]
		}
	}
	return nil
}

// D1: a severity word reads as confirmed incidents, disclosed every time; an
// explicit tier wins over it.
func TestSeverityReadsAsConfirmedAndIsDisclosed(t *testing.T) {
	for _, q := range []string{"show me the critical incidents", "show me the critical incidentes", "any major outages", "show me only critical", "urgent issues today"} { //nolint:misspell // the lab's own typo, under test
		r := run(t, q, cx)
		if r.AST == nil || r.AST.Type != ast.IncidentList || !hasFilter(r.AST, "verdict_tier", "confirmed") {
			t.Errorf("%q → %+v", q, r)
			continue
		}
		if rd := readingOf(r, lex.KindSeverity); rd == nil || rd.To != SeverityMeaning {
			t.Errorf("%q: the severity reading must be disclosed: %+v", q, r.Readings)
		}
	}
	r := run(t, "critical suspected incidents", cx)
	if r.AST == nil || !hasFilter(r.AST, "verdict_tier", "suspected") || hasFilter(r.AST, "verdict_tier", "confirmed") || readingOf(r, lex.KindSeverity) != nil {
		t.Errorf("an explicit tier wins over a severity word: %+v", r)
	}
	if r := run(t, "show me the incidents", cx); r.AST == nil || len(r.AST.Filters) != 0 || len(r.Readings) != 0 {
		t.Errorf("no severity word, no filter, no reading: %+v", r)
	}
}

// "only critical" refines the incident list on screen (conversation §9).
func TestOnlyCriticalRefinesThePriorList(t *testing.T) {
	prior := &ast.AST{V: 1, Type: ast.IncidentList, Target: "incident", Filters: []ast.Filter{{Field: "state", Op: "eq", Values: []string{"open"}}}}
	x := cx
	x.PriorAST = prior
	r := run(t, "only critical", x)
	if r.AST == nil || r.Intent != "refine_filter" || !hasFilter(r.AST, "verdict_tier", "confirmed") || !hasFilter(r.AST, "state", "open") {
		t.Fatalf("only critical → %+v", r)
	}
	if readingOf(r, lex.KindSeverity) == nil {
		t.Fatal("the refinement must disclose the severity reading")
	}
}

// Inventory: counts and lists of the caller's visible devices, sites and
// circuits — never a role the inventory cannot filter by.
func TestInventoryQuestions(t *testing.T) {
	for _, c := range []struct {
		q       string
		typ     ast.QueryType
		target  string
		refs    int
		groupBy string
	}{
		{"how many devices are onboarded?", ast.EntityCount, "device", 0, ""},
		{"how many devices can you see ?", ast.EntityCount, "device", 0, ""},
		{"how many devices do we have in total", ast.EntityCount, "device", 0, ""},
		{"how many devices in dallas", ast.EntityCount, "device", 1, ""},
		{"how many devices per site", ast.EntityCount, "device", 0, "site"},
		{"number of sites", ast.EntityCount, "site", 0, ""},
		{"count the circuits", ast.EntityCount, "circuit", 0, ""},
		{"list the sites", ast.EntityList, "site", 0, ""},
		{"which devices do we have in dallas", ast.EntityList, "device", 1, ""},
	} {
		r := run(t, c.q, cx)
		if r.AST == nil || r.AST.Type != c.typ || r.AST.Target != c.target || len(r.AST.Refs) != c.refs {
			t.Errorf("%q → %+v", c.q, r)
			continue
		}
		if g := ""; len(r.AST.GroupBy) > 0 {
			g = r.AST.GroupBy[0]
			if g != c.groupBy {
				t.Errorf("%q group_by %q, want %q", c.q, g, c.groupBy)
			}
		} else if c.groupBy != "" {
			t.Errorf("%q: missing group_by %q", c.q, c.groupBy)
		}
		if r.AST.Time.Kind != "" {
			t.Errorf("%q: an inventory question has no window: %+v", c.q, r.AST.Time)
		}
	}
	for _, q := range []string{"how many routers", "how many firewalls in dallas", "how many devices and sites"} {
		if r := run(t, q, cx); r.AST != nil {
			t.Errorf("%q must not be answered as every device: %+v", q, r.AST)
		}
	}
}

// A superlative with no metric word ranks by the metric it names; with no
// number, the top 5 — disclosed.
func TestSuperlativesRank(t *testing.T) {
	r := run(t, "which interfaces are busiest", cx)
	if r.AST == nil || r.AST.Type != ast.MetricTopK || r.AST.Target != "interface" || r.AST.Metric != "if_util_max_pct" || r.AST.Limit != DefaultSuperlativeN {
		t.Fatalf("which interfaces are busiest → %+v", r)
	}
	if rd := readingOf(r, lex.KindImplicitN); rd == nil || rd.From != "busiest" {
		t.Fatalf("the implicit top 5 must be disclosed: %+v", r.Readings)
	}
	r = run(t, "which 5 interfaces are busiest", cx)
	if r.AST == nil || r.AST.Limit != 5 || readingOf(r, lex.KindImplicitN) != nil {
		t.Fatalf("an explicit number needs no reading: %+v", r)
	}
	if r := run(t, "busiest devices", cx); r.AST == nil || r.AST.Metric != "cpu_util_pct" || r.AST.Target != "device" {
		t.Fatalf("busiest devices → %+v", r.AST)
	}
}

// "What's wrong with X" lists X's incidents when X resolves.
func TestWhatsWrongWithAResolvedName(t *testing.T) {
	r := run(t, "what's wrong with edge-1", cx)
	if r.AST == nil || r.AST.Type != ast.IncidentList || len(r.AST.Refs) != 1 || r.AST.Refs[0].ID != "device:edge-1" {
		t.Fatalf("what's wrong with edge-1 → %+v", r)
	}
	if r := run(t, "what's wrong with the quantum flux", cx); r.AST != nil {
		t.Fatalf("an unresolved X is not understood: %+v", r.AST)
	}
}

// A bare name: found → that entity; not found in the caller's scope → said
// so (with candidates from the caller's own scope), never Unparsed.
func TestLookupFoundAndNotFound(t *testing.T) {
	r := run(t, "where is edge-1", cx)
	if r.AST == nil || r.AST.Type != ast.EntityList || r.AST.Target != "device" || len(r.AST.Refs) != 1 {
		t.Fatalf("where is edge-1 → %+v", r)
	}
	r = run(t, "I cannot find RETAIL", cx)
	if r.AST != nil || r.Unparsed || r.NotFound == nil || r.NotFound.Name != "RETAIL" {
		t.Fatalf("I cannot find RETAIL → %+v", r)
	}
	r = run(t, "find dalas", cx)
	if r.NotFound == nil || len(r.DidYouMean) != 1 || r.DidYouMean[0].Refs[0].EntityID != "site:dfw-hq" || !r.DidYouMean[0].Refs[0].NeedsConfirmation {
		t.Fatalf("find dalas → %+v", r)
	}
	if r := run(t, "show me cpu", cx); r.NotFound != nil {
		t.Fatalf("a grammar word is never a lookup: %+v", r)
	}
}
