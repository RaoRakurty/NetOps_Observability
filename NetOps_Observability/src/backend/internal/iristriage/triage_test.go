// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package iristriage

import (
	"strings"
	"testing"
)

func TestClassifyTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    Signals
		want string
		miss bool
	}{
		{"operator corrected a data metric", Signals{Corrections: []string{"wrong_metric"}, DataAnswered: true, DataRows: 3, DataOutcome: "answered"}, WrongTool, true},
		{"operator said not what I meant", Signals{Corrections: []string{"other"}}, WrongRoute, true},
		{"correction beats a dead end", Signals{Corrections: []string{"other"}, DeadEndKind: EndNoDocs}, WrongRoute, true},
		{"model did not route it", Signals{ModelFirst: true, PlannerUnavailable: true}, ProviderError, true},
		{"module with no tools", Signals{DeadEndKind: EndNotBuilt}, NoTool, true},
		{"docs miss", Signals{DeadEndKind: EndNoDocs}, NoData, true},
		{"playbook miss", Signals{DeadEndKind: EndNoPlaybook}, NoData, true},
		{"feature miss", Signals{DeadEndKind: EndNoFeature}, NoData, true},
		{"source did not respond", Signals{DeadEndKind: EndUnavailableIO}, NoData, true},
		{"didn't catch that", Signals{DeadEndKind: EndCapability}, Wording, true},
		{"grammar unparsed", Signals{DataOutcome: "unparsed"}, Wording, true},
		{"entity not found", Signals{DataOutcome: "not_found"}, NoData, true},
		{"empty result", Signals{DataAnswered: true, DataOutcome: "answered", DataRows: 0}, NoData, true},
		{"a denial is the answer", Signals{DeadEndKind: EndDenied}, "", false},
		{"answered with rows", Signals{DataAnswered: true, DataOutcome: "answered", DataRows: 4}, "", false},
		{"plain answer", Signals{ModelFirst: true}, "", false},
	} {
		got, miss := Classify(tc.s)
		if got != tc.want || miss != tc.miss {
			t.Errorf("%s: got (%q,%v) want (%q,%v)", tc.name, got, miss, tc.want, tc.miss)
		}
		if miss && !Valid(got) {
			t.Errorf("%s: class %q not in the closed set", tc.name, got)
		}
	}
}

func TestSummarizeOrdersAndBounds(t *testing.T) {
	var items []Item
	for i := 0; i < 9; i++ {
		items = append(items, Item{Class: NoData, Question: "where is page " + strings.Repeat("x", 300), Tenant: "acme"})
	}
	items = append(items, Item{Class: Wording, Question: "gimme stuff", Tenant: "globex"}, Item{Class: "bogus", Question: "x"})
	s := Summarize(items, false)
	if len(s) != 2 || s[0].Class != NoData || s[0].Count != 9 || s[1].Class != Wording {
		t.Fatalf("summary %+v", s)
	}
	if len(s[0].Examples) != MaxExamples {
		t.Fatalf("examples %d", len(s[0].Examples))
	}
	if s[0].Examples[0].Tenant != "" {
		t.Fatal("a tenant view must not carry tenant ids")
	}
	if len([]rune(s[0].Examples[0].Question)) > MaxExampleRunes+1 {
		t.Fatal("examples are clipped")
	}
	if p := Summarize(items, true); p[0].Examples[0].Tenant != "acme" {
		t.Fatal("a platform view keeps the tenant on examples")
	}
}

func TestCandidatesDedupeAndCarryTheReviewNotice(t *testing.T) {
	f := Candidates([]Candidate{
		{Question: "Show  me BGP peers", Source: "miss", Class: Wording},
		{Question: "show me bgp peers", Source: "miss", Class: Wording},
		{Question: "show me bgp peers", Source: "correction", Kind: "wrong_metric"},
		{Question: "", Source: "miss"},
	}, 10)
	if f.Review != ReviewNotice || len(f.Candidates) != 2 {
		t.Fatalf("%+v", f)
	}
	if g := Candidates(f.Candidates, 1); len(g.Candidates) != 1 {
		t.Fatal("bounded")
	}
}
