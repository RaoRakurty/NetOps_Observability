// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

import (
	"reflect"
	"testing"
)

var testVocab = NewVocab([]string{"show", "issues", "incidents", "latency", "interfaces", "memory", "compare", "devices", "deploy", "change", "chance"})

func TestCorrectRepairsUnambiguousTypos(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"shwo", "show"}, {"isues", "issues"}, {"incidentes", "incidents"}, {"latnecy", "latency"}, //nolint:misspell // typos under test
		{"interfacse", "interfaces"}, {"memroy", "memory"}, {"incidnets", "incidents"},
	} {
		if fix, ties := testVocab.Correct(c.in); fix != c.want || ties != nil {
			t.Errorf("Correct(%q) = %q %v, want %q", c.in, fix, ties, c.want)
		}
	}
}

// The guard table: what is never corrected.
func TestCorrectGuards(t *testing.T) {
	for _, c := range []struct{ in, why string }{
		{"sho", "3 letters or fewer are never fuzzed"},
		{"isu", "3 letters"},
		{"show", "already a word"},
		{"devices", "already a word"},
		{"device", "a singular of a vocabulary plural is a word"},
		{"compared", "an inflection is a word, not a typo"},
		{"deploying", "an inflection is a word"},
		{"changes", "a plural of a vocabulary word"},
		{"edge-1", "a separator: a name"},
		{"sho1", "a digit: a name or an id"},
		{"late.ncy", "a separator: an identifier"},
		{"10.0.0.1", "an address"},
		{"2024", "a number"},
		{"slow", "a plain English word is not a typo of show"},
		{"business", "a plain English word"},
		{"xhow", "a different first letter counts double"},
		{"shoowww", "too far (3 edits)"},
		{"memorry", "letters 4–7 allow one edit … this is one"},
	} {
		fix, ties := testVocab.Correct(c.in)
		if c.in == "memorry" {
			if fix != "memory" {
				t.Errorf("memorry must be repaired, got %q", fix)
			}
			continue
		}
		if fix != "" || ties != nil {
			t.Errorf("Correct(%q) = %q %v: %s", c.in, fix, ties, c.why)
		}
	}
	// Eight letters or more allow two edits; seven allow one.
	if fix, _ := testVocab.Correct("intrefaces"); fix != "interfaces" {
		t.Errorf("two edits on 10 letters: %q", fix)
	}
	if fix, _ := testVocab.Correct("lantecy"); fix != "" {
		t.Errorf("two edits on 7 letters must not repair: %q", fix)
	}
}

// Equally close candidates are offered, never applied.
func TestCorrectTieIsOffered(t *testing.T) {
	fix, ties := testVocab.Correct("chanbe") // change and chance are both one edit away
	if fix != "" || !reflect.DeepEqual(ties, []string{"chance", "change"}) {
		t.Fatalf("tie = %q %v", fix, ties)
	}
}

func TestRepairTextKeepsPunctuationAndDiscloses(t *testing.T) {
	r := testVocab.RepairText("shwo me the isues? now", nil)
	if r.Text != "show me the issues? now" {
		t.Errorf("text = %q", r.Text)
	}
	want := []Reading{{From: "shwo", To: "show", Kind: KindTypo}, {From: "isues", To: "issues", Kind: KindTypo}}
	if !reflect.DeepEqual(r.Readings, want) {
		t.Errorf("readings = %+v", r.Readings)
	}
	if got := r.Readings[0].Note(); got != `I read "shwo" as "show".` {
		t.Errorf("note = %q", got)
	}
	kept := testVocab.RepairText("shwo isues", func(i int, w string) bool { return w == "shwo" })
	if kept.Text != "shwo issues" || len(kept.Readings) != 1 {
		t.Errorf("keep must leave the word as typed: %+v", kept)
	}
	tie := testVocab.RepairText("any chanbe", nil)
	if tie.Text != "any chanbe" || len(tie.Ties["chanbe"]) != 2 {
		t.Errorf("a tie is offered, not applied: %+v", tie)
	}
}

// The router and the grammar share the core vocabulary: the lab's "list top
// isues today" reaches the router as "issues".
func TestClassifierRepair(t *testing.T) {
	text, rs := ClassifierRepair("List top ISUES today?")
	if text != "list top issues today?" || len(rs) != 1 || rs[0].From != "isues" {
		t.Fatalf("ClassifierRepair = %q %+v", text, rs)
	}
	if text, rs := ClassifierRepair("why is dallas slow"); text != "why is dallas slow" || len(rs) != 0 {
		t.Fatalf("a plain word is never repaired: %q %+v", text, rs)
	}
}

func TestMaxTypoDistance(t *testing.T) {
	for n, want := range map[int]int{1: 0, 3: 0, 4: 1, 7: 1, 8: 2, 20: 2} {
		if got := MaxTypoDistance(n); got != want {
			t.Errorf("MaxTypoDistance(%d) = %d, want %d", n, got, want)
		}
	}
}
