// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

import "testing"

// Live 2026-11-12: "how many devices are connected" was read as "how many
// devices are connector" and answered from the integrations module. A
// correctly spelt word is never rewritten into a vocabulary word that merely
// shares its stem; a true misspelling still is.
func TestARealWordIsNeverRewrittenIntoItsSibling(t *testing.T) {
	core := CoreVocab()
	for _, w := range nearDomainWords {
		if fix, ties := core.Correct(w); fix != "" || ties != nil {
			t.Errorf("Correct(%q) = %q %v: a real word must be left as typed", w, fix, ties)
		}
	}
	// Odd casing is the same word: Fold lower-cases before any reading.
	text, rds := ClassifierRepair("tell me which tenant are we in and how many devices are connected and how are they discovereD?")
	if text != "tell me which tenant are we in and how many devices are connected and how are they discovered?" || len(rds) != 0 {
		t.Fatalf("the owner's question must reach the router as typed (lower-cased): %q %+v", text, rds)
	}
	// True misspellings are still repaired.
	for in, want := range map[string]string{"isues": "issues", "incidnets": "incidents", "devcies": "devices", "intrefaces": "interfaces"} { //nolint:misspell // typos under test
		if fix, _ := core.Correct(in); fix != want {
			t.Errorf("Correct(%q) = %q, want %q", in, fix, want)
		}
	}
}

// nearDomainWords are ordinary, correctly spelt words an operator types that
// sit near a vocabulary word (the audit of 2026-11-12). Shared with the
// grammar's own vocabulary test (compile package) through NearDomainWords.
var nearDomainWords = NearDomainWords()

func TestSameWordFamily(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"connected", "connector", true},
		{"connection", "connector", true},
		{"discovered", "discovery", true},
		{"monitoring", "monitored", true},
		{"polling", "poll", true},
		{"configuration", "configure", true},
		{"statuss", "status", false}, // a doubled letter is a typo, not a form
		{"devic", "device", false},
		{"incidentes", "incidents", false}, //nolint:misspell // typo under test
		{"isues", "issues", false},
		{"show", "show", false},
		{"edge-1", "edge", false},
	} {
		if got := SameWordFamily(c.a, c.b); got != c.want {
			t.Errorf("SameWordFamily(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// "atm" is shorthand only at the end of a question: before a noun it is the
// network term (ATM interfaces) and stays as typed.
func TestATMIsShorthandOnlyAtTheEnd(t *testing.T) {
	if got := Normalize("show atm interfaces on edge-1").Norm; got != "show atm interfaces on edge-1" {
		t.Fatalf("a domain term must not be rewritten: %q", got)
	}
	if got := Normalize("what's down atm").Norm; got != "what down right now" {
		t.Fatalf("sentence-final atm is shorthand: %q", got)
	}
	if got, rds := ExpandAbbreviations("show atm interfaces"); got != "show atm interfaces" || len(rds) != 0 {
		t.Fatalf("router reading: %q %+v", got, rds)
	}
	if got, _ := ExpandAbbreviations("anything down atm?"); got != "anything down right now?" {
		t.Fatalf("router reading: %q", got)
	}
}
