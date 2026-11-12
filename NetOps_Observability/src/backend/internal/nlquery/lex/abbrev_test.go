// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

import (
	"reflect"
	"testing"
)

// Chat-speak and NOC shorthand read as the words they stand for, by the
// grammar (Normalize) and the router (ClassifierRepair) alike; the ones that
// carry meaning are disclosed, the framing ones are not.
func TestShorthandIsExpandedAndDisclosed(t *testing.T) {
	for q, want := range map[string]string{
		"which links are down rn":      "which links are down right now",
		"whch devices r down":          "whch devices are down",
		"whats up w/ bgp on cedge-82":  "whats up with bgp on cedge-82",
		"bgp nbrs on edge-1 pls":       "bgp neighbors on edge-1 please",
		"ifaces with errors atm":       "interfaces with errors right now",
		"what changed yday thx":        "what changed yesterday",
		"aren't established":           "are not established",
		"show cpu on r1 for u":         "show cpu on r1 for you",
		"show cfg changes on edge-u":   "show config changes on edge-u",
		"is edge-1 up isnt it":         "is edge-1 up is not it",
		"rn":                           "right now",
		"u-turn r2 rn2":                "u-turn r2 rn2", // names, not shorthand
		"show me the noisiest device!": "show me the noisiest device",
	} {
		if got := Normalize(q).Norm; got != want {
			t.Errorf("Normalize(%q) = %q, want %q", q, got, want)
		}
	}
	nt := Normalize("bgp nbrs down rn pls")
	want := []Reading{{From: "nbrs", To: "neighbors", Kind: KindAbbreviation}, {From: "rn", To: "right now", Kind: KindAbbreviation}}
	if !reflect.DeepEqual(nt.Readings, want) {
		t.Fatalf("readings = %+v, want %+v (pls is framing: not disclosed)", nt.Readings, want)
	}
	if r := (Reading{From: "rn", To: "right now", Kind: KindAbbreviation}).Note(); r != `I read "rn" as "right now".` {
		t.Fatalf("note = %q", r)
	}
}

func TestClassifierReadsShorthandToo(t *testing.T) {
	got, rds := ClassifierRepair("anything broken rn?")
	if got != "anything broken right now?" {
		t.Fatalf("router reading = %q (sentence punctuation must survive)", got)
	}
	if len(rds) != 1 || rds[0].From != "rn" || rds[0].Kind != KindAbbreviation {
		t.Fatalf("readings = %+v", rds)
	}
	if got, _ := ClassifierRepair("thx, any isues?"); got != "any issues?" {
		// "thx" reads as nothing; the typo after it is still repaired.
		t.Fatalf("router reading = %q", got)
	}
	if got, _ := ExpandAbbreviations("all good thx."); got != "all good." {
		t.Fatalf("an empty expansion keeps the sentence end: %q", got)
	}
}

func TestWindowReadingNote(t *testing.T) {
	if n := (Reading{From: "lately", To: "last 24 hours", Kind: KindWindow}).Note(); n != `I read "lately" as the last 24 hours.` {
		t.Fatalf("note = %q", n)
	}
}
