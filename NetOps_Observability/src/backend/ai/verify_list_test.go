// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"strings"
	"testing"
)

// Live 2026-11-12: an answer reached the operator with a raw
// "[problem:<uuid>, problem:<uuid>, …]" list. A list was judged as ONE id —
// real ids were stripped as invented, and a list longer than the old 160-byte
// match escaped the check entirely. Each id of a list is now judged alone.
func TestVerifyGroundingJudgesEachIDOfAList(t *testing.T) {
	ids := []string{
		"problem:4fdcb775-6e0c-5827-8c23-31467149ebff",
		"problem:033eced1-0000-4000-8000-000000000001",
		"problem:033eced1-0000-4000-8000-000000000002",
		"problem:033eced1-0000-4000-8000-000000000003",
	}
	valid := ids[:3]
	text := "Three are confirmed [" + strings.Join(ids, ", ") + "]."
	if len(text) < 180 {
		t.Fatal("fixture: the list must be longer than the old 160-byte bound")
	}
	r := VerifyGrounding(text, valid)
	if strings.Contains(r.Text, ids[3]) {
		t.Fatalf("an invented id inside a long list must be stripped: %q", r.Text)
	}
	for _, id := range valid {
		if !strings.Contains(r.Text, id) {
			t.Fatalf("a real id inside a list must be kept: %q", r.Text)
		}
	}
	if len(r.Removed) != 1 || r.Removed[0] != ids[3] {
		t.Fatalf("removed = %v", r.Removed)
	}
	// A list of nothing but invented ids goes, with its brackets.
	r = VerifyGrounding("Bad [problem:x, problem:y].", valid)
	if r.Text != "Bad." || len(r.Removed) != 2 {
		t.Fatalf("all-invented list: %q %v", r.Text, r.Removed)
	}
	// Non-citation brackets are untouched; a single real id is unchanged.
	for _, keep := range []string{"see [1] and [note]", "ok [" + valid[0] + "]"} {
		if r := VerifyGrounding(keep, valid); r.Text != keep {
			t.Fatalf("%q changed to %q", keep, r.Text)
		}
	}
}

// The statement classes see every id of a list as cited.
func TestCitedKnownReadsAList(t *testing.T) {
	sc := &statementContext{perIncident: true}
	sc.stampIncident("problem:a1", "a1", "confirmed", "one")
	sc.stampIncident("problem:b2", "b2", "suspected", "two")
	got := sc.citedKnown("Both [problem:a1; problem:b2].")
	if len(got) != 2 {
		t.Fatalf("citedKnown = %v", got)
	}
}
