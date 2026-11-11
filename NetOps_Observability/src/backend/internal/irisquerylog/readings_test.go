// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisquerylog

import (
	"strings"
	"testing"

	"netops/backend/internal/nlquery/lex"
)

// A rephrase reading (hybrid NLU plan B1) is a whole question and the model's
// one-line rewording of it: it is kept, bounded at the rephrase's own limit,
// while a word reading keeps its 64-rune bound and an unknown kind is dropped.
func TestReadingsKeepTheRephraseBounded(t *testing.T) {
	long := strings.Repeat("q", 500)
	got := boundedReadings([]Reading{
		{From: long, To: long, Kind: lex.KindRephrase},
		{From: long, To: "show", Kind: lex.KindTypo},
		{From: "x", To: "y", Kind: "made_up"},
	})
	if len(got) != 2 {
		t.Fatalf("readings = %+v", got)
	}
	if got[0].Kind != lex.KindRephrase || len([]rune(got[0].From)) != maxRephraseRunes || len([]rune(got[0].To)) != maxRephraseRunes {
		t.Errorf("rephrase = %d/%d runes, want %d", len([]rune(got[0].From)), len([]rune(got[0].To)), maxRephraseRunes)
	}
	if len([]rune(got[1].From)) != 64 {
		t.Errorf("typo reading From = %d runes, want 64", len([]rune(got[1].From)))
	}
}

func TestRephraseReadingNote(t *testing.T) {
	r := lex.Reading{From: "is cpu sluggish on edge-1", To: "average cpu on edge-1", Kind: lex.KindRephrase}
	if got := r.Note(); !strings.Contains(got, `"average cpu on edge-1"`) || !strings.Contains(got, "rephrased by the AI model") {
		t.Errorf("note = %q", got)
	}
}
