// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// quality_fold_test.go — FormatMissingEvidence must measure its offset on the
// line it is going to slice.
//
// It found "needs " in a strings.ToLower COPY and then sliced the ORIGINAL.
// strings.ToLower is not length preserving, so one U+023A, U+023E or invalid
// UTF-8 byte earlier in the line moved the offset: far enough and the slice
// runs past the end of the string and panics, short of that it returns a key
// cut in the wrong place and the operator reads the wrong missing-evidence
// bullet. The lines come from the engine, which builds them from device and
// telemetry text.

import (
	"strings"
	"testing"
)

var qualityFoldGrowers = []struct{ name, pad string }{
	{"U+023A", "Ⱥ"},
	{"U+023E", "Ⱦ"},
	{"invalid UTF-8", "\xff"},
}

func TestFormatMissingEvidenceSurvivesLowercaseGrowth(t *testing.T) {
	for _, g := range qualityFoldGrowers {
		t.Run(g.name, func(t *testing.T) {
			line := strings.Repeat(g.pad, 30) + " needs ospf_adjacency_change"
			got := FormatMissingEvidence([]string{line})
			if len(got) != 1 {
				t.Fatalf("want one bullet, got %v", got)
			}
			want := evidenceKeyToLabel("ospf_adjacency_change") + " was not found"
			if got[0] != want {
				t.Fatalf("the key was read from the wrong offset\n  got : %q\n  want: %q", got[0], want)
			}
		})
	}
}

func TestFormatMissingEvidenceNeverSlicesPastTheLine(t *testing.T) {
	for _, g := range qualityFoldGrowers {
		for n := 1; n <= 40; n++ {
			for _, tail := range []string{" needs ", " needs x", "needs", " NEEDS bgp_session_reset", ""} {
				_ = FormatMissingEvidence([]string{strings.Repeat(g.pad, n) + tail}) // must not panic
			}
		}
	}
}

// A line that ends exactly at "needs " carries no key after it. The old code
// appended a one-space sentinel and indexed [0] into strings.Fields of it,
// which panics: a space is not a field. No Unicode needed, just a truncated
// engine line.
func TestFormatMissingEvidenceHandlesALineThatEndsAtNeeds(t *testing.T) {
	got := FormatMissingEvidence([]string{"the correlation needs "})
	if len(got) != 1 || strings.TrimSpace(got[0]) == "" {
		t.Fatalf("want one non-empty bullet, got %v", got)
	}
}
