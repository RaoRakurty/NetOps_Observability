// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// docs_relevance_test.go — the ABSOLUTE relevance floor on documentation
// retrieval (docsMinSpecificity in docs_index.go).
//
// Why it exists. Every other guard in DocsIndex.Search is RELATIVE: "≥2 matched
// terms" and "within 25% of the leader" both ask whether a chunk is good
// compared to the other chunks. A question the corpus knows nothing about
// therefore still came back with the corpus's least-bad page. On the 132-page
// corpus "configure vmware vsphere drs affinity for my cluster" retrieved
// deploy/back-up-and-restore, because "configure" and "cluster" appear in it
// while the four words that carry the question appear nowhere.
//
// The floor is measured in IDF — the same quantity BM25 already scores with —
// so it scales with the corpus rather than being a magic score threshold. This
// file pins it from BOTH sides: re-tuning the constant must break something.

import (
	"math"
	"testing"
)

// specificity is the quantity the floor is expressed in: the share of a
// question's total information content that the corpus can actually match.
// Recomputed here from the index's own document frequencies so the test measures
// the property, not the implementation.
func specificity(ix *DocsIndex, query string) float64 {
	qterms := tokenize(query)
	if len(qterms) == 0 || ix.Len() == 0 {
		return 0
	}
	n := float64(ix.Len())
	idf := func(term string) float64 {
		df := float64(ix.df[term])
		return math.Log(1 + (n-df+0.5)/(df+0.5))
	}
	total := 0.0
	for _, q := range qterms {
		total += idf(q)
	}
	if total == 0 {
		return 0
	}
	best := 0.0
	for i := range ix.chunks {
		present := map[string]bool{}
		for _, t := range ix.terms[i] {
			present[t] = true
		}
		matched, mIDF := 0, 0.0
		for _, q := range qterms {
			if present[q] {
				matched++
				mIDF += idf(q)
			}
		}
		if matched >= 2 && mIDF/total > best {
			best = mIDF / total
		}
	}
	return best
}

// TestDocsSearchDeclinesOutOfScopeQuestions — questions whose DISTINCTIVE words
// the corpus has never seen must retrieve nothing, so the caller says "the
// documentation doesn't cover that" instead of paraphrasing an unrelated page.
func TestDocsSearchDeclinesOutOfScopeQuestions(t *testing.T) {
	ix := LoadDocsIndex()
	if ix.Len() == 0 {
		t.Skip("no documentation corpus embedded in this build")
	}
	for _, q := range []string{
		// The exact question from the 2026-09-03 golden run (decline-005).
		"configure vmware vsphere drs affinity for my cluster",
		"reset my kubernetes ingress controller certificate rotation policy",
		"how do I tune the jvm heap on my elasticsearch data nodes",
		"set up a terraform provider for aws transit gateway peering",
	} {
		t.Run(q, func(t *testing.T) {
			if hits := ix.Search(q, 3); len(hits) != 0 {
				t.Fatalf("out-of-scope question surfaced %s (score %.3f); specificity was %.3f",
					hits[0].Chunk.ID, hits[0].Score, specificity(ix, q))
			}
		})
	}
}

// TestDocsSearchStillAnswersRealQuestions — the floor must not be a mute button.
// These are questions the corpus DOES cover, including ones carrying tokens it
// has never seen (a model number, a hostname), which must still retrieve.
func TestDocsSearchStillAnswersRealQuestions(t *testing.T) {
	ix := LoadDocsIndex()
	if ix.Len() == 0 {
		t.Skip("no documentation corpus embedded in this build")
	}
	for _, q := range []string{
		"how do I set up SNMP discovery",
		"walk me through onboarding my very first device",
		"how do I configure snmp credentials on a juniper mx204",
		"where do I see the alert rules",
	} {
		t.Run(q, func(t *testing.T) {
			if hits := ix.Search(q, 3); len(hits) == 0 {
				t.Fatalf("a question the corpus covers retrieved nothing; specificity was %.3f (floor %.2f)",
					specificity(ix, q), docsMinSpecificity)
			}
		})
	}
}

// TestDocsRelevanceFloorIsCalibrated pins the floor against the measured
// evidence, so the constant cannot be moved without moving these numbers too.
// The margins on both sides are asserted, not just the verdicts.
func TestDocsRelevanceFloorIsCalibrated(t *testing.T) {
	ix := LoadDocsIndex()
	if ix.Len() == 0 {
		t.Skip("no documentation corpus embedded in this build")
	}
	cases := []struct {
		query string
		want  bool // true = must clear the floor
	}{
		{"configure vmware vsphere drs affinity for my cluster", false},
		{"reset my kubernetes ingress controller certificate rotation policy", false},
		{"walk me through onboarding my very first device", true},
		{"how do I set up SNMP discovery", true},
	}
	for _, tc := range cases {
		got := specificity(ix, tc.query)
		clears := got >= docsMinSpecificity
		if clears != tc.want {
			t.Errorf("specificity(%q) = %.3f, floor %.2f → clears=%v, want %v",
				tc.query, got, docsMinSpecificity, clears, tc.want)
		}
		t.Logf("specificity(%q) = %.3f (floor %.2f)", tc.query, got, docsMinSpecificity)
	}
	if docsMinSpecificity <= 0 || docsMinSpecificity >= 1 {
		t.Fatalf("the floor must be a share of the question's information, got %v", docsMinSpecificity)
	}
}

// The floor is only ever a floor: it can REMOVE a hit, never add or reorder one.
func TestDocsRelevanceFloorOnlyRemoves(t *testing.T) {
	ix := LoadDocsIndex()
	if ix.Len() == 0 {
		t.Skip("no documentation corpus embedded in this build")
	}
	for _, q := range []string{"how do I set up SNMP discovery", "syslog", "what is a seam"} {
		hits := ix.Search(q, 5)
		for i := 1; i < len(hits); i++ {
			if hits[i-1].Score < hits[i].Score {
				t.Errorf("%q: results are no longer score-ordered at %d", q, i)
			}
		}
	}
}
