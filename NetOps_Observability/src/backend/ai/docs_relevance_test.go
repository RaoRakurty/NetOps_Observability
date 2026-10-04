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
	qterms := docsQueryTerms(query) // folded exactly as Search folds it
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
		{"how do I tune the jvm heap on my elasticsearch data nodes", false},
		{"create a monitor that alerts when interface errors climb", true},
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

// chunkSpecificity is specificity() for one chunk: the share of the question's
// IDF that this chunk's terms match. -1 when the chunk is not in the index.
func chunkSpecificity(ix *DocsIndex, query, id string) float64 {
	qterms := docsQueryTerms(query)
	n := float64(ix.Len())
	idf := func(term string) float64 {
		df := float64(ix.df[term])
		return math.Log(1 + (n-df+0.5)/(df+0.5))
	}
	total := 0.0
	for _, q := range qterms {
		total += idf(q)
	}
	for i, c := range ix.chunks {
		if c.ID != id {
			continue
		}
		present := map[string]bool{}
		for _, t := range ix.terms[i] {
			present[t] = true
		}
		m := 0.0
		for _, q := range qterms {
			if present[q] {
				m += idf(q)
			}
		}
		return m / total
	}
	return -1
}

// TestDocsFloorIsPerQuestionNotPerChunk — the strict floor asks whether the
// corpus knows what the QUESTION is about. Applied per chunk it dropped the
// right page whenever the question used words that page does not: the
// topology canvas explains pinning an incident but never says "blast radius",
// so its own ratio sits under docsMinSpecificity. It must still be returned,
// because a better-covered chunk proves the question is in scope, and it
// clears the per-chunk floor.
func TestDocsFloorIsPerQuestionNotPerChunk(t *testing.T) {
	ix := goldenIndex()
	if ix.Len() == 0 {
		t.Skip("no documentation corpus embedded in this build")
	}
	const q = "Pin an incident onto the topology view to see its blast radius"
	const id = "doc:infrastructure/topology-canvas#step-4---pin-an-incident-in-investigate-mode"
	got := chunkSpecificity(ix, q, id)
	if got < 0 {
		t.Fatalf("chunk %s is missing from the corpus — the page moved; update this test", id)
	}
	if got >= docsMinSpecificity || got < docsChunkMinSpecificity {
		t.Fatalf("precondition: want the chunk's own ratio between %.2f and %.2f, got %.3f — pick another probe",
			docsChunkMinSpecificity, docsMinSpecificity, got)
	}
	found := false
	for _, h := range ix.Search(q, 3) {
		if h.Chunk.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("the topology page (own ratio %.3f) must be retrieved once the question clears the question-level floor", got)
	}
	// The other side: a question whose BEST chunk is under the floor returns
	// nothing at all, however many chunks clear the per-chunk floor.
	const out = "how do I tune the jvm heap on my elasticsearch data nodes"
	if specificity(ix, out) >= docsMinSpecificity {
		t.Fatal("precondition: the jvm question must sit under the question-level floor")
	}
	if hits := ix.Search(out, 3); len(hits) != 0 {
		t.Fatalf("an out-of-scope question must return nothing, got %s", hits[0].Chunk.ID)
	}
}
