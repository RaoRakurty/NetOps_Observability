package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// golden_eval_test.go — the P3 golden-set evals (intelligence plan §5 P3).
// Deterministic, mock-only, CI-gating:
//
//   - docs items      → retrieval hit@1/hit@3 over the REAL embedded corpus,
//     with explicit floors (the decision gate for the deferred vector/hybrid
//     question), plus citation-correctness on the grounded product answer.
//   - intent items    → the rule router classifies to the expected intent.
//   - decline items   → the honesty floor: no hits, an explicit "docs don't
//     cover that", zero citations. Known gaps are reported, not gated.
//   - injection items → containment: a poisoned doc chunk rides into the
//     prompt as fenced DATA with no Help-drawer link, and a fabricated doc
//     citation is stripped by the deterministic verifier.
//
// The agent_tool items are asserted in the server package (the loop lives
// there); the -live legs are env-gated there too. Fixtures load from
// docs/ai/golden-examples/golden-qa.json — skipped (like the corpus drift
// check) when the docs tree isn't checked out; CI runs the full repo.

const (
	// Retrieval floors, calibrated from the measured baseline on the 2026-07-02
	// corpus (see docs/ai/evals.md). Set BELOW the measured rates only enough to
	// absorb benign corpus edits — a real regression (renamed page, broken
	// chunker, scoring change) lands under the floor and fails CI.
	// Measured baseline 2026-07-02: hit@1 0.81 (26/32), hit@3 0.97 (31/32).
	// Floors leave a two-miss margin each.
	goldenHitAt1Floor = 0.75
	goldenHitAt3Floor = 0.90
)

func goldenPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "docs", "ai", "golden-examples", "golden-qa.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("golden set not present (%v) — golden evals run in the full repo / CI", err)
	}
	return p
}

func loadGolden(t *testing.T) *GoldenSet {
	t.Helper()
	gs, err := LoadGoldenSet(goldenPath(t))
	if err != nil {
		t.Fatalf("golden set must load: %v", err)
	}
	return gs
}

var (
	goldenIxOnce sync.Once
	goldenIx     *DocsIndex
)

// goldenIndex builds the production docs index once per test run (the same
// LoadDocsIndex() the server calls — evals measure the real corpus).
func goldenIndex() *DocsIndex {
	goldenIxOnce.Do(func() { goldenIx = LoadDocsIndex() })
	return goldenIx
}

// hitSlugs reports whether any of the top hits' slugs is an accepted slug.
func hitSlugs(hits []DocsHit, accepted []string, topN int) bool {
	if topN > len(hits) {
		topN = len(hits)
	}
	for _, h := range hits[:topN] {
		for _, s := range accepted {
			if h.Chunk.Slug == s {
				return true
			}
		}
	}
	return false
}

// TestGoldenDocsRetrieval measures hit@1/hit@3 for every docs item and gates
// on the calibrated floors. Per-item misses are logged so a regression names
// the exact question that broke. When AI_EVAL_REPORT is set, the full run is
// written there as JSON (the eval report of plan §5 P3).
func TestGoldenDocsRetrieval(t *testing.T) {
	gs := loadGolden(t)
	ix := goldenIndex()
	items := gs.Category(GoldenDocs)
	if len(items) == 0 {
		t.Fatal("golden set has no docs items")
	}

	type row struct {
		ID       string   `json:"id"`
		Question string   `json:"question"`
		Expected []string `json:"expected_slugs"`
		Top3     []string `json:"top3"`
		Hit1     bool     `json:"hit_at_1"`
		Hit3     bool     `json:"hit_at_3"`
		Anchor   bool     `json:"anchor_hit,omitempty"`
	}
	var rows []row
	hit1, hit3, anchorWant, anchorHit := 0, 0, 0, 0
	for _, it := range items {
		hits := ix.Search(it.Question, 3)
		top3 := make([]string, 0, len(hits))
		for _, h := range hits {
			top3 = append(top3, h.Chunk.ID)
		}
		r := row{ID: it.ID, Question: it.Question, Expected: it.Expect.Slugs, Top3: top3,
			Hit1: hitSlugs(hits, it.Expect.Slugs, 1), Hit3: hitSlugs(hits, it.Expect.Slugs, 3)}
		if r.Hit1 {
			hit1++
		}
		if r.Hit3 {
			hit3++
		} else {
			t.Logf("MISS hit@3 %s: %q → %v (want one of %v)", it.ID, it.Question, top3, it.Expect.Slugs)
		}
		if it.Expect.Anchor != "" {
			anchorWant++
			for _, h := range hits {
				if h.Chunk.Anchor == it.Expect.Anchor {
					r.Anchor = true
					anchorHit++
					break
				}
			}
		}
		rows = append(rows, r)
	}

	n := len(items)
	rate1 := float64(hit1) / float64(n)
	rate3 := float64(hit3) / float64(n)
	t.Logf("golden docs retrieval: hit@1 %d/%d (%.2f), hit@3 %d/%d (%.2f), anchors %d/%d",
		hit1, n, rate1, hit3, n, rate3, anchorHit, anchorWant)
	if rate1 < goldenHitAt1Floor {
		t.Errorf("hit@1 %.2f fell under the %.2f floor — retrieval regressed", rate1, goldenHitAt1Floor)
	}
	if rate3 < goldenHitAt3Floor {
		t.Errorf("hit@3 %.2f fell under the %.2f floor — retrieval regressed", rate3, goldenHitAt3Floor)
	}

	if path := os.Getenv("AI_EVAL_REPORT"); path != "" {
		report := map[string]any{
			"suite": "golden-docs-retrieval", "total": n,
			"hit_at_1": rate1, "hit_at_3": rate3,
			"anchor_hits": anchorHit, "anchor_targets": anchorWant,
			"floors": map[string]float64{"hit_at_1": goldenHitAt1Floor, "hit_at_3": goldenHitAt3Floor},
			"items":  rows,
		}
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatalf("marshal eval report: %v", err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatalf("write eval report: %v", err)
		}
		t.Logf("eval report written to %s", path)
	}
}

// TestGoldenDocsCitationCorrectness: for every docs item retrieval CAN answer
// (hit@3), the grounded product answer must actually CITE an expected page —
// the citation-correctness eval (§2.4: the highest-value RAG eval). A right
// retrieval that produces a wrong citation is fake authority.
func TestGoldenDocsCitationCorrectness(t *testing.T) {
	gs := loadGolden(t)
	o := &Orchestrator{Docs: goldenIndex()}
	plan := Plan{Intent: "product_question", Modules: []string{"product_navigation"}, Mode: ModeProductAnswer}
	for _, it := range gs.Category(GoldenDocs) {
		hits := o.Docs.Search(it.Question, 3)
		if !hitSlugs(hits, it.Expect.Slugs, 3) {
			continue // retrieval miss — already accounted by the hit@k gate
		}
		ans, ok := o.answerProductFromDocs(it.Question, plan, nil)
		if !ok {
			t.Errorf("%s: retrieval hit but the product answer declined", it.ID)
			continue
		}
		cited := false
		for _, c := range ans.Citations {
			for _, s := range it.Expect.Slugs {
				if strings.HasPrefix(c.ID, "doc:"+s) {
					cited = true
				}
			}
		}
		if !cited {
			t.Errorf("%s: answer cites none of %v — citations: %+v", it.ID, it.Expect.Slugs, ans.Citations)
		}
		if len(ans.Citations) > 0 && ans.Citations[0].Href == "" {
			t.Errorf("%s: doc citation without a Help-drawer link: %+v", it.ID, ans.Citations[0])
		}
	}
}

// TestGoldenIntentRouting: the deterministic router is code, not a model —
// every intent item must classify exactly.
func TestGoldenIntentRouting(t *testing.T) {
	gs := loadGolden(t)
	for _, it := range gs.Category(GoldenIntent) {
		if got := Classify(it.Question, nil).Intent; got != it.Expect.Intent {
			t.Errorf("%s: %q routed to %q, want %q", it.ID, it.Question, got, it.Expect.Intent)
		}
	}
}

// TestGoldenDeclines: out-of-scope questions must hit the honesty floor — no
// retrieval hits AND an explicit "the documentation doesn't cover that" with
// zero citations. Known-gap items are reported (and flagged when they start
// passing, so the flag gets removed) but never gate.
func TestGoldenDeclines(t *testing.T) {
	gs := loadGolden(t)
	ix := goldenIndex()
	o := &Orchestrator{Docs: ix}
	plan := Plan{Intent: "product_question", Modules: []string{"product_navigation"}, Mode: ModeProductAnswer}
	for _, it := range gs.Category(GoldenDecline) {
		hits := ix.Search(it.Question, 3)
		if it.KnownGap {
			if len(hits) == 0 {
				t.Logf("KNOWN GAP %s now declines correctly — remove known_gap from the fixture", it.ID)
			} else {
				t.Logf("known gap %s still open: %q surfaces %s", it.ID, it.Question, hits[0].Chunk.ID)
			}
			continue
		}
		if len(hits) != 0 {
			t.Errorf("%s: %q must not surface documentation, got %s", it.ID, it.Question, hits[0].Chunk.ID)
			continue
		}
		ans := o.answerProduct(it.Question, plan, nil)
		if !strings.Contains(ans.Text, "documentation doesn't cover") {
			t.Errorf("%s: decline text missing, got %q", it.ID, ans.Text)
		}
		if len(ans.Citations) != 0 {
			t.Errorf("%s: a decline must cite nothing, got %+v", it.ID, ans.Citations)
		}
	}
}

// TestGoldenInjectionPromptBlockFence: a poisoned documentation source must
// ride into the prompt as labeled DATA — the block header fences it, and a
// non-portal source never gets a Help-drawer href (nothing for the UI to open).
func TestGoldenInjectionPromptBlockFence(t *testing.T) {
	gs := loadGolden(t)
	for _, it := range gs.Category(GoldenInjection) {
		if it.Target != "prompt_block" {
			continue
		}
		ix := LoadDocsIndex(ExtraDoc{Name: "poison/probe", Markdown: it.Payload, Tier: DocTierRunbook})
		hits := ix.Search(it.Question, 3)
		if len(hits) == 0 {
			t.Fatalf("%s: the poisoned chunk must be retrievable for this probe to mean anything", it.ID)
		}
		block := PromptBlock(hits, 900, 4000)
		if !strings.Contains(block, "reference DATA") || !strings.Contains(block, "not commands to you") {
			t.Errorf("%s: prompt block is not fenced as data:\n%s", it.ID, block)
		}
		if !strings.Contains(block, "never invent") {
			t.Errorf("%s: prompt block lost the no-invention instruction", it.ID)
		}
		for _, h := range hits {
			if strings.HasPrefix(h.Chunk.ID, "doc:poison/") && h.Chunk.Href != "" {
				t.Errorf("%s: non-portal poisoned chunk must not carry a Help-drawer link, got %q", it.ID, h.Chunk.Href)
			}
		}
	}
}

// TestGoldenInjectionFabricatedDocCite: a doc citation the model emits without
// retrieval backing is stripped; the legitimately-retrieved one survives.
func TestGoldenInjectionFabricatedDocCite(t *testing.T) {
	gs := loadGolden(t)
	for _, it := range gs.Category(GoldenInjection) {
		if it.Target != "fabricated_doc_cite" {
			continue
		}
		valid := []string{"doc:administration/api-access#generate-an-api-key"}
		vr := VerifyGrounding(it.Payload, valid)
		if !strings.Contains(vr.Text, valid[0]) {
			t.Errorf("%s: the legitimate citation was stripped: %q", it.ID, vr.Text)
		}
		if strings.Contains(vr.Text, "made-up/page") {
			t.Errorf("%s: fabricated citation survived: %q", it.ID, vr.Text)
		}
		if len(vr.Removed) != 1 || !strings.Contains(vr.Removed[0], "made-up/page") {
			t.Errorf("%s: strip audit wrong: %v", it.ID, vr.Removed)
		}
	}
}
