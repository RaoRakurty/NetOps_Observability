// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestVerifyGrounding(t *testing.T) {
	valid := []string{"log:os:1", "problem:abc"}

	// Fabricated citation (kind:detail shape, not in the set) is stripped;
	// genuine ones are kept.
	got := VerifyGrounding("BGP loss [log:os:1] and also [finding:fake:9].", valid)
	if strings.Contains(got.Text, "finding:fake:9") {
		t.Errorf("fabricated citation not stripped: %q", got.Text)
	}
	if !strings.Contains(got.Text, "log:os:1") {
		t.Errorf("genuine citation was removed: %q", got.Text)
	}
	if len(got.Removed) != 1 || got.Removed[0] != "finding:fake:9" {
		t.Errorf("expected 1 removed (finding:fake:9), got %v", got.Removed)
	}

	// Non-citation brackets (no colon) and plain numeric refs are left alone.
	keep := VerifyGrounding("see item [1] and note [important].", nil)
	if keep.Text != "see item [1] and note [important]." || len(keep.Removed) != 0 {
		t.Errorf("non-citation brackets must be untouched, got %q removed=%v", keep.Text, keep.Removed)
	}

	// Case-insensitive match on ids.
	ci := VerifyGrounding("ref [LOG:OS:1] ok", []string{"log:os:1"})
	if len(ci.Removed) != 0 {
		t.Errorf("case-insensitive id should be kept, removed=%v", ci.Removed)
	}

	// Empty text is a no-op.
	if e := VerifyGrounding("", valid); e.Text != "" || len(e.Removed) != 0 {
		t.Errorf("empty text should be a no-op, got %+v", e)
	}

	// Whitespace/punctuation is tidied after a removal.
	tidy := VerifyGrounding("packet loss [finding:x:1] . Next: check.", nil)
	if strings.Contains(tidy.Text, " .") || strings.Contains(tidy.Text, "  ") {
		t.Errorf("artifacts not tidied: %q", tidy.Text)
	}
}

// End-to-end: a model that invents a citation has it stripped from the RCA
// answer, and the answer is badged "Verified".
func TestOrchestratorStripsFabricatedCitation(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{
		DS:    ds,
		Tools: Tools(ds),
		LLM:   MockLLM{Reply: "Confirmed BGP session loss [log:os:1]; corroborated by [finding:fabricated:99]."},
	}
	ans, err := o.Ask(context.Background(), opsA(), "explain this problem", map[string]string{"problem_id": "pa"})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if ans.Mode != ModeProblemExplanation {
		t.Fatalf("mode = %s", ans.Mode)
	}
	if strings.Contains(ans.Text, "fabricated:99") {
		t.Errorf("fabricated citation survived into the answer: %q", ans.Text)
	}
	if !strings.Contains(ans.Text, "log:os:1") {
		t.Errorf("genuine citation should remain: %q", ans.Text)
	}
	if !containsStr(ans.ModeBadges, "Verified") {
		t.Errorf("expected a Verified badge after stripping, got %v", ans.ModeBadges)
	}
}
