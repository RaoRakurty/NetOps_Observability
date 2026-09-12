// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

// The curated concepts doc (ai/product_knowledge/correlix.md) is always embedded,
// so LoadProductKB() with no extra is the real shipped product knowledge.
func TestLoadProductKB(t *testing.T) {
	kb := LoadProductKB()
	if len(kb.All()) < 10 {
		t.Fatalf("expected the curated concept sections to load, got %d", len(kb.All()))
	}
	// Concept sections map to a UI route.
	var seamHasRoute bool
	for _, s := range kb.All() {
		if strings.Contains(strings.ToLower(s.Title), "seam") && s.Route != "" {
			seamHasRoute = true
		}
	}
	if !seamHasRoute {
		t.Error("the seam concept should map to a UI route")
	}
	// Extra docs are additive.
	withExtra := LoadProductKB("## An extra section\nsome extra body about widgets.")
	if len(withExtra.All()) <= len(kb.All()) {
		t.Error("extra markdown should add sections")
	}
}

func TestProductKBSearch(t *testing.T) {
	kb := LoadProductKB()
	cases := []struct{ q, wantTitleContains string }{
		{"what is a seam", "seam"},
		{"what does suspected mean", "verdict"},
		{"how does correlation work", "correlation"},
		{"what is correlix", "Correlix"},
		{"how do I set up SNMP discovery", "SNMP"},
		{"what does confirmed mean", "verdict"},
		{"how do I enable SSO", "SSO"},
	}
	for _, c := range cases {
		hits := kb.Search(c.q, 3)
		if len(hits) == 0 {
			t.Errorf("%q: no hits", c.q)
			continue
		}
		if !strings.Contains(strings.ToLower(hits[0].Section.Title), strings.ToLower(c.wantTitleContains)) {
			t.Errorf("%q: top = %q, want a title containing %q", c.q, hits[0].Section.Title, c.wantTitleContains)
		}
	}
	// Off-topic → no product section.
	if h := kb.Search("what is the weather today", 3); len(h) != 0 {
		t.Errorf("off-topic query should return no section, got %v", h[0].Section.Title)
	}
}

// End-to-end: a product question is answered from the curated KB, deterministically.
func TestAnswerProductViaOrchestrator(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{
		DS: ds, Tools: Tools(ds),
		LLM:       MockLLM{Err: context.DeadlineExceeded}, // prove no provider needed
		ProductKB: LoadProductKB(),
	}
	ans, err := o.Ask(context.Background(), Principal{Cross: true}, "what is a seam?", nil)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if ans.Mode != ModeProductAnswer || ans.Intent != "product_question" {
		t.Fatalf("mode=%s intent=%s, want product_answer/product_question", ans.Mode, ans.Intent)
	}
	if !strings.Contains(strings.ToLower(ans.Text), "seam") || !strings.Contains(strings.ToLower(ans.Text), "boundary") {
		t.Errorf("product answer should explain a seam: %q", ans.Text)
	}
	if !containsStr(ans.ModeBadges, "Product help") {
		t.Errorf("expected a Product help badge, got %v", ans.ModeBadges)
	}
	if len(ans.Citations) == 0 || ans.Citations[0].Href == "" {
		t.Errorf("product answer should carry a deep link, got %v", ans.Citations)
	}
}
