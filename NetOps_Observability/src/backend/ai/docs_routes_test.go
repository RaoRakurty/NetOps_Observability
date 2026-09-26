// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

// docs_routes_test.go — the in-app deep links a documentation answer offers
// (docs_routes.go), and the product-answer path end to end. Ported from the
// retired product_kb_test.go: the assertions that still apply (a seam concept
// maps to a UI route; concept and how-to questions are answered; off-topic is
// declined; a product answer carries a link) now run against the docs index,
// which is the only product-knowledge path.

// TestDocRouteMapsCuratedConcepts — every curated concept section the old
// ProductKB linked still gets its route, and the seam concept (the case the old
// test pinned) lands on the RCA board.
func TestDocRouteMapsCuratedConcepts(t *testing.T) {
	ix := LoadDocsIndex()
	want := map[string]string{
		"What is a seam": "#/investigate/rca",
		"What do the verdict tiers mean (confirmed, suspected, undetermined)": "#/investigate/rca",
		"What is RCA (root cause analysis) in Correlix":                       "#/investigate/rca",
		"How to set up SNMP discovery":                                        "#/infrastructure/discovery",
		"How to enable SSO (OIDC / SAML / LDAP / TACACS)":                     "#/platform/auth",
		"How to create a report":                                              "#/analytics/reports",
		"What is a tenant and an org":                                         "#/admin/identity",
	}
	found := map[string]bool{}
	for _, c := range ix.All() {
		if c.Tier != DocTierCurated {
			continue
		}
		if route, ok := want[c.SectionTitle]; ok {
			found[c.SectionTitle] = true
			if got := docRoute(c); got != route {
				t.Errorf("docRoute(%q) = %q, want %q", c.SectionTitle, got, route)
			}
		}
	}
	for title := range want {
		if !found[title] {
			t.Errorf("curated section %q is missing from the index — the concept doc changed; update this test", title)
		}
	}
}

// TestDocRouteNeverLinksPortalPages — the rule table is for the curated tiers
// only. A portal page whose title happens to contain a rule word must not get
// an in-app link: "Configuration drift" is a security page, not Administration
// settings.
func TestDocRouteNeverLinksPortalPages(t *testing.T) {
	portal := DocChunk{PageTitle: "Configuration drift", SectionTitle: "Configuration drift", Slug: "security/config-drift", Tier: DocTierPortal}
	if got := docRoute(portal); got != "" {
		t.Fatalf("portal chunk got an in-app route %q; rules apply to curated tiers only", got)
	}
	runbook := DocChunk{PageTitle: "Application Knowledge", SectionTitle: "Configuration surfaces", Tier: DocTierRunbook}
	if got := docRoute(runbook); got != "#/admin/settings" {
		t.Fatalf("runbook chunk %q → %q, want #/admin/settings", runbook.SectionTitle, got)
	}
	none := DocChunk{PageTitle: "Correlix", SectionTitle: "Build / run", Tier: DocTierCurated}
	if got := docRoute(none); got != "" {
		t.Fatalf("a section no rule names must get no route, got %q", got)
	}
}

// TestDocRouteRulesAreOrderedAndResolvable — the first matching rule wins (so
// "SNMP discovery" is the discovery page, not SNMP profiles), and every rule
// has at least one word the tokenizer keeps (a rule of only short words would
// match everything).
func TestDocRouteRulesAreOrderedAndResolvable(t *testing.T) {
	c := DocChunk{PageTitle: "Correlix", SectionTitle: "How to set up SNMP discovery", Tier: DocTierCurated}
	if got := docRoute(c); got != "#/infrastructure/discovery" {
		t.Fatalf("SNMP discovery → %q, want the discovery page", got)
	}
	for _, r := range docRouteRules {
		if len(docTerms(r.terms)) == 0 {
			t.Errorf("rule %q has no indexable word", r.terms)
		}
		if !strings.HasPrefix(r.route, "#/") {
			t.Errorf("rule %q route %q is not an in-app hash route", r.terms, r.route)
		}
	}
}

// TestDocsAnswerConceptAndHowToQuestions — the questions the old ProductKB
// answered are answered by the docs index, with a page about the concept in
// the top three.
func TestDocsAnswerConceptAndHowToQuestions(t *testing.T) {
	ix := LoadDocsIndex()
	cases := []struct{ q, want string }{
		{"what is a seam", "seam"},
		{"what does suspected mean", "verdict"},
		{"how does correlation work", "correlation"},
		{"what is correlix", "correlix"},
		{"how do I set up SNMP discovery", "snmp"},
		{"what does confirmed mean", "verdict"},
		{"how do I enable SSO", "sso"},
	}
	for _, c := range cases {
		hits := ix.Search(c.q, 3)
		if len(hits) == 0 {
			t.Errorf("%q: no hits", c.q)
			continue
		}
		ok := false
		for _, h := range hits {
			if strings.Contains(strings.ToLower(h.Chunk.Breadcrumb+" "+h.Chunk.Slug), c.want) {
				ok = true
			}
		}
		if !ok {
			var got []string
			for _, h := range hits {
				got = append(got, h.Chunk.Breadcrumb)
			}
			t.Errorf("%q: no top-3 hit is about %q, got %v", c.q, c.want, got)
		}
	}
	if h := ix.Search("what is the weather today", 3); len(h) != 0 {
		t.Errorf("off-topic query should return nothing, got %s", h[0].Chunk.ID)
	}
}

// TestAnswerProductViaOrchestrator — end to end: a product question is answered
// from the docs deterministically (no provider), cites a page the reader can
// open, and — when a curated concept section is among the hits — offers the
// Correlix page the concept lives on.
func TestAnswerProductViaOrchestrator(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{
		DS: ds, Tools: Tools(ds),
		LLM:  MockLLM{Err: context.DeadlineExceeded}, // prove no provider needed
		Docs: LoadDocsIndex(),
	}
	ans, err := o.Ask(context.Background(), Principal{Cross: true}, "what is a seam?", nil)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if ans.Mode != ModeProductAnswer || ans.Intent != "product_question" {
		t.Fatalf("mode=%s intent=%s, want product_answer/product_question", ans.Mode, ans.Intent)
	}
	if !strings.Contains(strings.ToLower(ans.Text), "seam") {
		t.Errorf("product answer should explain a seam: %q", ans.Text)
	}
	if !containsStr(ans.ModeBadges, "Product help") {
		t.Errorf("expected a Product help badge, got %v", ans.ModeBadges)
	}
	if len(ans.Citations) == 0 || ans.Citations[0].Href == "" {
		t.Fatalf("product answer should carry a link, got %v", ans.Citations)
	}
	nav := 0
	for i, c := range ans.Citations {
		if c.Kind != "navigation" {
			if nav > 0 {
				t.Errorf("doc citation at %d follows a navigation citation — doc links must come first: %v", i, ans.Citations)
			}
			continue
		}
		nav++
		if c.ID != "nav:"+c.Href || c.Href != "#/investigate/rca" {
			t.Errorf("seam answer navigation citation = %+v, want nav:#/investigate/rca", c)
		}
	}
	if nav != 1 {
		t.Errorf("want exactly one in-app link (deduplicated) for the seam concept, got %d: %v", nav, ans.Citations)
	}

	// No docs index wired → the capability clarification, never an invented answer.
	bare := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}}
	plan := Plan{Intent: "product_question", Modules: []string{"product_navigation"}, Mode: ModeProductAnswer}
	if a := bare.answerProduct("what is a seam?", plan, nil); a.Mode != ModeUnavailable || len(a.Citations) != 0 {
		t.Errorf("no docs index: want the capability clarification, got mode=%s cites=%v", a.Mode, a.Citations)
	}
}
