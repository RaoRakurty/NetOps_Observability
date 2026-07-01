package ai

import (
	"context"
	"strings"
	"testing"
)

const sampleProductDoc = `# Correlix — Application Knowledge

## What the product is
Correlix is a network observability platform: discovery, telemetry ingestion,
correlation, RCA, and dashboards behind one pane.

## Discovery (device inventory)
Devices are found via SNMP scan (ENABLE_SNMP_DISCOVERY, SNMP_CIDR_RANGES) or
declared statically. Manage SNMP credentials in the SNMP Profile Manager.

## Setup runbooks (how-to)
To set up SNMP discovery: set ENABLE_SNMP_DISCOVERY=true and SNMP_CIDR_RANGES,
then add v2c/v3 credentials in the SNMP Profile Manager.

## RCA and verdicts
A correlation groups related signals into a problem. Its verdict is undetermined,
suspected, or confirmed — confirmed needs independent evidence across two signal
classes. A seam is a control-plane ownership boundary between network domains.
`

func TestLoadProductKB(t *testing.T) {
	kb := LoadProductKB(sampleProductDoc)
	if len(kb.All()) < 4 {
		t.Fatalf("expected the ## sections to parse, got %d", len(kb.All()))
	}
	// The discovery section carries a UI route.
	var hasRoute bool
	for _, s := range kb.All() {
		if strings.Contains(strings.ToLower(s.Title), "discovery") && s.Route != "" {
			hasRoute = true
		}
	}
	if !hasRoute {
		t.Error("discovery section should map to a UI route")
	}

	// Empty doc → empty KB, no panic.
	if len(LoadProductKB("").All()) != 0 {
		t.Error("empty doc should yield an empty KB")
	}
}

func TestProductKBSearch(t *testing.T) {
	kb := LoadProductKB(sampleProductDoc)
	cases := []struct{ q, wantTitleContains string }{
		{"what is a seam", "RCA and verdicts"},
		{"what does suspected mean", "RCA and verdicts"},
		{"how do I set up SNMP discovery", "Setup runbooks"},
	}
	for _, c := range cases {
		hits := kb.Search(c.q, 3)
		if len(hits) == 0 {
			t.Errorf("%q: no hits", c.q)
			continue
		}
		if !strings.Contains(hits[0].Section.Title, c.wantTitleContains) {
			t.Errorf("%q: top = %q, want a title containing %q", c.q, hits[0].Section.Title, c.wantTitleContains)
		}
	}
	// "what is correlix" is answerable (correlix appears in the intro) — any hit is
	// a reasonable answer, so just assert retrieval finds something.
	if len(kb.Search("what is correlix", 3)) == 0 {
		t.Error("'what is correlix' should retrieve a product section")
	}
	// Off-topic → no product section.
	if h := kb.Search("what is the weather today", 3); len(h) != 0 {
		t.Errorf("off-topic query should return no section, got %d", len(h))
	}
}

// End-to-end: a product question is answered from the KB, deterministically.
func TestAnswerProductViaOrchestrator(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{
		DS: ds, Tools: Tools(ds),
		LLM:       MockLLM{Err: context.DeadlineExceeded}, // prove no provider needed
		ProductKB: LoadProductKB(sampleProductDoc),
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
}
