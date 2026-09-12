// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestLoadKB(t *testing.T) {
	kb := LoadKB()
	if len(kb.All()) < 10 {
		t.Fatalf("expected the curated playbook set to load, got %d", len(kb.All()))
	}
	for _, p := range kb.All() {
		if p.ID == "" || p.Title == "" {
			t.Errorf("playbook missing id/title: %+v", p)
		}
		if len(p.Keywords) == 0 {
			t.Errorf("%s has no keywords (retrieval would never match)", p.ID)
		}
		if len(p.NextActions) == 0 {
			t.Errorf("%s parsed no next actions", p.ID)
		}
	}
	// A known playbook is present and parsed.
	bgp, ok := kb.Get("bgp-adjacency-flap")
	if !ok {
		t.Fatal("bgp-adjacency-flap playbook should exist")
	}
	if bgp.Owner != "Network / Routing" {
		t.Errorf("bgp owner = %q", bgp.Owner)
	}
}

func TestKBSearch(t *testing.T) {
	kb := LoadKB()

	// On-topic queries return the right playbook first.
	cases := []struct{ query, wantTopID string }{
		{"why is my BGP peer flapping and withdrawing prefixes", "bgp-adjacency-flap"},
		{"OSPF neighbor stuck in exstart", "ospf-neighbor-down"},
		{"ISP circuit latency and packet loss on the DIA egress", "isp-dia-latency"},
		{"large transfers fail but small ones work, MTU?", "mtu-fragmentation"},
		{"stateful firewall dropping return traffic asymmetric", "asymmetric-routing"},
	}
	for _, c := range cases {
		hits := kb.Search(c.query, KBHints{}, 3)
		if len(hits) == 0 {
			t.Errorf("%q: no hits", c.query)
			continue
		}
		if hits[0].Playbook.ID != c.wantTopID {
			t.Errorf("%q: top = %q, want %q (hits: %v)", c.query, hits[0].Playbook.ID, c.wantTopID, ids(hits))
		}
	}

	// Off-topic query returns nothing rather than a bad match.
	if hits := kb.Search("what is the weather today", KBHints{}, 3); len(hits) != 0 {
		t.Errorf("off-topic query should return no playbook, got %v", ids(hits))
	}

	// Hints bias retrieval (owner-domain "provider" → ISP/DIA family).
	hits := kb.Search("latency", KBHints{FaultDomains: []string{"provider"}}, 1)
	if len(hits) == 0 || hits[0].Playbook.ID != "isp-dia-latency" {
		t.Errorf("provider-hinted latency query should surface isp-dia-latency, got %v", ids(hits))
	}
}

func TestKBSnippetBounded(t *testing.T) {
	kb := LoadKB()
	p, _ := kb.Get("packet-loss-triage")
	s := p.Snippet()
	if !strings.Contains(s, p.Title) {
		t.Error("snippet should carry the title")
	}
	if !strings.Contains(strings.ToLower(s), "next actions") {
		t.Error("snippet should include next actions")
	}
}

// The orchestrator answers a troubleshooting question from the KB deterministically
// (no LLM), framed as guidance, with the owner + next actions filled.
func TestAnswerKBViaOrchestrator(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{
		DS:    ds,
		Tools: Tools(ds),
		LLM:   MockLLM{Err: context.DeadlineExceeded}, // prove the path needs no provider
		KB:    LoadKB(),
	}
	p := Principal{Cross: true}
	ans, err := o.Ask(context.Background(), p, "how do I troubleshoot a BGP adjacency flap?", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if ans.Mode != ModeInvestigationPlan {
		t.Fatalf("mode = %q, want investigation_plan", ans.Mode)
	}
	if ans.RecommendedOwner == "" || len(ans.NextActions) == 0 {
		t.Errorf("expected owner + next actions, got owner=%q actions=%v", ans.RecommendedOwner, ans.NextActions)
	}
	if len(ans.Citations) == 0 || !strings.HasPrefix(ans.Citations[0].ID, "playbook:") {
		t.Errorf("expected a playbook citation, got %v", ans.Citations)
	}
	// Must be framed as guidance, not evidence.
	joined := strings.ToLower(ans.Text + " " + strings.Join(ans.Disclaimers, " "))
	if !strings.Contains(joined, "guidance") {
		t.Errorf("KB answer must be framed as guidance: %q / %v", ans.Text, ans.Disclaimers)
	}
}

func ids(hits []KBHit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.Playbook.ID
	}
	return out
}
