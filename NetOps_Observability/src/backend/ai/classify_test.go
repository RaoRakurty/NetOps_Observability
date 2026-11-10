// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

// TestClassifyBroadPhrasings is the regression guard for the "every question
// gives the same 25-incident briefing" bug: current_state is now an EXPLICIT
// intent, natural incident phrasings route to the actionable list, and truly
// unrecognized questions get a capability clarification — NOT the briefing.
func TestClassifyBroadPhrasings(t *testing.T) {
	for _, c := range broadPhrasings {
		got := Classify(c.q, nil).Intent
		if got != c.want {
			t.Errorf("Classify(%q) intent = %q, want %q", c.q, got, c.want)
		}
	}
}

// TestClassifyUsesSharedNormaliser: the router reads a question through the
// shared normaliser (internal/nlquery/lex), so case, smart quotes, accents and
// stray spacing never change the intent — every family above is re-asked in
// those shapes and must land where its plain form does.
func TestClassifyUsesSharedNormaliser(t *testing.T) {
	shapes := []func(string) string{
		strings.ToUpper,
		func(q string) string { return strings.ReplaceAll(q, "'", "’") },
		func(q string) string { return "  " + strings.ReplaceAll(q, " ", "   ") + "  " },
	}
	for _, c := range broadPhrasings {
		for i, shape := range shapes {
			if got := Classify(shape(c.q), nil).Intent; got != c.want {
				t.Errorf("shape %d of %q → %q, want %q", i, shape(c.q), got, c.want)
			}
		}
	}
	// A typographic apostrophe used to break every "what's …" rule.
	if got := Classify("what’s broken", nil).Intent; got != "incident_list" {
		t.Errorf("smart-quoted what's: %q", got)
	}
}

var broadPhrasings = []struct {
	q    string
	want string
}{
	// Explicit status / overview → current_state (the briefing is appropriate here).
	{"what is going on right now", "current_state"},
	{"what's happening", "current_state"},
	{"give me a status update", "current_state"},
	{"how is the network", "current_state"},
	{"is everything ok", "current_state"},
	{"network health", "current_state"},
	{"what should the NOC focus on", "current_state"},
	{"summarize the network health", "current_state"},

	// Incident/problem/outage phrasings → the filtered actionable LIST.
	{"show me the critical incidents", "incident_list"},
	{"are there any issues", "incident_list"},
	{"is there any problem", "incident_list"},
	{"any outages", "incident_list"},
	{"what is broken", "incident_list"},
	{"whats wrong", "incident_list"},
	{"anything down", "incident_list"},
	{"what needs attention", "incident_list"},
	{"do we have any incidents", "incident_list"},
	{"what's the biggest problem", "incident_list"},

	// RCA / explain.
	{"explain this incident", "problem_explanation"},

	// Modules.
	{"show me top talkers", "flow_analytics_summary"},
	{"any metric anomalies", "telemetry_summary"},
	{"are my integrations healthy", "integration_health_summary"},

	// Playbook / history / shift.
	{"how do I troubleshoot a bgp flap", "network_kb"},
	{"what happened overnight", "time_range_summary"},
	{"give me the shift handoff", "shift_handoff"},

	// Navigation.
	{"where do I configure servicenow", "product_navigation"},

	// Product / how-to questions ABOUT Correlix → product_question (answered
	// from the product knowledge; degrades to a capability clarification if the
	// KB has no match — the KB lookup is the disambiguator).
	{"what is a seam", "product_question"},
	{"how do I set up SNMP discovery", "product_question"},
	{"what does suspected mean", "product_question"},

	// Truly unrecognized → capability clarification, NOT current_state.
	{"who should I call about the wan", "capability"},
	{"tell me a joke", "capability"},
}

// A misspelt word the router repairs is disclosed on the answer (D2): the
// lab's "list top isues today" reaches the incident list and says how it read
// the question; a correctly spelt question carries no such line.
func TestRouterRepairsAreDisclosed(t *testing.T) {
	if got := Classify("list top isues today", nil).Intent; got != "incident_list" {
		t.Fatalf("list top isues today → %q, want incident_list", got)
	}
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "list top isues today", nil)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, d := range ans.Disclaimers {
		if d == `I read "isues" as "issues".` {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("the repair must be disclosed exactly once: %q", ans.Disclaimers)
	}
	plain, err := o.Ask(context.Background(), tenantA(), "list top issues today", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range plain.Disclaimers {
		if strings.HasPrefix(d, "I read ") {
			t.Fatalf("nothing repaired, nothing disclosed: %q", plain.Disclaimers)
		}
	}
}
