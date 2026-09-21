// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

// verdict_honesty_test.go — the narrative may not claim more than the engine
// proved (verify.go enforceVerdictHonesty + orchestrator.go
// problemClosingInstruction). The structured fields have always been honest;
// these tests pin the PROSE to the same standard.

func TestProblemClosingInstructionIsVerdictConditional(t *testing.T) {
	confirmed := problemClosingInstruction("confirmed")
	if !strings.Contains(confirmed, "the likely root cause and why") {
		t.Errorf("a confirmed verdict must still ask for the cause: %q", confirmed)
	}
	for _, v := range []string{"undetermined", "suspected", "candidate", ""} {
		got := problemClosingInstruction(v)
		if strings.Contains(got, "the likely root cause and why") {
			t.Errorf("verdict %q must NOT ask for a root cause: %q", v, got)
		}
		for _, want := range []string{"has NOT established a cause", "SYMPTOM", "what evidence is still missing", "possibly because of X (unconfirmed)"} {
			if !strings.Contains(got, want) {
				t.Errorf("verdict %q closing instruction is missing %q: %q", v, want, got)
			}
		}
	}
}

func TestOverclaimsVocabularyIsClosedAndHedgeAware(t *testing.T) {
	overclaiming := []string{
		"The root cause is a BGP session reset on core-1.",
		"The root cause was the uplink optic.",
		"Root cause identified: the access uplink.",
		"The outage was caused by a firewall policy change.",
		"The cause is congestion on the DIA circuit.",
		"This is confirmed as a provider fault.",
		"Correlix confirms a link fault on leaf-2.",
		"This is definitely an MTU blackhole.",
		"The mechanism is certainly a control-plane reset.",
		"A tunnel flap is the proven trigger.",
	}
	for _, s := range overclaiming {
		if !overclaims(s) {
			t.Errorf("must be flagged as an overclaim: %q", s)
		}
	}
	honest := []string{
		"The root cause has not been identified.",
		"Possibly because of an uplink fault (unconfirmed).",
		"The symptom may be caused by congestion, but no path evidence was collected.",
		"Nothing is confirmed yet — probe evidence is missing.",
		"edge-1 logged a BGP adjacency change [log:os:1].",
		"Two devices lost their uplink within the same minute.",
		"It is unclear whether the tunnel or the underlay degraded first.",
		"This could be caused by an MTU mismatch; a path MTU probe would show it.",
		"The engine cannot confirm a cause from one signal on one device.",
		// The RCA report's own hedged wording must survive untouched.
		"Root cause has not been identified — possibly because of a WAN routing session flap (unconfirmed best hypothesis).",
	}
	for _, s := range honest {
		if overclaims(s) {
			t.Errorf("honest sentence wrongly flagged: %q", s)
		}
	}
}

func TestSplitSentencesRoundTrips(t *testing.T) {
	in := "One. Two! Three?  Four without a stop"
	parts := splitSentences(in)
	if strings.Join(parts, "") != in {
		t.Errorf("splitSentences must be lossless: %q → %q", in, strings.Join(parts, ""))
	}
	if len(parts) != 4 {
		t.Errorf("expected 4 sentences, got %d: %q", len(parts), parts)
	}
}

func TestEnforceVerdictHonestyConfirmedPassesThrough(t *testing.T) {
	text := "The root cause is a BGP session reset on core-1 [log:os:1]. Next: check the peering link."
	got, badges, disc := enforceVerdictHonesty(text, "confirmed", "fallback", nil, nil)
	if got != text || len(badges) != 0 || len(disc) != 0 {
		t.Errorf("a confirmed verdict must pass through untouched: %q badges=%v disc=%v", got, badges, disc)
	}
}

func TestEnforceVerdictHonestyDropsTheOverclaimAndDiscloses(t *testing.T) {
	text := "edge-1 logged repeated BGP adjacency changes over 20 minutes and two probe paths degraded at the same time [log:os:1]. " +
		"The root cause is a BGP session reset on core-1. Next: verify the peering link."
	got, badges, disc := enforceVerdictHonesty(text, "undetermined", "fallback summary", nil, nil)
	if strings.Contains(got, "root cause is") {
		t.Errorf("the overclaiming sentence survived: %q", got)
	}
	if !strings.Contains(got, "BGP adjacency changes") || !strings.Contains(got, "Next: verify the peering link") {
		t.Errorf("the honest sentences must survive: %q", got)
	}
	if len(badges) != 1 || badges[0] != "Verified" {
		t.Errorf("the change must carry a badge, got %v", badges)
	}
	if len(disc) != 1 || !strings.Contains(disc[0], "1 sentence claiming an established cause was removed") ||
		!strings.Contains(disc[0], "Undetermined") {
		t.Errorf("the removal must be disclosed honestly, got %v", disc)
	}
}

func TestEnforceVerdictHonestyFallsBackWhenNothingHonestSurvives(t *testing.T) {
	text := "The root cause is a BGP session reset on core-1. This is confirmed."
	fallback := "Correlix detected a low-evidence incident on core-1. Correlix does not have enough evidence yet to determine a root cause."
	got, badges, disc := enforceVerdictHonesty(text, "undetermined", fallback, nil, nil)
	if got != fallback {
		t.Errorf("expected the evidence-only summary, got %q", got)
	}
	if len(badges) != 1 || len(disc) != 1 || !strings.Contains(disc[0], "replaced with the evidence-only summary") {
		t.Errorf("the replacement must be disclosed: badges=%v disc=%v", badges, disc)
	}
}

// overclaimLLM is the worst case the review describes: a model that answers an
// undetermined incident with a confident cause.
type overclaimLLM struct{}

func (overclaimLLM) Complete(_ context.Context, _ string, _ []LLMMessage) (string, string, error) {
	return "The root cause is a BGP session reset on core-1 [log:os:1]. " +
		"edge-1 logged repeated adjacency changes across a 20-minute window [log:os:1]. " +
		"Next: verify the peering link.", "mock", nil
}

// TestUndeterminedVerdictNeverYieldsANarrativeNamingACause drives the real
// explain path end to end: the card badge says Undetermined / Not established,
// so the headline may not say a cause was found.
func TestUndeterminedVerdictNeverYieldsANarrativeNamingACause(t *testing.T) {
	ds := newMockDS()
	ds.problems["t-a"]["pu"] = &Problem{
		ID: "pu", Title: "Link flap on core-1", Verdict: "undetermined", Confidence: 0,
		Devices: []string{"core-1"}, MissingEvidence: []string{"probe_loss"}, SignalCount: 1, NodeCount: 1,
	}
	ds.evidence["pu"] = []EvidenceItem{{CitationID: "log:os:1", Kind: "log", Text: "core-1 %LINK-3-UPDOWN Ethernet1", Href: "#/explore/logs"}}
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: overclaimLLM{}, Flags: func(string) bool { return false }}

	ans, err := o.Ask(context.Background(), tenantA(), "explain problem pu", map[string]string{"problem_id": "pu"})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	low := strings.ToLower(ans.Text)
	for _, forbidden := range []string{"root cause is", "is a bgp session reset"} {
		if strings.Contains(low, forbidden) {
			t.Errorf("an undetermined verdict named a cause: %q", ans.Text)
		}
	}
	if !strings.Contains(ans.Text, "adjacency changes") {
		t.Errorf("the honest, grounded sentence must survive: %q", ans.Text)
	}
	// The deterministic fields stay honest, and the change is disclosed.
	if ans.Problem == nil || ans.Problem.Verdict != "undetermined" {
		t.Fatalf("the engine verdict must be untouched: %+v", ans.Problem)
	}
	if ans.ConfidenceLabel != "Not established" {
		t.Errorf("confidence label = %q, want Not established", ans.ConfidenceLabel)
	}
	found := false
	for _, d := range ans.Disclaimers {
		if strings.Contains(d, "claiming an established cause was removed") {
			found = true
		}
	}
	if !found {
		t.Errorf("the removal must be disclosed to the operator, got %v", ans.Disclaimers)
	}
}

// TestConfirmedVerdictKeepsItsCauseNarrative is the other half: the guardrail
// must not blunt an answer the engine actually earned.
func TestConfirmedVerdictKeepsItsCauseNarrative(t *testing.T) {
	ds := newMockDS() // "pa" is confirmed at 82%
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: overclaimLLM{}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), tenantA(), "explain problem pa", map[string]string{"problem_id": "pa"})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if !strings.Contains(strings.ToLower(ans.Text), "root cause is") {
		t.Errorf("a confirmed verdict must keep its cause narrative: %q", ans.Text)
	}
}

// emptyReplyLLM is a provider that answers with nothing and no error — the
// failure mode the module-health path used to render as a blank headline.
type emptyReplyLLM struct{}

func (emptyReplyLLM) Complete(_ context.Context, _ string, _ []LLMMessage) (string, string, error) {
	return "   ", "mock", nil
}

func TestModuleHealthEmptyProviderReplyFallsBackToTheDeterministicSummary(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: emptyReplyLLM{}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), opsA(), "show me the top talkers", nil)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if strings.TrimSpace(ans.Text) == "" {
		t.Fatal("an empty provider reply must never yield an empty headline")
	}
	if ans.Module == nil || strings.TrimSpace(ans.Module.Headline) == "" {
		t.Fatalf("the module headline must be filled deterministically: %+v", ans.Module)
	}
	if !ans.EvidenceOnly {
		t.Error("an unusable provider reply must be disclosed as evidence-only")
	}
	if ans.ProviderNote == "" {
		t.Error("the reason must reach the operator as a footer note")
	}
}
