// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestStatusAndConfidenceLabels(t *testing.T) {
	if StatusLabel("undetermined") != "Undetermined" || StatusLabel("CONFIRMED") != "Confirmed" {
		t.Fatal("status labels")
	}
	// 0% / undetermined must read as "Not established", never a bare 0% (spec §10/19).
	if ConfidenceLabel(0, "undetermined") != "Not established" {
		t.Fatalf("0%% undetermined must be 'Not established', got %q", ConfidenceLabel(0, "undetermined"))
	}
	if ConfidenceLabel(0.9, "confirmed") != "High" {
		t.Fatalf("0.9 confirmed should be High, got %q", ConfidenceLabel(0.9, "confirmed"))
	}
}

func TestFormatMissingEvidence(t *testing.T) {
	in := []string{
		"Routing adjacency change: needs ospf_adjacency_change",
		"Routing adjacency change: needs isis_adjacency_change",
		"Routing adjacency change: needs ospf_adjacency_change", // dup → collapsed
	}
	out := FormatMissingEvidence(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 deduped bullets, got %d: %v", len(out), out)
	}
	if out[0] != "OSPF adjacency-change signal was not found" {
		t.Fatalf("key not mapped to operational language: %q", out[0])
	}
	// No raw key should survive into a user-facing bullet.
	for _, b := range out {
		if strings.Contains(b, "_") || strings.Contains(b, "needs ") {
			t.Fatalf("raw debug token leaked into bullet: %q", b)
		}
	}
}

func TestInferOwner(t *testing.T) {
	if got := InferOwner("unassigned", "needs ospf_adjacency_change"); !strings.HasPrefix(got, "Network / Routing team") {
		t.Fatalf("routing evidence → Network/Routing, got %q", got)
	}
	if got := InferOwner("", "firewall_deny spike"); !strings.HasPrefix(got, "Network / Security team") {
		t.Fatalf("firewall evidence → Security, got %q", got)
	}
	if got := InferOwner("neteng-oncall"); got != "neteng-oncall" {
		t.Fatalf("explicit owner must pass through, got %q", got)
	}
	if got := InferOwner("unassigned", "nothing recognizable here"); got != "Needs triage" {
		t.Fatalf("no domain → Needs triage, got %q", got)
	}
}

func TestScrubAndDedup(t *testing.T) {
	if s := Scrub("owner: unassigned and a null value"); strings.Contains(s, "unassigned") || strings.Contains(s, "null") {
		t.Fatalf("scrub left raw tokens: %q", s)
	}
	d := dedupeLines([]string{"A", "a", " A ", "B"})
	if len(d) != 2 {
		t.Fatalf("dedupe (case/space-insensitive) expected 2, got %v", d)
	}
}

func TestNextActionsRCA(t *testing.T) {
	acts := NextActionsRCA("undetermined", []string{"leaf4"}, []string{"needs ospf_adjacency_change"})
	if len(acts) == 0 {
		t.Fatal("undetermined RCA must produce next actions")
	}
	joined := strings.ToLower(strings.Join(acts, " "))
	if !strings.Contains(joined, "neighbor") || !strings.Contains(joined, "undetermined") {
		t.Fatalf("routing/undetermined next actions missing: %v", acts)
	}
}

// TestUndeterminedRcaPolished is the headline acceptance test (spec §9/§23): the
// P-534394-style answer must be NOC-friendly — friendly id, "Not established"
// confidence, inferred owner, clean missing-evidence bullets, next actions,
// evidence-only badge — and must NOT lead with "AI provider unavailable" or
// show a bare "0% confidence" in the main text.
func TestUndeterminedRcaPolished(t *testing.T) {
	ds := &qualMockDS{}
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), Principal{Tenant: "t", Perms: map[string]bool{"correlations:read": true}},
		"explain this incident", map[string]string{"correlation_id": "11111111-1111-1111-1111-111111111111"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeProblemExplanation {
		t.Fatalf("mode = %s", ans.Mode)
	}
	if ans.ConfidenceLabel != "Not established" {
		t.Fatalf("undetermined confidence must be 'Not established', got %q", ans.ConfidenceLabel)
	}
	if strings.Contains(ans.Text, "0% confidence") || strings.Contains(strings.ToLower(ans.Text), "provider unavailable") {
		t.Fatalf("main answer must not lead with debug/provider text: %q", ans.Text)
	}
	if !strings.Contains(ans.Text, "leaf4") || !strings.Contains(strings.ToLower(ans.Text), "low-evidence") {
		t.Fatalf("summary should be a NOC note about leaf4: %q", ans.Text)
	}
	if !strings.HasPrefix(ans.RecommendedOwner, "Network / Routing") {
		t.Fatalf("owner should be inferred to Network/Routing, got %q", ans.RecommendedOwner)
	}
	if len(ans.NextActions) == 0 || len(ans.MissingEvidence) == 0 {
		t.Fatalf("must include next actions + missing-evidence bullets")
	}
	if !ans.EvidenceOnly || !contains(ans.ModeBadges, "Evidence-only mode") {
		t.Fatalf("provider-down answer must be flagged evidence-only with a badge, badges=%v", ans.ModeBadges)
	}
	for _, b := range ans.MissingEvidence {
		if strings.Contains(b, "_") {
			t.Fatalf("raw key leaked into missing-evidence bullet: %q", b)
		}
	}
}

// TestCurrentStateRanking is the acceptance test for the live-state briefing
// (current-state issue): a suspected CLASSIFIED incident must be "focus first"
// over undetermined unclassified 0% items; undetermined are grouped into a watch
// note (not dumped); confidence reads "established"-style not "0%"; the provider-
// unavailable note appears once (badge), not in the body.
func TestCurrentStateRanking(t *testing.T) {
	ds := &rankMockDS{}
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), Principal{Tenant: "t", Perms: map[string]bool{"correlations:read": true, "infrastructure:read": true}},
		"what is going on right now?", nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := ans.CurrentState
	if cs == nil || len(cs.RecommendedFocus) == 0 {
		t.Fatalf("no focus chosen: %+v", ans)
	}
	if !strings.Contains(cs.RecommendedFocus[0], "DIA egress latency") {
		t.Fatalf("focus must be the suspected classified incident, got %q", cs.RecommendedFocus[0])
	}
	if strings.Contains(cs.RecommendedFocus[0], "0%") {
		t.Fatalf("focus must not show a bare 0%%: %q", cs.RecommendedFocus[0])
	}
	if cs.WatchNote == "" || !strings.Contains(strings.ToLower(cs.WatchNote), "watch") {
		t.Fatalf("undetermined items must be grouped into a watch note, got %q", cs.WatchNote)
	}
	// Undetermined must NOT be dumped as individual actionable lines.
	for _, l := range cs.ActiveIncidents {
		if strings.Contains(strings.ToLower(l), "undetermined") {
			t.Fatalf("undetermined item leaked into the actionable list: %q", l)
		}
	}
	// Provider-unavailable appears once, as a badge — not repeated in the body
	// ("Network / Provider team" owner wording is fine; "provider unavailable" is not).
	low := strings.ToLower(ans.Text)
	if strings.Contains(low, "provider unavailable") || strings.Contains(low, "ai provider") || strings.Contains(low, "evidence-only summary") {
		t.Fatalf("provider state must be a badge, not body text: %q", ans.Text)
	}
	if !contains(ans.ModeBadges, "Evidence-only mode") {
		t.Fatalf("evidence-only badge missing: %v", ans.ModeBadges)
	}
}

// rankMockDS returns a mix: one suspected CLASSIFIED high-confidence incident +
// several undetermined unclassified low-evidence ones (newest first, so a recency
// sort would wrongly pick an undetermined item).
type rankMockDS struct{}

func (rankMockDS) GetProblem(_ context.Context, _ Principal, _ string) (*Problem, error) {
	return nil, ErrNotFound
}
func (rankMockDS) GetProblemEvidence(_ context.Context, _ Principal, _ string) ([]EvidenceItem, error) {
	return nil, nil
}
func (rankMockDS) ListActiveProblems(_ context.Context, _ Principal, _ int) ([]Problem, error) {
	return []Problem{
		{ID: "u1", DisplayID: "P-AAAAAA", Title: "Low-evidence correlation", Verdict: "undetermined", Confidence: 0, SignalCount: 1, NodeCount: 1, Devices: []string{"leaf4"}},
		{ID: "u2", DisplayID: "P-BBBBBB", Title: "Low-evidence correlation", Verdict: "undetermined", Confidence: 0, SignalCount: 1, NodeCount: 1, Devices: []string{"leaf1"}},
		{ID: "s1", DisplayID: "P-CCCCCC", Title: "ISP / DIA egress latency", Verdict: "suspected", Confidence: 1.0, SignalCount: 6, NodeCount: 2, Devices: []string{"wan-r2"}},
	}, nil
}

// qualMockDS serves one undetermined, single-signal routing problem (the P-534394
// shape) for the quality acceptance test.
type qualMockDS struct{}

func (qualMockDS) GetProblem(_ context.Context, _ Principal, id string) (*Problem, error) {
	return &Problem{
		ID: id, DisplayID: "P-111111", Title: "Unclassified correlation", Verdict: "undetermined",
		Confidence: 0, SignalCount: 1, NodeCount: 1, Devices: []string{"leaf4"},
		MissingEvidence: []string{
			"Routing adjacency change: needs ospf_adjacency_change",
			"Routing adjacency change: needs isis_adjacency_change",
		},
	}, nil
}
func (qualMockDS) GetProblemEvidence(_ context.Context, _ Principal, _ string) ([]EvidenceItem, error) {
	return nil, nil
}
func (qualMockDS) ListActiveProblems(_ context.Context, _ Principal, _ int) ([]Problem, error) {
	return nil, nil
}
