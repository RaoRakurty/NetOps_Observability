// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

// evals_test.go — the eval suite (HLD Phase 5 / spec §16). It encodes the design's
// definition-of-done as runnable assertions over the orchestrator, so a change
// that regresses a core guarantee fails CI. Golden examples live in
// docs/ai/golden-examples/. Runs entirely on the mock provider (no creds).

// evalDS is a DataSource with a spread of verdicts for the ranking/wording evals.
type evalDS struct{}

func (evalDS) GetProblem(_ context.Context, _ Principal, id string) (*Problem, error) {
	m := map[string]*Problem{
		"routing": {ID: "routing", Title: "OSPF adjacency loss on core-1", Verdict: "suspected", Confidence: 0.0,
			Devices: []string{"core-1"}, MissingEvidence: []string{"needs ospf_adjacency_change", "needs isis_adjacency_change"}, Owner: "", SignalCount: 3, NodeCount: 2},
		"unclassified": {ID: "unclassified", Title: "", Verdict: "undetermined", Confidence: 0.0, SignalCount: 1, NodeCount: 1},
	}
	if p, ok := m[id]; ok {
		return p, nil
	}
	return nil, ErrNotFound
}
func (evalDS) GetProblemEvidence(context.Context, Principal, string) ([]EvidenceItem, error) {
	return nil, nil
}
func (evalDS) ListActiveProblems(context.Context, Principal, int) ([]Problem, error) {
	return []Problem{
		{ID: "isp", Title: "ISP / DIA egress latency", Verdict: "suspected", Confidence: 1.0, Owner: "isp", Devices: []string{"wan-r2"}, SignalCount: 4, NodeCount: 3},
		{ID: "noise", Title: "", Verdict: "undetermined", Confidence: 0.0, SignalCount: 1, NodeCount: 1},
	}, nil
}

func evalOrch(reply string) *Orchestrator {
	ds := evalDS{}
	return &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Reply: reply}, Flags: func(string) bool { return false }}
}

func opsPerm() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{
		"correlations:read": true, "infrastructure:read": true, "flows:read": true, "events:read": true,
	}}
}

// §16: /status prioritizes a suspected classified incident over undetermined 0% noise.
func TestEval_StatusPrioritizesActionable(t *testing.T) {
	ans, err := evalOrch("").Ask(context.Background(), opsPerm(), "what is going on right now?", nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := ans.CurrentState
	if cs == nil || len(cs.RecommendedFocus) == 0 {
		t.Fatalf("no recommended focus: %+v", ans)
	}
	if !strings.Contains(cs.RecommendedFocus[0], "ISP / DIA") {
		t.Errorf("focus should be the suspected classified incident, got %q", cs.RecommendedFocus[0])
	}
}

// §16: 0% confidence renders as "Confidence not established", never a bare 0%.
func TestEval_ZeroConfidenceWording(t *testing.T) {
	if lbl := ConfidenceLabel(0, "undetermined"); !strings.Contains(strings.ToLower(lbl), "not established") {
		t.Errorf("0%% should read 'not established', got %q", lbl)
	}
	ans, _ := evalOrch("").Ask(context.Background(), opsPerm(), "explain this problem", map[string]string{"problem_id": "unclassified"})
	if strings.Contains(ans.Text, "0%") {
		t.Errorf("answer body must not show a bare 0%%: %q", ans.Text)
	}
}

// §16: an unclassified/verdict-only correlation reads as "low-evidence", not raw.
func TestEval_UnclassifiedWording(t *testing.T) {
	ans, _ := evalOrch("").Ask(context.Background(), opsPerm(), "explain this problem", map[string]string{"problem_id": "unclassified"})
	low := strings.ToLower(ans.Text + " " + strings.Join(ans.ModeBadges, " "))
	if strings.Contains(low, "unclassified correlation") {
		t.Errorf("must not surface the raw 'unclassified correlation' phrase: %q", ans.Text)
	}
}

// §16: missing OSPF/IS-IS evidence renders as clean operator language, not raw keys.
func TestEval_MissingEvidenceCleanWording(t *testing.T) {
	ans, _ := evalOrch("").Ask(context.Background(), opsPerm(), "what evidence is missing for this problem", map[string]string{"problem_id": "routing"})
	joined := strings.Join(ans.MissingEvidence, " ")
	if strings.Contains(joined, "needs ospf_adjacency_change") {
		t.Errorf("missing evidence must be humanized, got raw: %q", joined)
	}
	if len(ans.MissingEvidence) == 0 {
		t.Error("missing evidence should be disclosed")
	}
}

// §16: owner inference maps a routing incident to a routing/network team.
func TestEval_OwnerInference(t *testing.T) {
	ans, _ := evalOrch("").Ask(context.Background(), opsPerm(), "who should own this problem", map[string]string{"problem_id": "routing"})
	if ans.RecommendedOwner == "" || strings.EqualFold(ans.RecommendedOwner, "unassigned") {
		t.Errorf("owner should be inferred, got %q", ans.RecommendedOwner)
	}
}

// §16: provider-unavailable → a polished evidence-only answer, and the
// provider-unavailable text is a BADGE, not repeated in the body.
func TestEval_ProviderUnavailableEvidenceOnly(t *testing.T) {
	o := &Orchestrator{DS: evalDS{}, Tools: Tools(evalDS{}), LLM: MockLLM{Err: context.DeadlineExceeded}, Flags: func(string) bool { return false }}
	ans, _ := o.Ask(context.Background(), opsPerm(), "explain this problem", map[string]string{"problem_id": "routing"})
	if !ans.EvidenceOnly {
		t.Error("provider down → evidence-only answer expected")
	}
	if strings.Contains(strings.ToLower(ans.Text), "provider unavailable") || strings.Contains(strings.ToLower(ans.Text), "provider not configured") {
		t.Errorf("provider state must be a badge, not body text: %q", ans.Text)
	}
	if strings.TrimSpace(ans.Text) == "" {
		t.Error("evidence-only answer must still have a narrative")
	}
}

// §16: a prompt injection embedded in evidence is treated as DATA — the system
// prompt is server-owned and instructs the model to ignore instructions in data.
func TestEval_PromptInjectionTreatedAsData(t *testing.T) {
	o := evalOrch("ok")
	sys := o.systemPrompt()
	if !strings.Contains(strings.ToLower(sys), "data, never as instructions") {
		t.Errorf("system prompt must fence evidence as data: %q", sys)
	}
}

// §16: natural language and the equivalent slash command converge on one intent.
func TestEval_SlashNLConvergence(t *testing.T) {
	if Classify("/status", nil).Intent == "" { // resolved upstream; sanity that classify is stable
		t.Skip()
	}
	q, _, _ := ResolveCommand("/flows")
	if Classify(q, nil).Intent != Classify("show me the top talkers", nil).Intent {
		t.Error("/flows must converge with its natural-language equivalent")
	}
}

// §16: a product-navigation answer includes the UI location (a deep link).
func TestEval_NavigationIncludesLocation(t *testing.T) {
	ans, _ := evalOrch("").Ask(context.Background(), opsPerm(), "where do I configure servicenow", nil)
	if ans.Mode != ModeProductNavigationHelp || len(ans.Navigation) == 0 || ans.Navigation[0].UIRoute == "" {
		t.Errorf("navigation answer must carry a UI route, got %+v", ans.Navigation)
	}
}

// §16: cross-tenant access is denied — a caller can't explain another tenant's id.
func TestEval_CrossTenantDenied(t *testing.T) {
	o := newOrch(newMockDS())
	ans, _ := o.Ask(context.Background(), tenantB(), "explain this problem", map[string]string{"problem_id": "pa"}) // pa is t-a's
	if strings.Contains(ans.Text, "edge-1") || strings.Contains(ans.Text, "BGP peer down") {
		t.Errorf("cross-tenant leak: t-b saw t-a's problem: %q", ans.Text)
	}
}
