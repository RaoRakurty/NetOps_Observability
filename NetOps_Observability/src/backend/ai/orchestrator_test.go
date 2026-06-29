package ai

import (
	"context"
	"strings"
	"testing"
)

// mockDS is a two-tenant DataSource: tenant "t-a" owns problem "pa", "t-b" owns
// "pb". A principal only ever sees its own tenant's rows (ErrNotFound otherwise),
// mirroring the real chTenantScope/RLS guarantee.
type mockDS struct {
	problems map[string]map[string]*Problem
	evidence map[string][]EvidenceItem
}

func newMockDS() *mockDS {
	return &mockDS{
		problems: map[string]map[string]*Problem{
			"t-a": {"pa": {ID: "pa", Title: "BGP peer down on edge-1", Verdict: "confirmed", Confidence: 0.82,
				Devices: []string{"edge-1"}, MissingEvidence: []string{"flow"}, Owner: "neteng", SignalCount: 7, NodeCount: 3}},
			"t-b": {"pb": {ID: "pb", Title: "High CPU on leaf-2", Verdict: "suspected", Confidence: 0.55,
				Devices: []string{"leaf-2"}, SignalCount: 2, NodeCount: 1}},
		},
		evidence: map[string][]EvidenceItem{
			"pa": {{CitationID: "log:os:1", Kind: "log", Text: "edge-1 %BGP-5-ADJCHANGE neighbor Down", Href: "#/explore/logs"}},
		},
	}
}

func (m *mockDS) GetProblem(_ context.Context, p Principal, id string) (*Problem, error) {
	if pr, ok := m.problems[p.Tenant][id]; ok {
		return pr, nil
	}
	return nil, ErrNotFound // cross-tenant or unknown — never reveal existence
}

func (m *mockDS) GetProblemEvidence(_ context.Context, p Principal, id string) ([]EvidenceItem, error) {
	if _, ok := m.problems[p.Tenant][id]; !ok {
		return nil, ErrNotFound
	}
	return m.evidence[id], nil
}

func (m *mockDS) ListActiveProblems(_ context.Context, p Principal, _ int) ([]Problem, error) {
	var out []Problem
	for _, pr := range m.problems[p.Tenant] {
		out = append(out, *pr)
	}
	return out, nil
}

func newOrch(ds DataSource) *Orchestrator {
	return &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Reply: "Likely BGP session loss on edge-1 [log:os:1]. Next: check the peering link."},
		Flags: func(string) bool { return false }}
}

func tenantA() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true}}
}
func tenantB() Principal {
	return Principal{Tenant: "t-b", Perms: map[string]bool{"correlations:read": true}}
}

func TestModuleRegistry(t *testing.T) {
	if len(Modules()) < 13 {
		t.Fatalf("expected the full module registry, got %d", len(Modules()))
	}
	if _, ok := ModuleByID("correlations_rca"); !ok {
		t.Fatal("correlations_rca module must exist")
	}
	if IsModuleEnabled("cloud_app_observability", func(string) bool { return false }) {
		t.Fatal("a future/flagged module must NOT be enabled when its flag is off")
	}
	if !IsModuleEnabled("correlations_rca", nil) {
		t.Fatal("a stable unflagged module must be enabled")
	}
}

func TestClassifyProblem(t *testing.T) {
	p := Classify("explain problem", map[string]string{"correlation_id": "pa"})
	if p.Mode != ModeProblemExplanation || p.Entities["problem_id"] != "pa" {
		t.Fatalf("expected problem_explanation for the UI-supplied id, got %+v", p)
	}
}

func TestAnswerProblemHappyPath(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeProblemExplanation || ans.Problem == nil {
		t.Fatalf("expected a problem_explanation answer, got %+v", ans)
	}
	if ans.Problem.Verdict != "confirmed" || ans.Problem.Confidence != "82%" {
		t.Fatalf("structured fields must come from the tool, got %+v", ans.Problem)
	}
	if len(ans.Citations) == 0 {
		t.Fatal("answer must be grounded with citations")
	}
	// Missing-evidence disclosure (DoD #10).
	found := false
	for _, d := range ans.Disclaimers {
		if strings.Contains(d, "Missing evidence") {
			found = true
		}
	}
	if !found {
		t.Fatalf("must disclose missing evidence, disclaimers=%v", ans.Disclaimers)
	}
}

// TestCrossTenantIsolation — the mandatory §3a.5 test: tenant B can never read
// tenant A's problem, and A's data never appears in B's answer.
func TestCrossTenantIsolation(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantB(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Problem != nil {
		t.Fatal("LEAK: tenant B received tenant A's problem object")
	}
	blob := ans.Text + strings.Join(ans.Disclaimers, " ")
	for _, secret := range []string{"BGP peer down on edge-1", "edge-1", "neteng"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("LEAK: tenant A data %q surfaced to tenant B: %q", secret, blob)
		}
	}
}

func TestPermissionGate(t *testing.T) {
	o := newOrch(newMockDS())
	noPerm := Principal{Tenant: "t-a"} // no correlations:read
	ans, err := o.Ask(context.Background(), noPerm, "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable {
		t.Fatalf("a caller without correlations:read must be refused, got %s", ans.Mode)
	}
}

func TestProviderDownDegrades(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), tenantA(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Problem == nil || ans.Text == "" {
		t.Fatal("must degrade to a deterministic evidence-only summary when the provider is down")
	}
	if ans.Provider != "none" {
		t.Fatalf("expected provider=none on fallback, got %q", ans.Provider)
	}
}

func TestCurrentStateSummary(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "what is going on right now?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeCurrentStateSummary || ans.CurrentState == nil {
		t.Fatalf("expected a current_state_summary, got %+v", ans)
	}
	if ans.CurrentState.Confirmed != 1 {
		t.Fatalf("tenant A has 1 confirmed problem, got %d", ans.CurrentState.Confirmed)
	}
	if len(ans.Citations) == 0 {
		t.Fatal("current-state must cite the active incidents")
	}
}

// Cross-tenant: B's current-state must never include A's problem.
func TestCurrentStateIsolation(t *testing.T) {
	o := newOrch(newMockDS())
	ans, _ := o.Ask(context.Background(), tenantB(), "what should the NOC focus on first?", nil)
	for _, l := range ans.CurrentState.ActiveIncidents {
		if strings.Contains(l, "edge-1") || strings.Contains(l, "BGP peer down") {
			t.Fatalf("LEAK: tenant A incident surfaced to tenant B: %q", l)
		}
	}
}

func TestNavigation(t *testing.T) {
	o := newOrch(newMockDS())
	ans, err := o.Ask(context.Background(), tenantA(), "where do I configure servicenow", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeProductNavigationHelp || len(ans.Navigation) == 0 {
		t.Fatalf("expected navigation help, got %+v", ans)
	}
}
