package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/ai"
)

// copilot_agent_test.go — the P2 agent-loop guarantees, proven with a mock
// model (no HTTP): the loop HALTS at its call cap against a runaway model, a
// cross-tenant probe yields "not found" and zero foreign rows (§3a.5), policy
// denials refuse execution, invented citations are stripped, and the daily
// budget meters.

// agentTestDS is a two-tenant ai.DataSource: tenant "t-a" owns problem A,
// "t-b" owns problem B — mirroring the chTenantScope/RLS guarantee.
type agentTestDS struct{}

const (
	problemA = "aaaaaaaa-1111-1111-1111-111111111111"
	problemB = "bbbbbbbb-2222-2222-2222-222222222222"
)

func (agentTestDS) GetProblem(_ context.Context, p ai.Principal, id string) (*ai.Problem, error) {
	own := map[string]string{"t-a": problemA, "t-b": problemB}[p.Tenant]
	if id != own {
		return nil, ai.ErrNotFound // cross-tenant/unknown — never reveal existence
	}
	return &ai.Problem{ID: id, Title: "BGP peer down", Verdict: "confirmed", Confidence: 0.8, SignalCount: 3, NodeCount: 1}, nil
}

func (d agentTestDS) GetProblemEvidence(ctx context.Context, p ai.Principal, id string) ([]ai.EvidenceItem, error) {
	if _, err := d.GetProblem(ctx, p, id); err != nil {
		return nil, err
	}
	return []ai.EvidenceItem{{CitationID: "log:os:1", Kind: "log", Text: "neighbor down", Href: "#/explore/logs"}}, nil
}

func (agentTestDS) ListActiveProblems(_ context.Context, p ai.Principal, _ int) ([]ai.Problem, error) {
	if p.Tenant != "t-a" {
		return nil, nil
	}
	return []ai.Problem{{ID: problemA, Title: "BGP peer down", Verdict: "confirmed", Confidence: 0.8}}, nil
}

// ListProblemsInWindow makes agentTestDS a WindowDataSource so the
// get_incident_history tool registers in the test harness (same tenant scoping).
func (d agentTestDS) ListProblemsInWindow(ctx context.Context, p ai.Principal, _ int) ([]ai.Problem, error) {
	probs, err := d.ListActiveProblems(ctx, p, 25)
	for i := range probs {
		probs[i].State = "closed"
	}
	return probs, err
}

// agentTestServer: the blank store path keeps the per-tenant AI config purely
// in-memory (kvSave on "" fails and is ignored) — persistence has its own tests.
func agentTestServer() *server {
	return &server{aiToolBudget: newAIDailyBudget(), aiTenantCfg: newAITenantConfigStore("", nil)}
}

func agentTestSetup(tenant string) (*server, ai.Principal, *ai.ToolRegistry, *ai.PolicyEngine, []ai.ToolSpec) {
	s := agentTestServer()
	p := ai.Principal{Tenant: tenant, Perms: map[string]bool{"correlations:read": true, "events:read": true}}
	reg := ai.Tools(agentTestDS{})
	pol := ai.NewPolicyEngine(ai.PolicyConfig{}, func(string) bool { return false })
	return s, p, reg, pol, ai.Manifest(reg, pol, p)
}

func TestAgentLoopHaltsRunawayModel(t *testing.T) {
	s, p, reg, pol, specs := agentTestSetup("t-a")
	rounds := 0
	// A runaway model: requests another lookup on EVERY round it is offered
	// tools; only answers when the loop withdraws them.
	call := func(_ context.Context, _ string, _ []ai.AgentTurn, sp []ai.ToolSpec) (string, []ai.ToolCall, error) {
		rounds++
		if len(sp) == 0 {
			return "final answer with what I have", nil, nil
		}
		return "", []ai.ToolCall{{ID: "c", Name: "get_active_major_incidents", Args: json.RawMessage(`{}`)}}, nil
	}
	res, err := s.runAgentLoop(context.Background(), jwtClaims{Tenant: "t-a", Sub: "u"}, p, reg, pol, specs, "sys",
		[]copilotMessage{{Role: "user", Content: "loop forever"}}, nil, call)
	if err != nil {
		t.Fatal(err)
	}
	if res.Calls != 4 { // AI_TOOLS_MAX_CALLS default
		t.Fatalf("loop must halt at the call cap: executed %d", res.Calls)
	}
	if !res.Truncated {
		t.Fatal("truncation must be disclosed")
	}
	if res.Text != "final answer with what I have" {
		t.Fatalf("forced final answer missing, got %q", res.Text)
	}
	if rounds > 7 {
		t.Fatalf("model called %d times — loop not bounded", rounds)
	}
}

// §3a.5 isolation: a model authenticated as tenant A asking for tenant B's
// problem gets "not found" — no foreign row ever reaches the prompt, the
// citations, or the narrative.
func TestAgentLoopCrossTenantProbeDenied(t *testing.T) {
	s, p, reg, pol, specs := agentTestSetup("t-a")
	var probeReply ai.ToolReply
	round := 0
	call := func(_ context.Context, _ string, turns []ai.AgentTurn, _ []ai.ToolSpec) (string, []ai.ToolCall, error) {
		round++
		if round == 1 {
			return "", []ai.ToolCall{{ID: "c1", Name: "get_problem", Args: json.RawMessage(`{"problem_id":"` + problemB + `"}`)}}, nil
		}
		// Capture what the loop fed back for the probe, then try to cite the
		// foreign problem anyway (fabricated grounding).
		last := turns[len(turns)-1]
		if len(last.Replies) > 0 {
			probeReply = last.Replies[0]
		}
		return "Tenant B has an outage [problem:" + problemB + "] trust me.", nil, nil
	}
	res, err := s.runAgentLoop(context.Background(), jwtClaims{Tenant: "t-a", Sub: "u"}, p, reg, pol, specs, "sys",
		[]copilotMessage{{Role: "user", Content: "what about tenant b?"}}, nil, call)
	if err != nil {
		t.Fatal(err)
	}
	if !probeReply.IsError || !strings.Contains(probeReply.Content, "not found") {
		t.Fatalf("cross-tenant probe must return a bare not-found, got %+v", probeReply)
	}
	if strings.Contains(probeReply.Content, "tenant") || strings.Contains(probeReply.Content, "BGP") {
		t.Fatalf("not-found reply leaks detail: %q", probeReply.Content)
	}
	// The invented citation of the foreign problem is stripped by the verifier.
	if strings.Contains(res.Text, problemB) {
		t.Fatalf("fabricated foreign citation survived: %q", res.Text)
	}
	for _, c := range res.Citations {
		if strings.Contains(c.ID, problemB) {
			t.Fatalf("foreign problem in citations: %+v", c)
		}
	}
}

func TestExecuteAgentToolPolicyAndValidation(t *testing.T) {
	s := agentTestServer()
	reg := ai.Tools(agentTestDS{})
	pol := ai.NewPolicyEngine(ai.PolicyConfig{}, func(string) bool { return false })
	noPerms := ai.Principal{Tenant: "t-a"}

	// Policy denial (caller lacks the permission the manifest would have hidden).
	rep, items := s.executeAgentTool(context.Background(), jwtClaims{Tenant: "t-a"}, noPerms, reg, pol,
		ai.ToolCall{ID: "c", Name: "get_problem", Args: json.RawMessage(`{"problem_id":"` + problemA + `"}`)})
	if !rep.IsError || !strings.Contains(rep.Content, "not permitted") || len(items) != 0 {
		t.Fatalf("policy denial expected, got %+v", rep)
	}

	// Unknown tool.
	rep, _ = s.executeAgentTool(context.Background(), jwtClaims{}, noPerms, reg, pol, ai.ToolCall{ID: "c", Name: "rm_rf"})
	if !rep.IsError || rep.Content != "unknown tool" {
		t.Fatalf("unknown tool expected, got %+v", rep)
	}

	// Bad args (missing required).
	perms := ai.Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true, "events:read": true}}
	rep, _ = s.executeAgentTool(context.Background(), jwtClaims{Tenant: "t-a"}, perms, reg, pol,
		ai.ToolCall{ID: "c", Name: "get_problem", Args: json.RawMessage(`{}`)})
	if !rep.IsError || !strings.Contains(rep.Content, "invalid arguments") {
		t.Fatalf("bad-args refusal expected, got %+v", rep)
	}

	// Happy path renders cited lines.
	rep, items = s.executeAgentTool(context.Background(), jwtClaims{Tenant: "t-a"}, perms, reg, pol,
		ai.ToolCall{ID: "c", Name: "get_problem", Args: json.RawMessage(`{"problem_id":"` + problemA + `"}`)})
	if rep.IsError || len(items) != 1 || !strings.Contains(rep.Content, "[problem:"+problemA+"]") {
		t.Fatalf("happy path wrong: %+v items=%d", rep, len(items))
	}
}

func TestAIDailyBudget(t *testing.T) {
	b := newAIDailyBudget()
	if !b.allow("t-a", 100) {
		t.Fatal("fresh budget must allow")
	}
	b.charge("t-a", 150)
	if b.allow("t-a", 100) {
		t.Fatal("over-budget tenant must be refused")
	}
	if !b.allow("t-b", 100) {
		t.Fatal("budget is per-tenant")
	}
	if !b.allow("t-a", 0) {
		t.Fatal("<=0 disables metering")
	}
}

// TestPerTenantGuardrails: the platform owner can override the lookup cap and
// the daily token budget per tenant; 0 means the platform default (owner
// decision 2026-07-02: guardrails configurable per tenant, defaults good).
func TestPerTenantGuardrails(t *testing.T) {
	t.Setenv("AI_TOOLS_MAX_CALLS", "4")
	t.Setenv("AI_TOOLS_DAILY_TOKENS", "250000")
	s := agentTestServer()
	if got := s.maxCallsFor("t-a"); got != 4 {
		t.Fatalf("unconfigured tenant must use the platform default, got %d", got)
	}
	if got := s.dailyTokensFor("t-a"); got != 250000 {
		t.Fatalf("unconfigured tenant budget default wrong: %d", got)
	}
	_, _ = s.aiTenantCfg.setEntitlement("t-a", false, true, 2, 50_000)
	if got := s.maxCallsFor("t-a"); got != 2 {
		t.Fatalf("tenant override must win, got %d", got)
	}
	if got := s.dailyTokensFor("t-a"); got != 50_000 {
		t.Fatalf("tenant budget override must win, got %d", got)
	}
	if got := s.maxCallsFor("t-b"); got != 4 {
		t.Fatal("override must not leak to other tenants")
	}
	// Clamps: the store refuses silly values.
	_, _ = s.aiTenantCfg.setEntitlement("t-a", false, true, 99, 99_000_000)
	if got := s.maxCallsFor("t-a"); got != 8 {
		t.Fatalf("max_calls must clamp to 8, got %d", got)
	}
	if got := s.dailyTokensFor("t-a"); got != 5_000_000 {
		t.Fatalf("daily_tokens must clamp to 5M, got %d", got)
	}
}

func TestAgentLoopEligibility(t *testing.T) {
	s := agentTestServer()
	t.Setenv("FEATURE_AI_TOOLS", "")
	if s.agentLoopEligible(jwtClaims{Tenant: "t-a"}) {
		t.Fatal("off by default")
	}
	t.Setenv("FEATURE_AI_TOOLS", "true")
	if s.agentLoopEligible(jwtClaims{Tenant: "t-a", Sub: "user", Role: "admin"}) {
		t.Fatal("tenant users are not entitled by default")
	}
	// Per-tenant entitlement (P4a): granting "AI Investigations" to ONE tenant
	// enables its users — and nobody else's.
	_, _ = s.aiTenantCfg.setEntitlement("t-a", false, true, 0, 0)
	if !s.agentLoopEligible(jwtClaims{Tenant: "t-a"}) {
		t.Fatal("entitled tenant must be eligible")
	}
	if s.agentLoopEligible(jwtClaims{Tenant: "t-b"}) {
		t.Fatal("entitlement must not leak to other tenants")
	}
	_, _ = s.aiTenantCfg.setEntitlement("t-a", false, false, 0, 0)
	t.Setenv("AI_TOOLS_ALL_TENANTS", "true")
	if !s.agentLoopEligible(jwtClaims{Tenant: "t-a"}) {
		t.Fatal("AI_TOOLS_ALL_TENANTS widens the rollout globally")
	}
}
