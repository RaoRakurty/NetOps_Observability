package ai

import (
	"context"
	"testing"
)

// fakeWriteTool is a CapWrite tool used only to prove the Policy Engine's
// execute-vs-not gate. (No such tool ships in v1.)
type fakeWriteTool struct{}

func (fakeWriteTool) Name() string            { return "create_itsm_ticket" }
func (fakeWriteTool) Module() string          { return "itsm" }
func (fakeWriteTool) Capability() Capability  { return CapWrite }
func (fakeWriteTool) RequiredPerms() []string { return []string{"incident:read"} }
func (fakeWriteTool) Freshness() Freshness    { return FreshnessLive }
func (fakeWriteTool) Run(context.Context, Principal, ToolArgs) (ToolResult, error) {
	return ToolResult{}, nil
}

func itsmPrincipal() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{"incident:read": true}}
}

// The headline guarantee: in default (read-only) mode the AI CANNOT run a
// write/execute tool — denied deterministically before any execution.
func TestPolicyHardDeniesActionsByDefault(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{}, func(string) bool { return false })
	d := pe.EvaluateTool(fakeWriteTool{}, itsmPrincipal())
	if d.Allow {
		t.Fatalf("write/execute tools MUST be denied in read-only mode; got allow (%s)", d.Reason)
	}
}

// A read tool with the right perms is allowed.
func TestPolicyAllowsGovernedReadTool(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{}, nil)
	d := pe.EvaluateTool(getProblemTool{}, tenantA())
	if !d.Allow {
		t.Fatalf("a permitted read tool must be allowed; got deny (%s)", d.Reason)
	}
}

// Lifting AllowActions removes the blanket capability ban (the P6 action gate
// then applies on top) — proving the flag is the single execute-vs-not knob.
func TestPolicyAllowActionsKnob(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{AllowActions: true}, nil)
	d := pe.EvaluateTool(fakeWriteTool{}, itsmPrincipal())
	if !d.Allow {
		t.Fatalf("with AllowActions, a permitted write tool should pass the capability gate; got deny (%s)", d.Reason)
	}
}

// Deny-list wins over everything; allow-list restricts to named tools.
func TestPolicyAllowDenyLists(t *testing.T) {
	deny := NewPolicyEngine(PolicyConfig{DenyTools: []string{"get_problem"}}, nil)
	if deny.EvaluateTool(getProblemTool{}, tenantA()).Allow {
		t.Fatal("deny-list must block the tool")
	}
	only := NewPolicyEngine(PolicyConfig{AllowTools: []string{"get_problem_evidence"}}, nil)
	if only.EvaluateTool(getProblemTool{}, tenantA()).Allow {
		t.Fatal("allow-list must exclude tools not on it")
	}
	if !only.EvaluateTool(getProblemEvidenceTool{}, tenantA()).Allow {
		t.Fatal("allow-list must permit a listed tool")
	}
}

// A policy-denied module can't be routed to.
func TestPolicyDenyModule(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{DenyModules: []string{"correlations_rca"}}, nil)
	if pe.EvaluateModule("correlations_rca", tenantA()).Allow {
		t.Fatal("deny-listed module must be refused")
	}
}
