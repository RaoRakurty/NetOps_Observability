// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_tool_gateway_test.go — tracker 337 N-A8 at the server boundary: the
// copilot agent loop runs tools through the same gateway as the engine, its
// tool calls are ledgered (surface copilot, latency), the per-tenant tool
// budget is keyed on the TOKEN's tenant and isolates tenants, the data source
// honours the per-call context, and nothing in this package runs a tool
// outside the gateway.

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
)

func TestCopilotToolCallsAreLedgered(t *testing.T) {
	s := agentTestServer()
	s.aiToolGateway = ai.NewToolGateway()
	reg := ai.Tools(agentTestDS{})
	pol := ai.NewPolicyEngine(ai.PolicyConfig{}, func(string) bool { return false })
	perms := ai.Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true, "events:read": true}}
	rec, err := aidecision.NewRecorder("alice", aidecision.SurfaceCopilot)
	if err != nil {
		t.Fatal(err)
	}
	ctx := aidecision.WithRecorder(context.Background(), rec)
	rep, _ := s.executeAgentTool(ctx, jwtClaims{Tenant: "t-a", Sub: "alice"}, perms, reg, pol,
		ai.ToolCall{ID: "c", Name: "get_problem", Args: json.RawMessage(`{"problem_id":"` + problemA + `"}`)})
	if rep.IsError {
		t.Fatalf("call failed: %+v", rep)
	}
	var exec *aidecision.Entry
	for _, e := range rec.Entries() {
		if e.EventType == aidecision.ToolExecuted && e.Tool == "get_problem" {
			e := e
			exec = &e
		}
	}
	if exec == nil || exec.Outcome != ai.OutcomeOK || exec.Surface != "" && exec.Surface != aidecision.SurfaceCopilot ||
		exec.ArgsSHA256 == "" || exec.ResultSHA256 == "" || !strings.HasPrefix(exec.ToolVersion, "1@") {
		t.Fatalf("copilot tool call not ledgered as TOOL_EXECUTED with hashes and contract version: %+v", rec.Entries())
	}
	if s.aiToolGateway.Metrics.Count("get_problem", ai.OutcomeOK) != 1 {
		t.Fatal("the copilot call did not pass the gateway")
	}
}

// The budget is keyed on the principal's tenant (from the token): tenant A
// exhausting a tool's rate does not throttle tenant B on the SAME gateway.
func TestCopilotToolRateIsPerTenant(t *testing.T) {
	s := agentTestServer()
	s.aiToolGateway = &ai.ToolGateway{Limiter: onlyNLimiter{n: 1, used: map[string]int{}}, Metrics: ai.NewToolMetrics()}
	reg := ai.Tools(agentTestDS{})
	pol := ai.NewPolicyEngine(ai.PolicyConfig{}, func(string) bool { return false })
	perm := map[string]bool{"correlations:read": true, "events:read": true}
	call := ai.ToolCall{ID: "c", Name: "get_problem", Args: json.RawMessage(`{"problem_id":"` + problemA + `"}`)}
	a := ai.Principal{Tenant: "t-a", Perms: perm}
	b := ai.Principal{Tenant: "t-b", Perms: perm}
	if rep, _ := s.executeAgentTool(context.Background(), jwtClaims{Tenant: "t-a"}, a, reg, pol, call); rep.IsError {
		t.Fatalf("first call: %+v", rep)
	}
	if rep, _ := s.executeAgentTool(context.Background(), jwtClaims{Tenant: "t-a"}, a, reg, pol, call); !rep.IsError || !strings.Contains(rep.Content, "per-minute limit") {
		t.Fatalf("second call for t-a must be rate limited: %+v", rep)
	}
	if rep, _ := s.executeAgentTool(context.Background(), jwtClaims{Tenant: "t-b"}, b, reg, pol, call); strings.Contains(rep.Content, "per-minute limit") {
		t.Fatalf("TENANT ISOLATION: t-b throttled by t-a's budget: %+v", rep)
	}
}

// onlyNLimiter allows n calls per key and records the keys it saw.
type onlyNLimiter struct {
	n    int
	used map[string]int
}

func (l onlyNLimiter) AllowN(key string, _ int) bool {
	if l.used[key] >= l.n {
		return false
	}
	l.used[key]++
	return true
}

// Every request's orchestrator shares the server's one gateway.
func TestNewOrchestratorWiresTheSharedGateway(t *testing.T) {
	s := agentTestServer()
	s.aiToolGateway = ai.NewToolGateway()
	r := httptest.NewRequest("POST", "/api/ai/ask", nil)
	o := s.newOrchestrator(r, jwtClaims{Tenant: "t-a", Sub: "alice"})
	if o.Gateway != s.aiToolGateway || o.Toolbox().Gateway != s.aiToolGateway {
		t.Fatal("the orchestrator does not use the server's tool gateway")
	}
}

// The data source reads under the context it is HANDED (the gateway's
// deadline), not the request context it captured.
func TestAIDataSourceBindsThePerCallContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := aiDataSource{ctx: context.Background()}
	if got := d.with(ctx); got.ctx != ctx {
		t.Fatal("with did not bind the per-call context")
	}
	//nolint:staticcheck // SA1012: nil context is the documented "keep the request's" case
	if got := d.with(nil); got.ctx != d.ctx {
		t.Fatal("a nil context must keep the request's")
	}
}

// Nothing in this package calls AITool.Run itself: the gateway (package ai)
// is the only place a tool runs.
func TestRootPackageNeverRunsAToolDirectly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "Run" && len(call.Args) == 3 {
				if id, ok := sel.X.(*ast.Ident); ok && (id.Name == "tool" || id.Name == "t") {
					t.Errorf("%s: a tool is run outside the gateway (use Toolbox.Invoke)", fset.Position(call.Pos()))
				}
			}
			return true
		})
	}
}
