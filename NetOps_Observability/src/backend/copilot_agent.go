package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"netops/backend/ai"
)

// copilot_agent.go — the server-owned, bounded agent loop (intelligence plan
// P2, §3.c). When FEATURE_AI_TOOLS is on and a provider key is configured, a
// free-form chat turn lets the MODEL choose read-only tools from a manifest the
// Policy Engine filtered to the caller — then the server validates every call,
// executes it with the caller's Principal against the same tenant-scoped
// DataSource the grounded engine uses, and feeds bounded results back. Hard
// bounds everywhere (call cap, wall-clock, per-reply size, daily token budget);
// the final narrative passes the deterministic grounding verifier.
//
// Rollout (plan §6 default #2): platform-owner/global-tenant first —
// AI_TOOLS_ALL_TENANTS=true widens it later (P4). Off by default.

const (
	aiToolsLoopTimeout  = 2 * time.Minute // hard wall-clock bound per turn
	aiToolsMaxCitations = 12              // citations returned to the UI
)

// featureAIToolsEnabled gates the loop (off by default — soak per plan §5 P2).
func featureAIToolsEnabled() bool { return os.Getenv("FEATURE_AI_TOOLS") == "true" }

// agentLoopEligible: the loop always runs for the platform owner / cross-tenant
// principals; tenant users need their tenant's per-tenant entitlement
// (ai_tenant_config.go, "AI Investigations"). AI_TOOLS_ALL_TENANTS=true remains
// as a global override that entitles every tenant at once.
func (s *server) agentLoopEligible(claims jwtClaims) bool {
	if !featureAIToolsEnabled() {
		return false
	}
	tenant, cross := principalTenant(claims)
	if cross || os.Getenv("AI_TOOLS_ALL_TENANTS") == "true" {
		return true
	}
	return s.aiTenantCfg.AgentToolsEnabled(tenant)
}

// ---- daily per-tenant token budget (LLM04/LLM10, plan §4.5) ------------------

// aiToolsDailyTokens is the platform-default per-tenant daily budget
// (metered by ai.DailyBudget); ≤0 disables metering.
func aiToolsDailyTokens() int { return envInt("AI_TOOLS_DAILY_TOKENS", 250_000) }

// ---- the loop ----------------------------------------------------------------

// agentToolCaller is one model round-trip. Injected so tests drive the loop
// with a mock model (runaway halt, cross-tenant probes) without HTTP.
type agentToolCaller func(ctx context.Context, system string, turns []ai.AgentTurn, specs []ai.ToolSpec) (string, []ai.ToolCall, error)

// agentLookup is the customer-facing record of one investigation step.
type agentLookup struct {
	Tool  string `json:"tool"`
	Label string `json:"label"`
	Items int    `json:"items"`
	Error bool   `json:"error,omitempty"`
}

type agentResult struct {
	Text      string
	Lookups   []agentLookup
	Citations []ai.Citation
	Truncated bool
	Calls     int // tool calls actually executed (0 → safe to fall back to plain chat)
}

// runAgentLoop drives model↔tool rounds until the model answers in text, the
// call budget or wall-clock runs out, or the model errors. Every tool call is
// (re-)authorized by the Policy Engine, schema-validated, executed with the
// caller's Principal, audited, and bounded.
// extraCiteIDs are citation ids that are valid WITHOUT a tool having produced
// them this turn (the pre-retrieved documentation block in the system prompt) —
// the verifier must not strip a legitimate cite of those.
func (s *server) runAgentLoop(ctx context.Context, claims jwtClaims, p ai.Principal, reg *ai.ToolRegistry, pol *ai.PolicyEngine, specs []ai.ToolSpec, system string, msgs []copilotMessage, extraCiteIDs []string, call agentToolCaller) (agentResult, error) {
	ctx, cancel := context.WithTimeout(ctx, aiToolsLoopTimeout)
	defer cancel()

	loopTenant, _ := principalTenant(claims)
	maxCalls := s.maxCallsFor(loopTenant) // per-tenant guardrail, platform default fallback

	turns := make([]ai.AgentTurn, 0, len(msgs)+2*maxCalls)
	for _, m := range msgs {
		turns = append(turns, ai.AgentTurn{Role: m.Role, Content: m.Content})
	}

	tenant, _ := principalTenant(claims)
	res := agentResult{}
	var evidence []ai.EvidenceItem
	started := time.Now()

	// maxCalls tool calls → at most maxCalls+1 model round-trips, +1 for the
	// forced final answer after exhaustion.
	for iter := 0; iter <= maxCalls+1; iter++ {
		// Tools stay on offer until the model actually over-asks: a model that
		// stops at the cap on its own is NOT truncated. Once a call was refused
		// for budget, tools are withdrawn and the model must answer.
		activeSpecs := specs
		if res.Truncated {
			activeSpecs = nil
		}
		text, calls, err := call(ctx, system, turns, activeSpecs)
		s.aiToolBudget.Charge(tenant, ai.EstTokens(turns, text))
		if err != nil {
			return res, err
		}
		if len(calls) == 0 || len(activeSpecs) == 0 {
			res.Text = text
			break
		}

		replies := make([]ai.ToolReply, 0, len(calls))
		for _, c := range calls {
			if res.Calls >= maxCalls {
				res.Truncated = true
				replies = append(replies, ai.ToolReply{ID: c.ID, Name: c.Name, IsError: true,
					Content: "Tool budget exhausted — no more lookups this turn. Answer with what you already have and say the investigation was truncated."})
				continue
			}
			res.Calls++
			rep, items := s.executeAgentTool(ctx, claims, p, reg, pol, c)
			replies = append(replies, rep)
			res.Lookups = append(res.Lookups, agentLookup{Tool: c.Name, Label: ai.ToolLabel(c.Name), Items: len(items), Error: rep.IsError})
			evidence = append(evidence, items...)
		}
		turns = append(turns,
			ai.AgentTurn{Role: "assistant", Content: text, Calls: calls},
			ai.AgentTurn{Role: "user", Replies: replies},
		)
	}
	if strings.TrimSpace(res.Text) == "" {
		return res, fmt.Errorf("the investigation did not produce an answer — please try again")
	}

	// Deterministic grounding verifier: strip any evidence citation the model
	// invented (same guarantee as the grounded engine).
	validIDs := append(make([]string, 0, len(evidence)+len(extraCiteIDs)), extraCiteIDs...)
	seen := map[string]bool{}
	for _, ev := range evidence {
		validIDs = append(validIDs, ev.CitationID)
		if seen[ev.CitationID] || len(res.Citations) >= aiToolsMaxCitations {
			continue
		}
		seen[ev.CitationID] = true
		label := ev.Text
		if len(label) > 80 {
			label = label[:80] + "…"
		}
		res.Citations = append(res.Citations, ai.Citation{ID: ev.CitationID, Kind: ev.Kind, Label: label, Href: ev.Href})
	}
	res.Text = ai.VerifyGrounding(res.Text, validIDs).Text

	logInfo("ai", "agent_loop", map[string]any{
		"tenant": claims.Tenant, "sub": claims.Sub,
		"calls": res.Calls, "truncated": res.Truncated,
		"duration_ms": time.Since(started).Milliseconds(),
	})
	return res, nil
}

// executeAgentTool validates + authorizes + runs ONE model-requested tool call
// and renders its bounded reply. Errors are turned into honest error replies
// (the model must know the lookup failed), never raw store errors (no schema/
// query text leaks into a prompt). Each call is audited with arg NAMES only.
func (s *server) executeAgentTool(ctx context.Context, claims jwtClaims, p ai.Principal, reg *ai.ToolRegistry, pol *ai.PolicyEngine, c ai.ToolCall) (ai.ToolReply, []ai.EvidenceItem) {
	started := time.Now()
	rep := ai.ToolReply{ID: c.ID, Name: c.Name}
	fail := func(msg, reason string) (ai.ToolReply, []ai.EvidenceItem) {
		rep.IsError = true
		rep.Content = msg
		s.auditAgentTool(claims, c, nil, started, false, reason)
		return rep, nil
	}

	tool, ok := reg.Get(c.Name)
	if !ok {
		return fail("unknown tool", "unknown_tool")
	}
	// Re-authorize at execution time (defense in depth — the manifest filter is
	// the first gate, this is the second; the tool itself re-validates args).
	if d := pol.EvaluateTool(tool, p); !d.Allow {
		return fail("not permitted: "+d.Reason, "policy_denied")
	}
	args, err := ai.ParseToolArgs(c.Name, c.Args)
	if err != nil {
		return fail("invalid arguments: "+err.Error(), "bad_args")
	}
	result, err := tool.Run(ctx, p, args)
	switch {
	case errors.Is(err, ai.ErrNotFound):
		// Cross-tenant / unknown ids look identical (§3a — never reveal existence).
		rep.IsError = true
		rep.Content = "not found"
		s.auditAgentTool(claims, c, args, started, false, "not_found")
		return rep, nil
	case errors.Is(err, ai.ErrNotImplemented):
		return fail("this lookup is not available in this build", "not_implemented")
	case err != nil:
		logWarn("ai", "agent tool failed", map[string]any{"tool": c.Name, "err": err.Error()})
		return fail("the lookup failed — do not invent its data", "tool_error")
	}

	rep.Content = ai.RenderToolReply(&result)
	s.auditAgentTool(claims, c, args, started, true, "ok")
	return rep, result.Items
}

// auditAgentTool writes the per-tool-call audit line: principal, tool, arg
// NAMES (never values — they may contain device names/log text), duration,
// outcome. Question text never appears (unchanged no-PII audit stance).
func (s *server) auditAgentTool(claims jwtClaims, c ai.ToolCall, args ai.ToolArgs, started time.Time, allowed bool, reason string) {
	names := make([]string, 0, len(args))
	for k := range args {
		names = append(names, k)
	}
	logInfo("ai", "tool_call", map[string]any{
		"tenant": claims.Tenant, "sub": claims.Sub,
		"tool": c.Name, "args": names,
		"allowed": allowed, "reason": reason,
		"duration_ms": time.Since(started).Milliseconds(),
	})
}
