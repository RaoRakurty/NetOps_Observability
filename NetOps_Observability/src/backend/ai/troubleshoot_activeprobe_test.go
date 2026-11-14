// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

var activeProbeNames = []string{"run_ping", "run_traceroute", "run_dns_test", "run_http_test"}

func probePrincipal() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{
		"correlations:read": true, "infrastructure:read": true, "infrastructure:write": true,
	}}
}

type probeCall struct{ req ActiveProbeRequest }

func probeRegistry(t *testing.T, calls *[]probeCall) *ToolRegistry {
	t.Helper()
	reg := &ToolRegistry{byName: map[string]AITool{}}
	reg.AddTroubleshootTools(nil, TroubleshootDeps{
		ActiveProbe: func(_ context.Context, _ Principal, req ActiveProbeRequest) (ActiveProbeReport, error) {
			if calls != nil {
				*calls = append(*calls, probeCall{req: req})
			}
			return ActiveProbeReport{Kind: req.Kind, Scoped: true, Results: []ActiveProbeResult{{
				Target: "edge-1", TargetKind: "device", Up: true, Sent: 3, Received: 3, RTTms: 4.2,
			}}}, nil
		},
	})
	if rej := reg.Rejected(); len(rej) > 0 {
		t.Fatalf("active probes rejected at registration: %v", rej)
	}
	return reg
}

func flagsOn(string) bool { return true }

// TestActiveProbeGate: the default policy denies every active probe with a
// reason; the server's reason travels to the denial; an open gate allows them;
// and a write is still denied whatever the probe gate says.
func TestActiveProbeGate(t *testing.T) {
	reg := probeRegistry(t, nil)
	p := probePrincipal()
	closed := NewPolicyEngine(PolicyConfig{}, flagsOn)
	reasoned := NewPolicyEngine(PolicyConfig{NetProbes: NetProbeGate{Reason: "this workspace has not turned active probes on"}}, flagsOn)
	open := NewPolicyEngine(PolicyConfig{NetProbes: NetProbeGate{Allow: true}}, flagsOn)
	for _, n := range activeProbeNames {
		tool, ok := reg.Get(n)
		if !ok {
			t.Fatalf("%s not registered", n)
		}
		if d := closed.EvaluateTool(tool, p); d.Allow || !strings.Contains(d.Reason, "not turned on") {
			t.Errorf("%s with the default policy: %+v", n, d)
		}
		if d := reasoned.EvaluateTool(tool, p); d.Allow || d.Reason != "this workspace has not turned active probes on" {
			t.Errorf("%s: the server's reason did not travel: %+v", n, d)
		}
		if d := open.EvaluateTool(tool, p); !d.Allow {
			t.Errorf("%s with the gate open: %+v", n, d)
		}
		// The probe permission is infrastructure:write: a read-only operator
		// cannot originate traffic even with every switch on.
		ro := Principal{Tenant: "t-a", Perms: map[string]bool{"infrastructure:read": true}}
		if d := open.EvaluateTool(tool, ro); d.Allow {
			t.Errorf("%s ran for a read-only operator", n)
		}
	}
	w := capTool{name: "write_thing", cap: CapWrite}
	if d := open.EvaluateTool(w, p); d.Allow {
		t.Error("an open probe gate let a write through")
	}
}

// capTool is a minimal AITool of a chosen capability.
type capTool struct {
	name string
	cap  Capability
}

func (c capTool) Name() string            { return c.name }
func (c capTool) Module() string          { return "telemetry" }
func (c capTool) Capability() Capability  { return c.cap }
func (c capTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (c capTool) Freshness() Freshness    { return FreshnessLive }
func (c capTool) Run(context.Context, Principal, ToolArgs) (ToolResult, error) {
	return ToolResult{}, nil
}

// TestActiveProbesNeverReachAModel: gate 1 — no manifest lists an active probe,
// even with the gate open; gate 2 — a model-named call is refused at execution
// time even with the gate open, while the engine's own path runs it.
func TestActiveProbesNeverReachAModel(t *testing.T) {
	var calls []probeCall
	reg := probeRegistry(t, &calls)
	p := probePrincipal()
	open := NewPolicyEngine(PolicyConfig{NetProbes: NetProbeGate{Allow: true}}, flagsOn)

	for _, spec := range (Toolbox{Registry: reg, Policy: open}).Manifest(p) {
		switch spec.Name {
		case "run_ping", "run_traceroute", "run_dns_test", "run_http_test":
			t.Errorf("the model's manifest lists %s", spec.Name)
		}
	}

	model := Toolbox{Registry: reg, Policy: open, ModelDirected: true}
	for _, n := range activeProbeNames {
		iv := model.Invoke(context.Background(), p, n, ToolArgs{"target": "edge-1"})
		if iv.Outcome != OutcomePolicyDenied || !strings.Contains(iv.Decision.Reason, "a model cannot call it directly") {
			t.Errorf("model-named %s: outcome %s, reason %q", n, iv.Outcome, iv.Decision.Reason)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("a model-named probe reached the collector: %+v", calls)
	}

	engine := Toolbox{Registry: reg, Policy: open}
	iv := engine.Invoke(context.Background(), p, "run_ping", ToolArgs{"target": "edge-1"})
	if !iv.OK() {
		t.Fatalf("engine path: %s %v", iv.Outcome, iv.Err)
	}
	if len(calls) != 1 || calls[0].req.Kind != ProbePing || calls[0].req.Target != "edge-1" {
		t.Fatalf("engine path request: %+v", calls)
	}
	// A model-directed toolbox still runs ordinary read tools.
	if _, d, ok := model.Authorize("run_ping", p); !ok || d.Allow {
		t.Fatalf("Authorize on a model toolbox: ok=%v %+v", ok, d)
	}
}

// TestActiveProbeRateLimitPerWorkspace: the contract budget applies per tool
// per workspace — the seventh ping in a minute is refused, another workspace
// is not affected.
func TestActiveProbeRateLimitPerWorkspace(t *testing.T) {
	reg := probeRegistry(t, nil)
	open := NewPolicyEngine(PolicyConfig{NetProbes: NetProbeGate{Allow: true}}, flagsOn)
	gw := NewToolGateway()
	tb := Toolbox{Registry: reg, Policy: open, Gateway: gw}
	c, _ := ContractFor("run_ping")
	p := probePrincipal()
	for i := 0; i < c.RatePerMin; i++ {
		if iv := tb.Invoke(context.Background(), p, "run_ping", ToolArgs{"target": "edge-1"}); !iv.OK() {
			t.Fatalf("call %d: %s", i+1, iv.Outcome)
		}
	}
	if iv := tb.Invoke(context.Background(), p, "run_ping", ToolArgs{"target": "edge-1"}); iv.Outcome != OutcomeRateLimited {
		t.Fatalf("over budget: %s", iv.Outcome)
	}
	other := p
	other.Tenant = "t-b"
	if iv := tb.Invoke(context.Background(), other, "run_ping", ToolArgs{"target": "edge-1"}); !iv.OK() {
		t.Fatalf("another workspace shares the budget: %s", iv.Outcome)
	}
}

func TestActiveProbeContracts(t *testing.T) {
	for _, n := range activeProbeNames {
		c, ok := ContractFor(n)
		if !ok || c.Risk != CapNetProbe {
			t.Fatalf("%s contract: %+v %v", n, c, ok)
		}
		if c.RatePerMin > 6 {
			t.Errorf("%s allows %d per minute; an active probe budget stays small", n, c.RatePerMin)
		}
		if _, ok := toolMetas[n]; !ok {
			t.Errorf("%s has no declared arguments", n)
		}
		if ToolStatementClass(n) != ClassObserved {
			t.Errorf("%s is not OBSERVED evidence", n)
		}
		if !skillToolAllowlist[n] {
			t.Errorf("%s is not usable as a method step", n)
		}
	}
}

func TestActiveProbeArgs(t *testing.T) {
	if _, err := activeProbeRequestFromArgs(ProbePing, ToolArgs{}); err == nil {
		t.Error("a ping without a target was accepted")
	}
	if _, err := activeProbeRequestFromArgs(ProbeTraceroute, ToolArgs{"target": "  "}); err == nil {
		t.Error("a traceroute with a blank target was accepted")
	}
	if r, err := activeProbeRequestFromArgs(ProbeDNS, ToolArgs{}); err != nil || r.Target != "" {
		t.Errorf("a DNS test re-running the declared probes: %+v %v", r, err)
	}
	if r, err := activeProbeRequestFromArgs(ProbePing, ToolArgs{"device_id": "edge-1"}); err != nil || r.Target != "edge-1" {
		t.Errorf("device_id as the target: %+v %v", r, err)
	}
	if _, err := activeProbeRequestFromArgs(ProbeHTTP, ToolArgs{"target": strings.Repeat("x", 129)}); err == nil {
		t.Error("an oversized target was accepted")
	}
}

// TestRenderActiveProbe: the answer never carries an address, says when
// nothing ran and why, and summarises a traceroute without transit routers.
func TestRenderActiveProbe(t *testing.T) {
	rep := ActiveProbeReport{Kind: ProbeTraceroute, Scoped: true, Results: []ActiveProbeResult{{
		Target: "edge-1", TargetKind: "device",
		Hops: []ActiveProbeHop{{TTL: 1, Replied: true, RTTms: 1}, {TTL: 2, Replied: true, RTTms: 3}, {TTL: 3}, {TTL: 4}},
	}}}
	tr := RenderActiveProbe(rep)
	if len(tr.Items) != 1 || !strings.Contains(tr.Items[0].Text, "replies stop after hop 2") {
		t.Fatalf("trace: %+v", tr.Items)
	}
	if !strings.HasPrefix(tr.Items[0].CitationID, ActiveProbeCitationPrefix+"traceroute:") {
		t.Fatalf("citation id %q", tr.Items[0].CitationID)
	}
	joined := strings.Join(tr.Notes, " ")
	if !strings.Contains(joined, "ONE vantage") {
		t.Errorf("the notes do not say it is one vantage: %v", tr.Notes)
	}

	cases := []struct {
		rep  ActiveProbeReport
		want string
	}{
		{ActiveProbeReport{Kind: ProbePing, Scoped: true, Results: []ActiveProbeResult{{Target: "edge-1", Sent: 3, Received: 2, LossPct: 33.3, RTTms: 5}}}, "2 of 3 echoes answered"},
		{ActiveProbeReport{Kind: ProbePing, Scoped: true, Results: []ActiveProbeResult{{Target: "edge-1", Sent: 3}}}, "100% loss"},
		{ActiveProbeReport{Kind: ProbeDNS, Scoped: true, Results: []ActiveProbeResult{{Target: "corp-dns", FailClass: "nxdomain"}}}, "does not exist"},
		{ActiveProbeReport{Kind: ProbeDNS, Scoped: true, Results: []ActiveProbeResult{{Target: "corp-dns", Up: true, Answers: 2}}}, "resolved (2 addresses)"},
		{ActiveProbeReport{Kind: ProbeHTTP, Scoped: true, Results: []ActiveProbeResult{{Target: "portal", StatusCode: 302, Up: true}}}, "redirect was not followed"},
		{ActiveProbeReport{Kind: ProbeHTTP, Scoped: true, Results: []ActiveProbeResult{{Target: "portal", FailClass: "tls"}}}, "certificate did not verify"},
		{ActiveProbeReport{Kind: ProbeHTTP, Scoped: true, Results: []ActiveProbeResult{{Target: "portal", Refused: "it resolves to an internal address"}}}, "not sent"},
	}
	for _, c := range cases {
		got := RenderActiveProbe(c.rep)
		if len(got.Items) != 1 || !strings.Contains(got.Items[0].Text, c.want) {
			t.Errorf("%s: %+v, want %q", c.rep.Kind, got.Items, c.want)
		}
	}

	if got := RenderActiveProbe(ActiveProbeReport{Kind: ProbePing}); len(got.Items) != 0 || !strings.Contains(strings.Join(got.Notes, " "), "no single workspace") {
		t.Errorf("platform scope: %+v", got)
	}
	un := RenderActiveProbe(ActiveProbeReport{Kind: ProbePing, Scoped: true, Unavailable: "this collector cannot send ICMP"})
	if len(un.Items) != 0 || !strings.Contains(strings.Join(un.Notes, " "), "UNKNOWN") {
		t.Errorf("collector unavailable must be UNKNOWN, never healthy: %+v", un)
	}

	many := ActiveProbeReport{Kind: ProbeDNS, Scoped: true, TargetsTotal: 5}
	for i := 0; i < 5; i++ {
		many.Results = append(many.Results, ActiveProbeResult{Target: "p", Up: true, Answers: 1})
	}
	if got := RenderActiveProbe(many); len(got.Items) != maxActiveProbeTargets || !got.Truncated {
		t.Errorf("cap: %d items truncated=%v", len(got.Items), got.Truncated)
	}
}
