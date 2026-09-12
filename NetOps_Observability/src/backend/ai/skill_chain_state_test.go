// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_chain_state_test.go — the design's own acceptance fixture, now driven by
// LIVE STATE rather than by the engine's wording: "BGP is down because the link
// is down" must chain bgp-session-down → interface-down because the DEVICE
// ITSELF reported the peer Idle (IRIS Phase A4, model doc §3.2).
//
// The A2 fixture (skill_chain_test.go) proves the same hop from the engine's
// verdict phrase. This one proves it from a typed `show` field, with no verdict
// phrase in scope at all — which is the whole point of the show-first battery:
// the method no longer needs the engine to have already said the word "link".

import (
	"context"
	"strings"
	"testing"
)

// stateChainOrchestrator is chainOrchestrator with a DEVICE-STATE seam wired.
// report(area) shapes what the battery "read" for each area, so a test can put
// the device in a specific state and watch the deterministic rules move.
func stateChainOrchestrator(t *testing.T, llm LLMClient, report func(area string) DeviceStateReport) (*Orchestrator, *[]ToolAuditEntry) {
	t.Helper()
	o, audit := chainOrchestrator(t, llm)
	deps := o.Troubleshoot
	deps.DeviceState = func(_ context.Context, _ Principal, req DeviceStateRequest) (DeviceStateReport, error) {
		rep := report(req.Area)
		rep.DeviceID, rep.Area = req.DeviceID, req.Area
		rep.DeviceName = "edge-1"
		return rep, nil
	}
	o.Troubleshoot = deps
	o.Tools.AddTroubleshootTools(o.DS, deps)
	return o, audit
}

// bgpIdleState is a device whose BGP peer is Idle and whose uplink is down.
func bgpIdleState(area string) DeviceStateReport {
	switch area {
	case "bgp":
		return DeviceStateReport{
			Dialect: "cisco/ios_xe", Status: "ok", Collected: true,
			Rows: []StateRow{
				{Text: "BGP peer 10.0.0.1 — AS65001, state Idle", Signals: []string{"state:bgp_peer=idle"}},
			},
		}
	case "interfaces":
		return DeviceStateReport{
			Dialect: "cisco/ios_xe", Status: "ok", Collected: true,
			Rows: []StateRow{
				{Text: "interface GigabitEthernet0/0/1 — admin up, oper down, last flap 00:04:12", Signals: []string{"state:if_oper=down"}},
			},
		}
	default:
		return DeviceStateReport{Dialect: "cisco/ios_xe", Status: "ok", Collected: true}
	}
}

func TestChainStateDrivenHopBgpToInterfaceDown(t *testing.T) {
	o, audit := stateChainOrchestrator(t, MockLLM{Reply: "The peer is Idle and the uplink is down [verdict:pa]."}, bgpIdleState)
	sk, ok := o.Skills.Get("bgp-session-down")
	if !ok {
		t.Fatal("bgp-session-down must load")
	}
	// Deliberately NO link phrase in scope: problem "pa" carries the mock's
	// default wording, so the A2 verdict:phrase rule cannot be what fires.
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk, Reason: "matched bgp down"},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("the chained turn must be handled")
	}
	names := chainNames(ans)
	if len(names) < 2 || names[0] != "bgp-session-down" || names[1] != "interface-down" {
		t.Fatalf("chain = %v, want bgp-session-down → interface-down", names)
	}
	if ans.Chain[1].Selected != ChainSelectedRule {
		t.Fatalf("hop selection = %q, want %q — the state fact must drive it deterministically",
			ans.Chain[1].Selected, ChainSelectedRule)
	}
	if !strings.Contains(strings.ToLower(ans.Chain[1].Reason), "idle") {
		t.Errorf("the hop reason must name the state that caused it, got %q", ans.Chain[1].Reason)
	}
	// The state read is the FIRST thing the method did, and it is audited.
	if len(ans.Lookups) == 0 || ans.Lookups[0] != "get_device_state" {
		t.Fatalf("lookups = %v, want the state read first (never guess device state)", ans.Lookups)
	}
	first := ""
	for _, e := range *audit {
		if e.Tool != "next_skill" {
			first = e.Tool
			break
		}
	}
	if first != "get_device_state" {
		t.Fatalf("the first audited gather step was %q, want get_device_state", first)
	}
	// The typed row is in the bundle with a stable state citation.
	cited := false
	for _, c := range ans.Citations {
		if strings.HasPrefix(c.ID, "state:bgp:") {
			cited = true
		}
	}
	if !cited {
		t.Errorf("the typed state row must be citable: %+v", ans.Citations)
	}
	// The module the state read belongs to is named on the answer.
	if !containsSignal(ans.Modules, "device_state") {
		t.Errorf("modules = %v, want device_state named", ans.Modules)
	}
}

// The honest-gap hop: when live state CANNOT be read, the method must not carry
// on as if the device were healthy — it hands off to the logs.
func TestChainStateNotWiredHopsToLogConfirmation(t *testing.T) {
	unread := func(string) DeviceStateReport {
		return DeviceStateReport{
			Collected: false,
			NotWired:  "live device-state collection is not wired on this deployment — no command was run",
			Commands:  []DiagnosticCommand{{SpecID: "bgp-summary", Purpose: "BGP state", Command: "show ip bgp summary"}},
		}
	}
	o, _ := stateChainOrchestrator(t, MockLLM{Reply: "State could not be read [verdict:pa]."}, unread)
	sk, _ := o.Skills.Get("bgp-session-down")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	names := chainNames(ans)
	if len(names) < 2 || names[1] != "log-confirmation" {
		t.Fatalf("chain = %v, want the unread-state hop to log-confirmation", names)
	}
	if ans.Chain[1].Selected != ChainSelectedRule {
		t.Fatalf("hop selection = %q, want a deterministic rule", ans.Chain[1].Selected)
	}
	// The gap is structural, not left to the narrative.
	gaps := strings.ToLower(strings.Join(ans.MissingEvidence, " | "))
	if !strings.Contains(gaps, "not wired") && !strings.Contains(gaps, "unknown") {
		t.Errorf("the unread state must reach MissingEvidence: %v", ans.MissingEvidence)
	}
}

// A healthy read must NOT fire the state rules — a deterministic hop has to be
// caused by a fact, never by the tool merely having run.
func TestChainStateRuleDoesNotFireOnHealthyState(t *testing.T) {
	healthy := func(string) DeviceStateReport {
		return DeviceStateReport{
			Dialect: "cisco/ios_xe", Status: "ok", Collected: true,
			Rows: []StateRow{{Text: "BGP peer 10.0.0.1 — AS65001, state Established", Signals: []string{"state:bgp_peer=established"}}},
		}
	}
	o, _ := stateChainOrchestrator(t, MockLLM{Reply: "Everything reads normal [verdict:pa]."}, healthy)
	sk, _ := o.Skills.Get("bgp-session-down")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if got := chainNames(ans); len(got) != 1 || got[0] != "bgp-session-down" {
		t.Fatalf("chain = %v, want the single entry skill (no state fact justified a hop)", got)
	}
}
