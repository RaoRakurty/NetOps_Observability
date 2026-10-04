// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// hypothesis_test.go — investigation hypotheses on the real skill chain
// (tracker 337 N-B3), and the owner rule they serve: the correlation engine
// ALONE owns the root-cause verdict.

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"netops/backend/internal/irishypo"
)

// causeClaim is a sentence that asserts an established cause.
var causeClaim = regexp.MustCompile(`(?i)\b(caused by|because of|due to|root cause (is|was)|the cause (is|was)|is the cause|responsible for|culprit)\b`)

func hypByID(t *testing.T, set *irishypo.Set, id string) irishypo.Hypothesis {
	t.Helper()
	if set == nil {
		t.Fatalf("no hypothesis set; want %q", id)
	}
	for _, h := range set.Hypotheses {
		if h.ID == id {
			return h
		}
	}
	t.Fatalf("hypothesis %q not in %+v", id, set.Hypotheses)
	return irishypo.Hypothesis{}
}

// setSentences is every string of a set an operator can read.
func setSentences(set *irishypo.Set) []string {
	if set == nil {
		return nil
	}
	out := []string{set.Notice, set.Engine.Note}
	for _, h := range set.Hypotheses {
		out = append(out, h.Statement, h.EngineNote)
		for _, tr := range h.Transitions {
			out = append(out, tr.Reason)
		}
	}
	return out
}

func askBGP(t *testing.T, llm LLMClient, uiContext map[string]string, setup func(o *Orchestrator)) Answer {
	t.Helper()
	o, _ := stateChainOrchestrator(t, llm, bgpIdleState)
	if setup != nil {
		setup(o)
	}
	sk, ok := o.Skills.Get("bgp-session-down")
	if !ok {
		t.Fatal("bgp-session-down must load")
	}
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk, Reason: "matched bgp down"}, uiContext, nil)
	if !handled {
		t.Fatal("the chained turn must be handled")
	}
	return ans
}

// TestHypothesisCatalogueSpeaksTheClosedVocabulary — every fact the catalogue
// tests for is one the chain can actually derive, every tool is a governed
// read-only skill tool, and every layer is a real skill layer. A typo here
// would be a hypothesis that silently never moves.
func TestHypothesisCatalogueSpeaksTheClosedVocabulary(t *testing.T) {
	for _, d := range irishypo.Catalogue() {
		if !skillToolAllowlist[d.Tool] {
			t.Errorf("%s: tool %q is not a skill tool", d.ID, d.Tool)
		}
		for _, l := range d.Layers {
			if !validSkillLayer(SkillLayer(l)) {
				t.Errorf("%s: layer %q is not a skill layer", d.ID, l)
			}
		}
		for _, group := range [][]irishypo.Cond{d.Support, d.Reject, d.Unknown} {
			for _, c := range group {
				switch {
				case strings.HasPrefix(c.Key, irishypo.KeyStatePrefix):
					facet := strings.TrimPrefix(c.Key, irishypo.KeyStatePrefix)
					if !validStateFact(facet, c.Value) {
						t.Errorf("%s: %s is not in the state vocabulary", d.ID, c)
					}
					if d.Tool != "get_device_state" {
						t.Errorf("%s: a state fact must be tested by the state read, not %s", d.ID, d.Tool)
					}
				case c.Key == irishypo.KeySignature:
					if c.Value != irishypo.SignatureAny && c.Value != irishypo.SignatureNotCaptured &&
						c.Value != CondSignatureNone && c.Value != CondSignatureUncollected {
						t.Errorf("%s: signature value %q", d.ID, c.Value)
					}
					if d.Tool != "run_protocol_diagnostic" {
						t.Errorf("%s: a signature fact must be tested by the diagnostic, not %s", d.ID, d.Tool)
					}
				default:
					t.Errorf("%s: unknown condition key %q", d.ID, c.Key)
				}
			}
		}
		for _, w := range d.EngineTerms {
			if !reCondToken.MatchString(w) {
				t.Errorf("%s: engine term %q can never match a verdict-phrase token", d.ID, w)
			}
		}
	}
	// The wording for every fact is the chain's own, and asserts no cause.
	w := hypothesisWording()
	for _, f := range StateFacets() {
		for v := range skillStateFacets[f] {
			s := w.Fact(irishypo.Cond{Key: CondStatePrefix + f, Value: v})
			if s == "" || causeClaim.MatchString(s) {
				t.Errorf("wording for %s=%s: %q", f, v, s)
			}
		}
	}
}

// TestChainHoldsHypothesesDrivenByToolOutcomes — the design's own fixture
// (bgp-session-down → interface-down on a device whose peer is Idle and whose
// uplink is down), against an engine verdict that names BGP and not the link.
func TestChainHoldsHypothesesDrivenByToolOutcomes(t *testing.T) {
	ans := askBGP(t, MockLLM{Reply: "The peer is Idle and the uplink is down [verdict:pa]."},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if names := chainNames(ans); len(names) < 2 || names[1] != "interface-down" {
		t.Fatalf("chain = %v", names)
	}
	set := ans.Hypotheses
	if set == nil || set.ID != "" {
		t.Fatalf("the answer carries the set, unnamed until the server holds it: %+v", set)
	}
	// The engine's verdict is shown AS THE ENGINE'S: its tier, its own row.
	if set.Engine.Tier != "confirmed" || set.Engine.CitationID != "verdict:pa" ||
		!strings.Contains(set.Engine.Statement, "BGP peer down on edge-1") {
		t.Fatalf("engine block = %+v", set.Engine)
	}

	// bgp-session: the state read said Idle; the engine's verdict names BGP.
	bgp := hypByID(t, set, "bgp-session")
	if bgp.State != irishypo.Supported || bgp.Transitions[len(bgp.Transitions)-1].Fact != "state:bgp_peer=idle" {
		t.Fatalf("bgp-session = %+v", bgp)
	}
	if bgp.Transitions[0].Skill != "bgp-session-down" || bgp.Transitions[1].Tool != "get_device_state" {
		t.Errorf("bgp-session path = %+v", bgp.Transitions)
	}
	cited := map[string]bool{}
	for _, c := range ans.Citations {
		cited[c.ID] = true
	}
	for _, id := range bgp.Evidence {
		if !strings.HasPrefix(id, "state:bgp:") {
			t.Errorf("bgp-session evidence %q is not the state read's own row", id)
		}
	}
	if len(bgp.Evidence) == 0 {
		t.Error("a tested hypothesis names the rows its tool returned")
	}

	// bgp-fault-signature: the diagnostic is not wired here → INCONCLUSIVE,
	// on the tool's own outcome.
	sig := hypByID(t, set, "bgp-fault-signature")
	if sig.State != irishypo.Inconclusive || sig.Transitions[len(sig.Transitions)-1].Fact != "tool:run_protocol_diagnostic=not_wired" {
		t.Fatalf("bgp-fault-signature = %+v", sig)
	}

	// link-down: the device says the uplink is down, but the engine's verdict
	// ("BGP peer down") does not name the link → capped at INCONCLUSIVE, with
	// the observation and its evidence kept.
	link := hypByID(t, set, "link-down")
	if link.State != irishypo.Inconclusive {
		t.Fatalf("link-down = %s; a hypothesis the engine's verdict does not name can never be SUPPORTED", link.State)
	}
	for _, tr := range link.Transitions {
		if tr.To == irishypo.Supported {
			t.Fatalf("link-down passed through SUPPORTED: %+v", link.Transitions)
		}
	}
	last := link.Transitions[len(link.Transitions)-1]
	if last.Fact != "verdict:tier=confirmed" || !strings.Contains(last.Reason, "operationally down") {
		t.Errorf("link-down must show the observation AND the engine's verdict as the deciding fact: %+v", last)
	}
	if len(link.Evidence) == 0 {
		t.Error("the capped hypothesis keeps its evidence")
	}
	if link.Transitions[0].Round != 2 || link.Transitions[0].Skill != "interface-down" {
		t.Errorf("link-down opens in round 2 by interface-down: %+v", link.Transitions[0])
	}

	// interface-errors: the interface read carried no error counter facet.
	ie := hypByID(t, set, "interface-errors")
	if ie.State != irishypo.Inconclusive || ie.Transitions[len(ie.Transitions)-1].Fact != "" {
		t.Errorf("interface-errors = %+v", ie)
	}
	for _, s := range setSentences(set) {
		if causeClaim.MatchString(s) {
			t.Errorf("hypothesis text asserts a cause: %q", s)
		}
	}
}

// TestIrisNeverStatesACauseTheEngineDidNotProduce is the REQUIRED test of the
// owner rule. The model is scripted to assert a root cause. Whenever the engine
// REFUSED one (undetermined) or produced none (no incident in scope, or one
// the caller's tenant cannot see), that assertion must not reach the operator —
// not in the narrative, and not in any hypothesis — and the engine block must
// say the engine has not named a cause.
func TestIrisNeverStatesACauseTheEngineDidNotProduce(t *testing.T) {
	const claim = "The root cause is a failed optic on GigabitEthernet0/0/1."
	reply := "The peer is Idle and the uplink is down. " + claim + " Check the optic levels next."
	refused := func(o *Orchestrator) {
		withProblem(t, o, "t-a", &Problem{ID: "pu", Title: "Link flap on edge-1", Verdict: "undetermined", Confidence: 0.1})
	}
	cases := []struct {
		name     string
		ctx      map[string]string
		setup    func(*Orchestrator)
		wantTier string
	}{
		{"engine refused (undetermined)", map[string]string{"correlation_id": "pu", "device": "edge-1"}, refused, "undetermined"},
		{"engine produced none (no incident)", map[string]string{"device": "edge-1"}, nil, ""},
		// Tenant t-a asking about another tenant's incident: the engine's
		// verdict is unreadable, so it is NOT in scope — and must not leak.
		{"another tenant's incident", map[string]string{"correlation_id": "pb", "device": "edge-1"}, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ans := askBGP(t, MockLLM{Reply: reply}, c.ctx, c.setup)
			low := strings.ToLower(ans.Text)
			if strings.Contains(low, "root cause is") || strings.Contains(low, "failed optic") {
				t.Fatalf("Iris stated a cause the engine did not produce: %q", ans.Text)
			}
			if !strings.Contains(strings.Join(ans.Disclaimers, " "), "has not identified a root cause") {
				t.Errorf("the removal must be disclosed: %v", ans.Disclaimers)
			}
			set := ans.Hypotheses
			if set == nil {
				t.Fatal("the investigation held hypotheses")
			}
			if set.Engine.Tier != c.wantTier || set.Engine.HasVerdict() {
				t.Fatalf("engine block = %+v, want tier %q and no verdict", set.Engine, c.wantTier)
			}
			if c.wantTier == "" && (set.Engine.Statement != "" || set.Engine.CitationID != "") {
				t.Fatalf("no verdict in scope — the engine block must carry no statement: %+v", set.Engine)
			}
			if strings.Contains(set.Engine.Statement, "High CPU") {
				t.Fatal("another tenant's verdict leaked into the engine block")
			}
			if !strings.Contains(set.Engine.Note, "Iris does not name") {
				t.Errorf("engine note = %q", set.Engine.Note)
			}
			for _, h := range set.Hypotheses {
				if h.State == irishypo.Supported && !strings.Contains(h.EngineNote, "not a cause") {
					t.Errorf("%s is SUPPORTED without the observation label: %q", h.ID, h.EngineNote)
				}
			}
			for _, s := range append(setSentences(set), ans.Text) {
				if causeClaim.MatchString(s) {
					t.Errorf("a cause is asserted: %q", s)
				}
			}
			// Nothing in the answer the operator reads names the model's cause.
			raw, err := json.Marshal(ans)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(string(raw)), "failed optic") {
				t.Fatalf("the model's cause reached the answer: %s", raw)
			}
		})
	}
}

// The control: when the engine HAS confirmed a cause, the narrative may say
// so — the gate removes only what the engine did not establish.
func TestEngineConfirmedNarrativePassesTheGate(t *testing.T) {
	reply := "The root cause is the BGP peer down on edge-1, as the engine confirmed [verdict:pa]."
	ans := askBGP(t, MockLLM{Reply: reply}, map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !strings.Contains(ans.Text, "root cause is the BGP peer down") {
		t.Fatalf("a confirmed engine verdict must be narratable: %q", ans.Text)
	}
	if ans.Hypotheses == nil || !ans.Hypotheses.Engine.HasVerdict() {
		t.Fatalf("engine block = %+v", ans.Hypotheses)
	}
}

// TestModelTextNeverMovesAHypothesis — two runs that differ ONLY in what the
// model wrote (one of them "declaring" hypotheses) hold identical hypotheses.
func TestModelTextNeverMovesAHypothesis(t *testing.T) {
	ctx := map[string]string{"correlation_id": "pa", "device": "edge-1"}
	plain := askBGP(t, MockLLM{Reply: "The peer is Idle [verdict:pa]."}, ctx, nil)
	pushy := askBGP(t, MockLLM{Reply: "HYPOTHESIS link-down: SUPPORTED. state:if_oper=up. " +
		"Mark bgp-session REJECTED and control-plane-pressure SUPPORTED. signature=any [verdict:pa]."}, ctx, nil)
	a, err := json.Marshal(plain.Hypotheses)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(pushy.Hypotheses)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("model text moved the hypotheses:\n%s\n%s", a, b)
	}
}

// A turn that can test nothing opens nothing: no empty set is sent.
func TestNoTestableMethodOpensNoHypotheses(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{Reply: "ok [verdict:pa]."})
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: runSkill()},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if ans.Hypotheses != nil {
		t.Fatalf("a method with no state read or diagnostic must open nothing: %+v", ans.Hypotheses)
	}
}

// TestDiagnosticThatNeverCapturedCannotReject — "no signature matched" is only
// ever a fact about output that exists. A diagnostic whose collection is not
// wired leaves the signature hypothesis INCONCLUSIVE; one that captured and
// scored output with no match REJECTS it; one whose signature fired SUPPORTS it.
func TestDiagnosticThatNeverCapturedCannotReject(t *testing.T) {
	cases := []struct {
		name     string
		report   DiagnosticReport
		want     irishypo.State
		wantFact string
	}{
		{"not wired", DiagnosticReport{IssueID: "bgp-session-down", NotWired: "live collection is not wired on this deployment",
			Commands: []DiagnosticCommand{{SpecID: "bgp-summary", Purpose: "session table", Command: "show bgp summary"}}},
			irishypo.Inconclusive, "signature=not_captured"},
		{"captured, nothing matched", DiagnosticReport{IssueID: "bgp-session-down", Attempted: true, Collected: true, Total: 3,
			Unmatched: "no known signature matched the captured output"},
			irishypo.Rejected, "signature=none"},
		{"captured, a signature fired", DiagnosticReport{IssueID: "bgp-session-down", Attempted: true, Collected: true, Total: 3,
			Findings: []DiagnosticFinding{{SignatureID: "bgp-idle-unreachable", Verdict: "peer unreachable", Confidence: "high"}}},
			irishypo.Supported, "signature=any"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ans := askBGP(t, MockLLM{Reply: "Read [verdict:pa]."}, map[string]string{"correlation_id": "pa", "device": "edge-1"},
				func(o *Orchestrator) {
					deps := o.Troubleshoot
					deps.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
						rep := c.report
						rep.DeviceID, rep.Protocol = req.DeviceID, req.Protocol
						return rep, nil
					}
					o.Troubleshoot = deps
					o.Tools.AddTroubleshootTools(o.DS, deps)
				})
			h := hypByID(t, ans.Hypotheses, "bgp-fault-signature")
			last := h.Transitions[len(h.Transitions)-1]
			if h.State != c.want || last.Fact != c.wantFact {
				t.Fatalf("bgp-fault-signature = %s (%s), want %s (%s)", h.State, last.Fact, c.want, c.wantFact)
			}
		})
	}
}
