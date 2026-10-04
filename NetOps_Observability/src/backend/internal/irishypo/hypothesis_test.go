// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irishypo

// hypothesis_test.go — the state machine, the outcome rules and the engine
// guarantee (tracker 337 N-B3).

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// causeAssertion is what no text this package writes may contain: a sentence
// that names a cause as established. The engine's own block may DISCLAIM one
// ("has not identified a cause") — that is the opposite of asserting it.
var causeAssertion = regexp.MustCompile(`(?i)\b(caused by|because of|due to|root cause (is|was)|the cause (is|was)|is the cause|responsible for|culprit|led to|resulted in)\b`)

func facts(states ...string) Facts {
	f := Facts{States: map[string]bool{}, Signatures: map[string]bool{}, EnginePhrase: map[string]bool{}}
	for _, s := range states {
		f.States[s] = true
	}
	return f
}

// runOne proposes, tests and resolves the catalogue entry id through the real
// tracker, with the given tool outcome, facts and engine.
func runOne(t *testing.T, id, outcome string, f Facts, e Engine) Hypothesis {
	t.Helper()
	var def Definition
	for _, d := range Catalogue() {
		if d.ID == id {
			def = d
		}
	}
	if def.ID == "" {
		t.Fatalf("no catalogue entry %q", id)
	}
	tr := NewTracker(Wording{})
	tr.Enter(1, "some-method", def.Layers[0], []string{def.Tool})
	if outcome != "" {
		tr.Observe(1, "some-method", map[string]string{def.Tool: outcome}, map[string][]string{def.Tool: {"state:x:1", "state:x:2"}})
	}
	set := tr.Finish(f, e)
	if set == nil {
		t.Fatal("a proposed hypothesis must produce a set")
	}
	for _, h := range set.Hypotheses {
		if h.ID == id {
			return h
		}
	}
	t.Fatalf("hypothesis %q missing from %+v", id, set)
	return Hypothesis{}
}

func noEngine() Engine { return NewEngine("", "", "") }

// TestTransitionRules — each tool outcome / fact → the expected state, with no
// engine verdict in scope.
func TestTransitionRules(t *testing.T) {
	sig := func(ids ...string) Facts {
		f := facts()
		f.DiagCaptured = true
		for _, id := range ids {
			f.Signatures[id] = true
		}
		return f
	}
	uncollected := facts()
	uncollected.DiagUncollected = true
	cases := []struct {
		name, id, outcome string
		f                 Facts
		want              State
		wantFact          string
	}{
		{"tool not wired", "link-down", "not_wired", facts("if_oper=down"), Inconclusive, "tool:get_device_state=not_wired"},
		{"tool denied", "link-down", "denied", facts("if_oper=down"), Inconclusive, "tool:get_device_state=denied"},
		{"tool error", "link-down", "error", facts("if_oper=down"), Inconclusive, "tool:get_device_state=error"},
		{"tool not found", "bgp-session", "not_found", facts("bgp_peer=idle"), Inconclusive, "tool:get_device_state=not_found"},
		{"state unread", "link-down", "ok", facts("collect=not_wired"), Inconclusive, "state:collect=not_wired"},
		{"state timed out", "igp-adjacency", "ok", facts("collect=timed_out", "igp_nbr=not_full"), Inconclusive, "state:collect=timed_out"},
		{"link down", "link-down", "ok", facts("collect=ok", "if_oper=down"), Supported, "state:if_oper=down"},
		{"link admin down", "link-down", "ok", facts("if_oper=admin_down"), Supported, "state:if_oper=admin_down"},
		{"link up", "link-down", "ok", facts("if_oper=up"), Rejected, "state:if_oper=up"},
		{"errors present", "interface-errors", "ok", facts("if_errors=present"), Supported, "state:if_errors=present"},
		{"errors none", "interface-errors", "ok", facts("if_errors=none"), Rejected, "state:if_errors=none"},
		{"bgp idle", "bgp-session", "ok", facts("bgp_peer=idle"), Supported, "state:bgp_peer=idle"},
		{"bgp active", "bgp-session", "ok", facts("bgp_peer=active"), Supported, "state:bgp_peer=active"},
		{"bgp established", "bgp-session", "ok", facts("bgp_peer=established"), Rejected, "state:bgp_peer=established"},
		{"bgp no neighbour", "bgp-session", "ok", facts("bgp_peer=none"), Inconclusive, "state:bgp_peer=none"},
		{"igp not full", "igp-adjacency", "ok", facts("igp_nbr=not_full"), Supported, "state:igp_nbr=not_full"},
		{"igp full", "igp-adjacency", "ok", facts("igp_nbr=full"), Rejected, "state:igp_nbr=full"},
		{"cpu high", "control-plane-pressure", "ok", facts("platform=cpu_high"), Supported, "state:platform=cpu_high"},
		{"platform ok", "control-plane-pressure", "ok", facts("platform=ok"), Rejected, "state:platform=ok"},
		{"signature fired", "bgp-fault-signature", "ok", sig("bgp-idle-unreachable"), Supported, "signature=any"},
		{"no signature", "bgp-fault-signature", "ok", sig(), Rejected, "signature=none"},
		{"nothing captured", "igp-fault-signature", "ok", uncollected, Inconclusive, "signature=uncollected"},
		// Collection never ran here: "nothing matched" would be a lie.
		{"never captured", "bgp-fault-signature", "ok", facts(), Inconclusive, "signature=not_captured"},
		{"both ways", "link-down", "ok", facts("if_oper=down", "if_oper=up"), Inconclusive, "state:if_oper=down & state:if_oper=up"},
		{"silent read", "link-down", "ok", facts("collect=ok"), Inconclusive, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := runOne(t, c.id, c.outcome, c.f, noEngine())
			if h.State != c.want {
				t.Fatalf("state = %s, want %s (%+v)", h.State, c.want, h.Transitions)
			}
			last := h.Transitions[len(h.Transitions)-1]
			if last.Fact != c.wantFact {
				t.Errorf("deciding fact = %q, want %q", last.Fact, c.wantFact)
			}
			if strings.TrimSpace(last.Reason) == "" {
				t.Error("every transition carries a server-authored reason")
			}
			// The path is exactly PROPOSED → TESTING → final.
			if len(h.Transitions) != 3 || h.Transitions[0].To != Proposed || h.Transitions[1].To != Testing ||
				h.Transitions[1].From != Proposed || last.From != Testing {
				t.Errorf("path = %+v, want PROPOSED → TESTING → %s", h.Transitions, c.want)
			}
			if c.outcome == "ok" && len(h.Evidence) == 0 {
				t.Error("a tested hypothesis carries the citation ids its tool returned")
			}
		})
	}
}

func TestNeverTestedIsInconclusive(t *testing.T) {
	h := runOne(t, "link-down", "", facts("if_oper=down"), noEngine())
	if h.State != Inconclusive || len(h.Transitions) != 2 || h.Transitions[1].From != Proposed {
		t.Fatalf("an untested hypothesis must close INCONCLUSIVE straight from PROPOSED: %+v", h)
	}
	if !strings.Contains(h.Transitions[1].Reason, "never tested") {
		t.Errorf("reason must say it was never tested: %q", h.Transitions[1].Reason)
	}
}

// TestTransitionTableIsClosed — the only legal edges are the five the design
// names; every other pair, including leaving a terminal state, is refused.
func TestTransitionTableIsClosed(t *testing.T) {
	want := map[[2]State]bool{
		{Proposed, Testing}: true, {Proposed, Inconclusive}: true,
		{Testing, Supported}: true, {Testing, Rejected}: true, {Testing, Inconclusive}: true,
	}
	for _, from := range States {
		for _, to := range States {
			if got := Legal(from, to); got != want[[2]State{from, to}] {
				t.Errorf("Legal(%s, %s) = %v", from, to, got)
			}
		}
	}
	tr := NewTracker(Wording{})
	h := &Hypothesis{State: Supported}
	tr.move(h, Transition{To: Rejected})
	if h.State != Supported || len(h.Transitions) != 0 {
		t.Fatal("a terminal state must never move")
	}
}

// TestProposalIsScopedToWhatTheMethodCanTest — a hypothesis opens only for a
// method of its layer that PLANS its testing tool, and only once.
func TestProposalIsScopedToWhatTheMethodCanTest(t *testing.T) {
	tr := NewTracker(Wording{})
	tr.Enter(1, "bgp-session-down", "bgp", []string{"get_rca_verdict"}) // no state read planned
	if set := tr.Finish(facts(), noEngine()); set != nil {
		t.Fatalf("nothing testable was planned, nothing may open: %+v", set)
	}
	tr = NewTracker(Wording{})
	tr.Enter(1, "bgp-session-down", "bgp", []string{"get_device_state", "run_protocol_diagnostic"})
	tr.Enter(2, "bgp-prefix-missing", "bgp", []string{"get_device_state"})
	tr.Enter(3, "interface-down", "physical", []string{"get_device_state"})
	set := tr.Finish(facts(), noEngine())
	var ids []string
	for _, h := range set.Hypotheses {
		ids = append(ids, h.ID)
	}
	if got := strings.Join(ids, ","); got != "bgp-session,bgp-fault-signature,link-down,interface-errors" {
		t.Fatalf("opened %s", got)
	}
	if set.Hypotheses[0].Transitions[0].Skill != "bgp-session-down" {
		t.Error("a hypothesis is credited to the method that opened it")
	}
}

// TestOnlyTheRoundsOwnOutcomeMovesToTesting — a tool from ANOTHER round, or a
// tool the hypothesis is not tested by, never moves it.
func TestOnlyItsOwnToolMovesItToTesting(t *testing.T) {
	tr := NewTracker(Wording{})
	tr.Enter(1, "interface-down", "physical", []string{"get_device_state", "search_logs"})
	tr.Observe(1, "interface-down", map[string]string{"search_logs": "ok"}, nil)
	for _, h := range tr.items {
		if h.State != Proposed {
			t.Fatalf("%s moved on another tool's outcome: %s", h.ID, h.State)
		}
	}
	tr.Observe(1, "interface-down", map[string]string{"get_device_state": "ok"}, nil)
	for _, h := range tr.items {
		if h.State != Testing {
			t.Fatalf("%s did not move to TESTING on its own tool: %s", h.ID, h.State)
		}
	}
}

// TestContradictingHypothesisIsNeverSupported — the engine has a verdict that
// does not name this domain: the hypothesis can at most be INCONCLUSIVE, never
// passes through SUPPORTED, keeps its evidence, and its text never phrases it
// as a cause.
func TestContradictingHypothesisIsNeverSupported(t *testing.T) {
	for _, tier := range []string{"confirmed", "suspected", "candidate"} {
		t.Run(tier, func(t *testing.T) {
			f := facts("if_oper=down")
			f.EngineTier = tier
			f.EnginePhrase = map[string]bool{"cpu": true, "high": true, "leaf-2": true}
			e := NewEngine(tier, "P-1 — High CPU on leaf-2; verdict "+tier, "verdict:p1")
			h := runOne(t, "link-down", "ok", f, e)
			if h.State != Inconclusive {
				t.Fatalf("state = %s, want INCONCLUSIVE beside a verdict that names something else", h.State)
			}
			for _, tr := range h.Transitions {
				if tr.To == Supported {
					t.Fatalf("a contradicting hypothesis passed through SUPPORTED: %+v", h.Transitions)
				}
			}
			last := h.Transitions[len(h.Transitions)-1]
			if last.Fact != "verdict:tier="+tier {
				t.Errorf("the engine's verdict must be the deciding fact, got %q", last.Fact)
			}
			if !strings.Contains(last.Reason, "if_oper=down") && !strings.Contains(last.Reason, "down") {
				t.Errorf("the observation must stay visible in the reason: %q", last.Reason)
			}
			if len(h.Evidence) == 0 || h.EngineNote == "" {
				t.Errorf("the evidence and the engine note must be shown: %+v", h)
			}
			for _, s := range hypothesisText(h) {
				if causeAssertion.MatchString(s) {
					t.Errorf("phrased as a cause: %q", s)
				}
			}
		})
	}
}

// When the engine's verdict DOES name the domain, a supported hypothesis
// stands — as consistent with the engine, which still owns the cause.
func TestAlignedHypothesisIsSupportedBesideTheEngine(t *testing.T) {
	f := facts("bgp_peer=idle")
	f.EngineTier = "confirmed"
	f.EnginePhrase = map[string]bool{"bgp": true, "peer": true, "down": true}
	h := runOne(t, "bgp-session", "ok", f, NewEngine("confirmed", "BGP peer down on edge-1", "verdict:pa"))
	if h.State != Supported {
		t.Fatalf("state = %s", h.State)
	}
	if !strings.Contains(h.EngineNote, "engine") || !strings.Contains(h.EngineNote, "alone names the cause") {
		t.Errorf("a supported hypothesis must defer to the engine: %q", h.EngineNote)
	}
}

// An engine that REFUSED a verdict (undetermined) or produced none: the
// observation may be supported, but it is labelled an observation, not a
// cause, and nothing anywhere in the set asserts one.
func TestNoEngineVerdictMeansObservationsOnly(t *testing.T) {
	for _, tier := range []string{"", "undetermined", "bogus"} {
		f := facts("if_oper=down")
		f.EngineTier = tier
		e := NewEngine(tier, "P-9 — link flap on edge-1", "verdict:p9")
		tr := NewTracker(Wording{})
		tr.Enter(1, "interface-down", "physical", []string{"get_device_state"})
		tr.Observe(1, "interface-down", map[string]string{"get_device_state": "ok"}, nil)
		set := tr.Finish(f, e)
		if set.Engine.HasVerdict() {
			t.Fatalf("tier %q is not a verdict", tier)
		}
		if tier != "undetermined" && set.Engine.Statement != "" {
			t.Errorf("with no verdict in scope the engine block carries no statement: %+v", set.Engine)
		}
		if !strings.Contains(set.Engine.Note, "Iris does not name") {
			t.Errorf("the engine note must say Iris does not name a cause: %q", set.Engine.Note)
		}
		for _, h := range set.Hypotheses {
			if h.State == Supported && !strings.Contains(h.EngineNote, "not a cause") {
				t.Errorf("%s supported without the observation label: %q", h.ID, h.EngineNote)
			}
		}
		for _, s := range setText(*set) {
			if causeAssertion.MatchString(s) {
				t.Errorf("tier %q: cause asserted in %q", tier, s)
			}
		}
		if !strings.Contains(set.Notice, "Only the correlation engine names a root cause") {
			t.Errorf("every set carries the notice: %q", set.Notice)
		}
	}
}

// TestNoTextAssertsACause — every catalogue statement and every sentence any
// path of the state machine can write is free of cause language.
func TestNoTextAssertsACause(t *testing.T) {
	ids := map[string]bool{}
	for _, d := range Catalogue() {
		if ids[d.ID] {
			t.Errorf("duplicate id %q", d.ID)
		}
		ids[d.ID] = true
		if causeAssertion.MatchString(d.Statement) || strings.Contains(strings.ToLower(d.Statement), "cause") {
			t.Errorf("%s statement names a cause: %q", d.ID, d.Statement)
		}
		if d.Tool == "" || len(d.Layers) == 0 || len(d.Support) == 0 || len(d.Reject) == 0 || len(d.EngineTerms) == 0 {
			t.Errorf("%s is incomplete: %+v", d.ID, d)
		}
	}
	for _, tier := range []string{"", "undetermined", "candidate", "suspected", "confirmed"} {
		for _, outcome := range []string{"", "ok", "error", "denied", "not_wired", "not_found"} {
			for _, st := range []string{"if_oper=down", "if_oper=up", "collect=failed", "bgp_peer=idle", "platform=cpu_high"} {
				f := facts(st)
				f.EngineTier = tier
				tr := NewTracker(Wording{})
				for _, d := range Catalogue() {
					tr.Enter(1, "m", d.Layers[0], []string{d.Tool})
				}
				if outcome != "" {
					tr.Observe(1, "m", map[string]string{"get_device_state": outcome, "run_protocol_diagnostic": outcome}, nil)
				}
				set := tr.Finish(f, NewEngine(tier, "", ""))
				for _, s := range setText(*set) {
					if causeAssertion.MatchString(s) {
						t.Errorf("tier=%q outcome=%q %s: %q", tier, outcome, st, s)
					}
				}
			}
		}
	}
}

func TestFinishIsNilSafeAndBounded(t *testing.T) {
	var tr *Tracker
	tr.Enter(1, "m", "bgp", []string{"get_device_state"})
	tr.Observe(1, "m", nil, nil)
	if tr.Finish(facts(), noEngine()) != nil {
		t.Fatal("a nil tracker yields no set")
	}
	defs := make([]Definition, 0, MaxHypotheses+5)
	for i := 0; i < MaxHypotheses+5; i++ {
		d := Catalogue()[0]
		d.ID = d.ID + "-" + string(rune('a'+i))
		defs = append(defs, d)
	}
	big := newTracker(defs, Wording{})
	big.Enter(1, "m", "physical", []string{"get_device_state"})
	if len(big.items) != MaxHypotheses {
		t.Fatalf("held %d hypotheses, bound is %d", len(big.items), MaxHypotheses)
	}
	long := NewEngine("confirmed", strings.Repeat("é", 400), "verdict:x")
	if len(long.Statement) > maxEngineStatement+len("…") {
		t.Errorf("engine statement not bounded: %d bytes", len(long.Statement))
	}
}

// The JSON a client receives names the states in the closed vocabulary.
func TestSetJSONShape(t *testing.T) {
	h := runOne(t, "bgp-session", "ok", facts("bgp_peer=idle"), noEngine())
	b, err := json.Marshal(Set{Notice: Notice, Engine: noEngine(), Hypotheses: []Hypothesis{h}})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	hs := back["hypotheses"].([]any)
	got := hs[0].(map[string]any)
	if got["state"] != "SUPPORTED" || got["id"] != "bgp-session" {
		t.Fatalf("json = %s", b)
	}
	trs := got["transitions"].([]any)
	if trs[0].(map[string]any)["to"] != "PROPOSED" {
		t.Fatalf("transitions json = %s", b)
	}
}

func hypothesisText(h Hypothesis) []string {
	out := []string{h.Statement, h.EngineNote}
	for _, tr := range h.Transitions {
		out = append(out, tr.Reason)
	}
	return out
}

func setText(s Set) []string {
	out := []string{s.Notice, s.Engine.Note}
	for _, h := range s.Hypotheses {
		out = append(out, hypothesisText(h)...)
	}
	return out
}
