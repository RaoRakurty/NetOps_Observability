package ai

// skill_state_condition_test.go — the `state:` half of the condition grammar
// (IRIS Phase A4). It is a BUILD GATE for the same reason the rest of the
// dialect is: a state rule that can never fire is a method that silently stops
// chaining, and a state fact that is not derived from a typed field is a guess.

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// stateDeclared is a tools: list that DOES read device state.
func stateDeclared() map[string]bool {
	return map[string]bool{"get_device_state": true, "get_rca_verdict": true}
}

func TestParseStateConditionAccepts(t *testing.T) {
	for facet, values := range skillStateFacets {
		for value := range values {
			raw := CondStatePrefix + facet + "=" + value
			c, err := parseSkillCondition(raw, stateDeclared())
			if err != nil {
				t.Fatalf("parseSkillCondition(%q): %v", raw, err)
			}
			if c.String() != raw {
				t.Fatalf("String() = %q, want %q", c.String(), raw)
			}
			if h := strings.TrimSpace(c.Human()); h == "" || h == raw {
				t.Errorf("%s must render operator-facing wording, got %q", raw, h)
			}
		}
	}
}

func TestParseStateConditionRejects(t *testing.T) {
	cases := []struct {
		name, raw string
		declared  map[string]bool
		want      string
	}{
		{"unknown facet", "state:if_colour=blue", stateDeclared(), "state facet"},
		{"value outside the facet's set", "state:if_oper=flapping", stateDeclared(), "state value"},
		{"a value from another facet", "state:bgp_peer=full", stateDeclared(), "state value"},
		{"empty facet", "state:=down", stateDeclared(), "state facet"},
		{"empty value", "state:if_oper=", stateDeclared(), "must be key=value"},
		{"the skill does not read state", "state:if_oper=down", condDeclared(), "needs get_device_state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSkillCondition(tc.raw, tc.declared)
			if err == nil {
				t.Fatalf("%q must fail the loader", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not explain the refusal (want %q)", err, tc.want)
			}
		})
	}
}

// The chain evaluator accepts only closed `state:` facts, and never takes one
// from anything but a tool's declared signal list.
func TestChainFactsAcceptOnlyClosedStateSignals(t *testing.T) {
	f := newChainFacts()
	f.addSignals([]string{
		"state:if_oper=down",
		"state:bgp_peer=idle",
		"state:collect=partial",
		"state:if_oper=sideways",                  // value outside the set
		"state:teleport=engaged",                  // facet outside the set",
		"state:if_oper",                           // not key=value
		"  state:route=absent  ",                  // whitespace is tolerated
		"stateroute=absent",                       // near-miss key
		"verdict:tier=fabricated",                 // wrong value for a real key
		strings.Repeat("state:if_oper=down ", 20), // over the per-signal length bound
	})
	got := make([]string, 0, len(f.states))
	for k := range f.states {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"bgp_peer=idle", "collect=partial", "if_oper=down", "route=absent"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("states = %v, want %v", got, want)
	}
	for _, tc := range []struct {
		cond SkillCondition
		want bool
	}{
		{SkillCondition{Key: "state:if_oper", Value: "down"}, true},
		{SkillCondition{Key: "state:if_oper", Value: "up"}, false},
		{SkillCondition{Key: "state:bgp_peer", Value: "idle"}, true},
		{SkillCondition{Key: "state:bgp_peer", Value: "established"}, false},
		{SkillCondition{Key: "state:platform", Value: "cpu_high"}, false},
	} {
		if got := f.holds(tc.cond); got != tc.want {
			t.Errorf("holds(%s) = %v, want %v", tc.cond, got, tc.want)
		}
	}
}

// A tool's signals cannot be spoofed into the OTHER fact families: the evaluator
// derives evidence kinds, notes and tool outcomes itself.
func TestStateSignalsCannotAssertOtherFacts(t *testing.T) {
	f := newChainFacts()
	f.addSignals([]string{"state:if_oper=down", "evidence:kind=metric", "note=capped", "tool:get_device_state=ok"})
	if f.kinds["metric"] || f.noteTokens["capped"] || f.toolOutcome["get_device_state"] != "" {
		t.Fatal("a tool must not be able to assert an evidence kind, a note token or its own outcome")
	}
	if !f.states["if_oper=down"] {
		t.Fatal("the legitimate state fact must still be recorded")
	}
}

// The embedded corpus must not carry a state rule a skill can never satisfy: a
// `state:` condition is only meaningful in a skill that gathers device state.
func TestEmbeddedSkillsStateRulesAreGatherable(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	found := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		gathersState := false
		for _, g := range sk.Gather {
			if g.Tool == "get_device_state" {
				gathersState = true
			}
		}
		for _, d := range sk.Decisions {
			if d.Cond == nil || !strings.HasPrefix(d.Cond.Key, CondStatePrefix) {
				continue
			}
			found++
			if !gathersState {
				t.Errorf("%s: authors %s but never gathers get_device_state — the rule could never fire", name, d.Cond)
			}
		}
	}
	if found == 0 {
		t.Fatal("no embedded skill uses the state grammar — Phase A4 would be unreachable from the methods")
	}
}

// Show-first: every skill that reads device state must read it in its FIRST
// couple of steps, and the RCA verdict is the only thing allowed to come first
// (the engine's conclusion is the documented starting point).
func TestEmbeddedSkillsGatherStateFirst(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		for i, g := range sk.Gather {
			if g.Tool != "get_device_state" {
				continue
			}
			if i > 1 {
				t.Errorf("%s gathers device state at step %d — show-first means step 1 (or step 2 behind get_rca_verdict)", name, i+1)
			}
			if i == 1 && sk.Gather[0].Tool != "get_rca_verdict" {
				t.Errorf("%s puts %q before the state read; only get_rca_verdict may precede it", name, sk.Gather[0].Tool)
			}
			if area := g.Args["area"]; !stateAreas[area] {
				t.Errorf("%s gathers device state for area %q, which is not in the closed vocabulary", name, area)
			}
		}
	}
}

// The osi-bisection entry method must read platform health when a device is in
// scope: a router that just reloaded reframes every symptom above it.
func TestOsiBisectionReadsPlatformState(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	sk, ok := set.Get("osi-bisection")
	if !ok {
		t.Fatal("osi-bisection must load")
	}
	for _, g := range sk.Gather {
		if g.Tool == "get_device_state" && g.Args["area"] == "platform" {
			if g.Bind["device_id"] != "device_id" {
				t.Fatalf("the state read must bind the SERVER-resolved device, got %+v", g.Bind)
			}
			return
		}
	}
	t.Fatal("osi-bisection must gather platform state")
}

// Plan-level proof that a state step is planned with its literal area and the
// server-resolved device — never with a model-supplied one.
func TestPlanGatherBindsStateArea(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{})
	sk, ok := loadTestSkills(t).Get("bgp-session-down")
	if !ok {
		t.Fatal("bgp-session-down must load")
	}
	ent := o.resolveSkillEntities(context.Background(), runPrincipal(), "bgp down on edge-1",
		map[string]string{"correlation_id": "pa", "device": "edge-1"})
	steps := planGather(sk, ent)
	if len(steps) == 0 || steps[0].Tool != "get_device_state" {
		t.Fatalf("the first planned step must be the state read, got %+v", steps)
	}
	if steps[0].Args["area"] != "bgp" || steps[0].Args["device_id"] != "dev-a" {
		t.Fatalf("state step args = %+v, want area=bgp and the resolved device id", steps[0].Args)
	}
}
