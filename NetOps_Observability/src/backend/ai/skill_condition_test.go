// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_condition_test.go — the A2 CONDITION GRAMMAR is a build gate, exactly as
// the rest of the skill dialect is. A `next=` line that carries a mistyped key,
// an outcome outside the closed vocabulary, or a tool the skill never declared
// must FAIL THE LOADER: a condition that can never fire is a method that
// silently stops chaining, which is indistinguishable at runtime from a method
// that decided not to.

import (
	"strconv"
	"strings"
	"testing"
)

// condDeclared is the tools: list the condition tests validate against.
func condDeclared() map[string]bool {
	return map[string]bool{"run_protocol_diagnostic": true, "get_rca_verdict": true}
}

func TestParseSkillConditionAccepts(t *testing.T) {
	cases := []struct {
		raw       string
		wantKey   string
		wantValue string
	}{
		{"signature=bgp-idle-unreachable", CondSignature, "bgp-idle-unreachable"},
		{"signature=none", CondSignature, CondSignatureNone},
		{"evidence:kind=metric", CondEvidenceKind, "metric"},
		{"evidence:kind=log", CondEvidenceKind, "log"},
		{"verdict:tier=undetermined", CondVerdictTier, "undetermined"},
		{"verdict:phrase=link", CondVerdictPhrase, "link"},
		{"note=capped", CondNote, "capped"},
		{"tool:run_protocol_diagnostic=ok", CondToolPrefix + "run_protocol_diagnostic", "ok"},
		{"tool:run_protocol_diagnostic=not_wired", CondToolPrefix + "run_protocol_diagnostic", "not_wired"},
		{"tool:get_rca_verdict=not_found", CondToolPrefix + "get_rca_verdict", "not_found"},
		{"tool:get_rca_verdict=denied", CondToolPrefix + "get_rca_verdict", "denied"},
		{"tool:get_rca_verdict=error", CondToolPrefix + "get_rca_verdict", "error"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			c, err := parseSkillCondition(tc.raw, condDeclared())
			if err != nil {
				t.Fatalf("parseSkillCondition(%q): %v", tc.raw, err)
			}
			if c.Key != tc.wantKey || c.Value != tc.wantValue {
				t.Fatalf("= %+v, want %s=%s", c, tc.wantKey, tc.wantValue)
			}
			if c.String() != tc.raw {
				t.Errorf("String() = %q, want the authored form %q", c.String(), tc.raw)
			}
			if strings.TrimSpace(c.Human()) == "" {
				t.Error("every condition must render an operator-facing reason")
			}
		})
	}
}

func TestParseSkillConditionRejects(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"unknown key", "metric:trend=rising", "condition key"},
		{"unknown namespaced key", "verdict:title=link", "condition key"},
		{"no value", "signature=", "key=value"},
		{"no key", "=none", "key=value"},
		{"not a pair at all", "the link is down", "key=value"},
		{"unknown evidence kind", "evidence:kind=laser", "evidence kind"},
		{"unknown verdict tier", "verdict:tier=probably", "verdict tier"},
		{"uppercase phrase token", "verdict:phrase=Link", "token"},
		{"one-character note token", "note=x", "token"},
		{"note token with a space", "note=not wired", "token"},
		{"tool off the allowlist", "tool:reboot_device=ok", "allowlist"},
		{"tool the skill never declared", "tool:search_logs=ok", "tools: list"},
		{"outcome outside the vocabulary", "tool:run_protocol_diagnostic=collected", "tool outcome"},
		{"signature id with a space", "signature=bgp idle", "signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseSkillCondition(tc.raw, condDeclared())
			if err == nil {
				t.Fatalf("parseSkillCondition(%q) accepted %+v; it must be a load error", tc.raw, c)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The loader is the gate: a condition only reaches the runtime through a skill.
func TestParseSkillDecisionConditions(t *testing.T) {
	withDecision := func(line string) string {
		return strings.Replace(goodSkill, "  - verdict=name the peer and its state",
			line+"\n  - verdict=name the peer and its state", 1)
	}

	t.Run("a machine condition is parsed and keeps the human tail", func(t *testing.T) {
		sk, err := parseSkill("unit-probe", withDecision(
			"  - next=log-confirmation when signature=none the diagnostic ran and matched nothing"))
		if err != nil {
			t.Fatalf("parseSkill: %v", err)
		}
		d := sk.Decisions[0]
		if d.Kind != DecisionNext || d.Target != "log-confirmation" {
			t.Fatalf("decision = %+v", d)
		}
		if d.Cond == nil || d.Cond.Key != CondSignature || d.Cond.Value != CondSignatureNone {
			t.Fatalf("condition = %+v, want signature=none", d.Cond)
		}
		if d.Reason != "the diagnostic ran and matched nothing" {
			t.Errorf("human reason = %q", d.Reason)
		}
	})

	t.Run("a condition with no human tail renders one", func(t *testing.T) {
		sk, err := parseSkill("unit-probe", withDecision("  - next=log-confirmation when verdict:tier=undetermined"))
		if err != nil {
			t.Fatalf("parseSkill: %v", err)
		}
		if got := sk.Decisions[0].Reason; got != "the RCA verdict is undetermined" {
			t.Errorf("generated reason = %q", got)
		}
	})

	t.Run("a free-text reason stays valid and carries NO machine condition", func(t *testing.T) {
		sk, err := parseSkill("unit-probe", withDecision("  - next=interface-down when the link beneath it is down"))
		if err != nil {
			t.Fatalf("parseSkill: %v", err)
		}
		d := sk.Decisions[0]
		if d.Cond != nil {
			t.Fatalf("free text must not become a condition: %+v", d.Cond)
		}
		if d.Reason != "the link beneath it is down" {
			t.Errorf("reason = %q", d.Reason)
		}
	})

	t.Run("a mistyped condition key fails the load", func(t *testing.T) {
		_, err := parseSkill("unit-probe", withDecision("  - next=log-confirmation when signatures=bgp-idle-unreachable"))
		if err == nil || !strings.Contains(err.Error(), "condition key") {
			t.Fatalf("want a condition-key load error, got %v", err)
		}
	})

	t.Run("a condition on a tool the skill does not gather fails the load", func(t *testing.T) {
		_, err := parseSkill("unit-probe", withDecision("  - next=log-confirmation when tool:search_logs=ok"))
		if err == nil || !strings.Contains(err.Error(), "tools: list") {
			t.Fatalf("want an undeclared-tool load error, got %v", err)
		}
	})
}

// The embedded corpus must satisfy the grammar AND actually carry the
// deterministic hops A2 exists for. A skill set where every next= is free text
// would load fine and never chain deterministically.
func TestEmbeddedSkillConditions(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	declaredOf := func(sk *Skill) map[string]bool {
		out := map[string]bool{}
		for _, tl := range sk.Tools {
			out[tl] = true
		}
		return out
	}
	conditioned := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		for _, d := range sk.Decisions {
			if d.Cond == nil {
				continue
			}
			conditioned++
			if d.Kind != DecisionNext {
				t.Errorf("%s: only a next= decision may carry a condition (%+v)", name, d)
			}
			// Re-parse the authored form: the corpus must satisfy the same
			// grammar the loader enforces, with no drift.
			if _, perr := parseSkillCondition(d.Cond.String(), declaredOf(sk)); perr != nil {
				t.Errorf("%s: condition %q does not re-parse: %v", name, d.Cond, perr)
			}
			if strings.TrimSpace(d.Reason) == "" {
				t.Errorf("%s: conditioned hop to %s has no operator-facing reason", name, d.Target)
			}
		}
	}
	if conditioned < 10 {
		t.Fatalf("only %d authored machine conditions in the corpus — A2 needs the deterministic hops", conditioned)
	}

	// The chain the design names explicitly: a BGP session whose carrying link is
	// implicated must reach interface-down deterministically.
	bgp, ok := set.Get("bgp-session-down")
	if !ok {
		t.Fatal("bgp-session-down must load")
	}
	var toIface []string
	for _, d := range bgp.Decisions {
		if d.Kind == DecisionNext && d.Target == "interface-down" && d.Cond != nil {
			toIface = append(toIface, d.Cond.String())
		}
	}
	if len(toIface) == 0 {
		t.Fatal("bgp-session-down must carry at least one MACHINE condition onto interface-down")
	}
}

// ---- fact evaluation -------------------------------------------------------

func TestChainFactsHolds(t *testing.T) {
	f := newChainFacts()
	f.addSignals([]string{
		"signature=bgp-idle-unreachable",
		"verdict:tier=confirmed",
		"verdict:phrase=link",
		"evidence:kind=metric",       // NOT tool-declarable: the runner derives kinds
		"tool:get_rca_verdict=ok",    // NOT tool-declarable: the runner derives outcomes
		"note=capped",                // NOT tool-declarable
		"signature=SHOUTING",         // wrong shape
		"verdict:tier=probably",      // outside the closed vocabulary
		strings.Repeat("x", 200),     // over the length bound
		"signature=" + CondSignature, // a literal "signature=signature" is still a shape-valid id
	})
	f.addEvidence([]EvidenceItem{{Kind: "log"}, {Kind: "nonsense"}})
	f.addNotes([]string{"Protocol diagnostics results were capped", "MAC-move seen"})
	f.recordTool("run_protocol_diagnostic", "ok")
	f.recordTool("run_protocol_diagnostic", "denied") // first outcome wins
	f.recordTool("search_logs", "invented")           // outside the vocabulary: ignored

	holds := map[string]bool{
		"signature=bgp-idle-unreachable":      true,
		"signature=ospf-flap-l1":              false,
		"signature=none":                      false, // a signature DID fire
		"verdict:tier=confirmed":              true,
		"verdict:tier=suspected":              false,
		"verdict:phrase=link":                 true,
		"verdict:phrase=optics":               false,
		"evidence:kind=log":                   true,
		"evidence:kind=metric":                false, // a tool cannot assert a kind
		"note=capped":                         true,
		"note=mac":                            true, // hyphenated compounds contribute their parts
		"note=absent":                         false,
		"tool:run_protocol_diagnostic=ok":     true,
		"tool:run_protocol_diagnostic=denied": false,
		"tool:search_logs=ok":                 false,
	}
	for raw, want := range holds {
		key, value, _ := strings.Cut(raw, "=")
		if got := f.holds(SkillCondition{Key: key, Value: value}); got != want {
			t.Errorf("holds(%s) = %v, want %v", raw, got, want)
		}
	}
	if got := f.holds(SkillCondition{Key: "made:up", Value: "x"}); got {
		t.Error("an unknown condition key must never fire")
	}
	if got := sortedToolOutcomes(f); len(got) != 1 || got[0] != "run_protocol_diagnostic=ok" {
		t.Errorf("tool outcomes = %v", got)
	}
}

// signature=none means "a diagnostic RAN and matched nothing" — never the
// trivially-true "no signature fired" of a turn that ran no diagnostic at all.
func TestSignatureNoneRequiresADiagnosticRun(t *testing.T) {
	none := SkillCondition{Key: CondSignature, Value: CondSignatureNone}

	bare := newChainFacts()
	if bare.holds(none) {
		t.Error("signature=none must not fire when no diagnostic ran")
	}

	ranClean := newChainFacts()
	ranClean.recordTool("run_protocol_diagnostic", "ok")
	if !ranClean.holds(none) {
		t.Error("signature=none must fire when the diagnostic ran and matched nothing")
	}

	ranMatched := newChainFacts()
	ranMatched.recordTool("run_protocol_diagnostic", "ok")
	ranMatched.addSignals([]string{"signature=bgp-admin-shut"})
	if ranMatched.holds(none) {
		t.Error("signature=none must not fire when a signature matched")
	}

	notWired := newChainFacts()
	notWired.recordTool("run_protocol_diagnostic", "not_wired")
	if notWired.holds(none) {
		t.Error("signature=none must not fire when the diagnostic could not run at all")
	}
}

func TestConditionTokens(t *testing.T) {
	got := conditionTokens("Physical LINK is up — MAC-move churn on Gi0/1, x")
	want := map[string]bool{"physical": true, "link": true, "is": true, "up": true,
		"mac-move": true, "mac": true, "move": true, "churn": true, "on": true, "gi0": true}
	for w := range want {
		if !containsFold(got, w) {
			t.Errorf("token %q missing from %v", w, got)
		}
	}
	for _, bad := range []string{"x", "1"} {
		if containsFold(got, bad) {
			t.Errorf("single-character token %q must not be produced: %v", bad, got)
		}
	}
}

// The RCA tool declares the ENGINE's own words as machine facts. It must never
// declare anything outside the closed grammar.
func TestVerdictPhraseSignals(t *testing.T) {
	got := verdictPhraseSignals("The link beneath the BGP session is down", 24)
	joined := strings.Join(got, " ")
	for _, want := range []string{"verdict:phrase=link", "verdict:phrase=bgp", "verdict:phrase=down"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	var long strings.Builder
	for i := 0; i < 80; i++ {
		long.WriteString("word" + strconv.Itoa(i) + " ")
	}
	if n := len(verdictPhraseSignals(long.String(), 24)); n != 24 {
		t.Errorf("phrase signals = %d, want the 24 cap", n)
	}
	for _, s := range got {
		if !strings.HasPrefix(s, CondVerdictPhrase+"=") {
			t.Errorf("signal %q is outside the closed grammar", s)
		}
	}
}
