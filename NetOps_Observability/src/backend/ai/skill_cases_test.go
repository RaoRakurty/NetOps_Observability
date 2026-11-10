// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_cases_test.go — the BEHAVIOURAL gate over the deterministic skill chain
// (tracker 331).
//
// The chain in skill_chain.go is the investigator that actually runs in
// production: `FEATURE_AI_TOOLS` is false and a lab has no provider key, so the
// hop a NOC operator gets is the one an authored machine condition fired. Until
// this file existed nothing proved any of those ~30 conditions still fires — the
// loader checked key SHAPE, and a reworded NOC signature or a retargeted
// diagnostic would have made the investigation one hop shallower with CI green.
//
// So every case in every skills/<name>/CASES.yaml is replayed here through the
// REAL machinery (skill_harness.go): the real embedded SKILL.md corpus, the real
// gather planner, the real Policy Engine, the real condition evaluator and the
// real chain loop. The ONLY thing substituted is what the governed tools returned
// — which is exactly the input a fixture is supposed to own.

import (
	"strings"
	"testing"
)

// ---- the fixture -----------------------------------------------------------

// caseDeps is the harness's registration-shaped troubleshoot seams.
func caseDeps() TroubleshootDeps { return harnessDeps(harnessEnv{}, SkillCase{}) }

// caseOrchestrator builds one case's turn, exactly as the runner does.
func caseOrchestrator(t *testing.T, set *SkillSet, c SkillCase) (*Orchestrator, *harnessProvider, *[]ToolAuditEntry) {
	t.Helper()
	o, llm, audit, err := newHarnessTurn(set, c, harnessEnv{})
	if err != nil {
		t.Fatal(err)
	}
	return o, llm, audit
}

// ---- the runner ------------------------------------------------------------

func TestSkillCasesPinTheChain(t *testing.T) {
	set := loadTestSkills(t)
	total := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		for _, c := range sk.Cases {
			total++
			t.Run(name+"/"+c.Name, func(t *testing.T) { runSkillCase(t, set, sk, c) })
		}
	}
	if total != set.CaseCount() {
		t.Fatalf("ran %d cases, the corpus carries %d", total, set.CaseCount())
	}
	if total < set.Len() {
		t.Fatalf("%d cases across %d skills — every skill must carry at least one", total, set.Len())
	}
}

// runSkillCase is the production runner's verdict on one case: there is one
// runner, so the suite and a customer's submission cannot disagree.
func runSkillCase(t *testing.T, set *SkillSet, sk *Skill, c SkillCase) {
	t.Helper()
	res := runCaseGuarded(set, sk, c, harnessEnv{})
	for _, f := range res.Failures {
		t.Error(f)
	}
	if res.Passed == (len(res.Failures) > 0) {
		t.Errorf("Passed = %v with %d failures", res.Passed, len(res.Failures))
	}
}

// ---- no authored rule may go untested --------------------------------------

// TestEveryAuthoredConditionIsExercised is the anti-drift half of the gate: a
// machine condition no case ever satisfies is a rule nobody has proven, which is
// how a dead rule survives review in the first place.
func TestEveryAuthoredConditionIsExercised(t *testing.T) {
	set := loadTestSkills(t)
	conditions := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		for _, d := range sk.Decisions {
			if d.Kind != DecisionNext || d.Cond == nil {
				continue
			}
			conditions++
			covered := false
			for _, c := range sk.Cases {
				if caseFacts(sk, c).holds(*d.Cond) {
					covered = true
					break
				}
			}
			if !covered {
				t.Errorf("%s: no case in CASES.yaml ever satisfies `next=%s when %s` — the rule is untested",
					name, d.Target, d.Cond)
			}
		}
	}
	if conditions == 0 {
		t.Fatal("the corpus carries no machine conditions at all — the chain would be model-only")
	}
	t.Logf("%d authored machine conditions across %d skills, all exercised by %d cases",
		conditions, set.Len(), set.CaseCount())
}

// caseFacts rebuilds the server-derived facts a case's fixture produces, using
// the same accumulators the chain itself uses.
func caseFacts(sk *Skill, c SkillCase) *chainFacts {
	f := newChainFacts()
	for _, tool := range sk.Tools {
		outcome := c.Tools[tool]
		if outcome == "" {
			outcome = "ok"
		}
		f.recordTool(tool, outcome)
	}
	f.addSignals(c.Signals)
	f.addEvidence(casePayload(c).Items)
	f.addNotes(c.Notes)
	return f
}

// ---- the loader's own refusals ---------------------------------------------

// caseProbeSkill is a minimal loaded skill the negative cases are parsed
// against, so every failure below is attributable to the one thing broken.
func caseProbeSkill(t *testing.T) *Skill {
	t.Helper()
	set := loadTestSkills(t)
	sk, ok := set.Get("bgp-session-down")
	if !ok {
		t.Fatal("bgp-session-down must load")
	}
	return sk
}

const goodCase = `
case: a probe case
question: why is bgp down on edge-1
ui:
  - correlation_id=case-probe
tools:
  - run_protocol_diagnostic=ok
signals:
  - state:bgp_peer=idle
evidence:
  - finding
notes:
  - a note
expect_chain:
  - bgp-session-down entry
  - interface-down rule
expect_selected: rule
expect_verdict:
  - peer
expect_notes:
  - something
expect_never:
  - mac-flap
`

func TestSkillCaseFileRejects(t *testing.T) {
	sk := caseProbeSkill(t)
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "no cases at all",
			raw:  "# only a comment\n",
			want: "ZERO cases",
		},
		{
			name: "only whitespace",
			raw:  "   \n\n---\n\n",
			want: "ZERO cases",
		},
		{
			name: "no hop is ever taken",
			raw: strings.Replace(goodCase,
				"expect_chain:\n  - bgp-session-down entry\n  - interface-down rule\nexpect_selected: rule",
				"expect_chain:\n  - bgp-session-down entry\nexpect_selected: none", 1),
			want: "no case takes a hop",
		},
		{
			name: "nothing is proven NOT to fire",
			raw:  strings.Replace(goodCase, "expect_never:\n  - mac-flap\n", "", 1),
			want: "no case carries expect_never",
		},
		{
			name: "no disclosure is ever proven",
			raw:  strings.Replace(goodCase, "expect_notes:\n  - something\n", "", 1),
			want: "no case carries expect_notes",
		},
		{
			name: "duplicate case name",
			raw:  goodCase + "\n---\n" + goodCase,
			want: "duplicate case",
		},
		{
			name: "unnamed case",
			raw:  strings.Replace(goodCase, "case: a probe case", "question: x", 1),
			want: "duplicate key",
		},
		{
			name: "no question",
			raw:  strings.Replace(goodCase, "question: why is bgp down on edge-1\n", "", 1),
			want: "question: is required",
		},
		{
			name: "unknown key",
			raw:  strings.Replace(goodCase, "case: a probe case", "case: a probe case\nexpect_everything: yes", 1),
			want: "unknown key",
		},
		{
			name: "a scalar given as a list",
			raw:  strings.Replace(goodCase, "expect_selected: rule", "expect_selected:\n  - rule", 1),
			want: "takes a value, not a list",
		},
		{
			name: "a list given as a scalar",
			raw:  strings.Replace(goodCase, "evidence:\n  - finding", "evidence: finding", 1),
			want: "takes a list, not a value",
		},
		{
			name: "a signal outside the closed vocabulary",
			raw:  strings.Replace(goodCase, "state:bgp_peer=idle", "state:bgp_peer=confused", 1),
			want: "outside the closed vocabulary",
		},
		{
			name: "a signal key no tool may declare",
			raw:  strings.Replace(goodCase, "state:bgp_peer=idle", "evidence:kind=finding", 1),
			want: "is not one a TOOL may declare",
		},
		{
			name: "signature=none is derived, never declared",
			raw:  strings.Replace(goodCase, "state:bgp_peer=idle", "signature=none", 1),
			want: "can never be declared by a tool",
		},
		{
			name: "an evidence kind outside the closed set",
			raw:  strings.Replace(goodCase, "  - finding", "  - vibes", 1),
			want: "evidence kind",
		},
		{
			name: "a tool outcome outside the closed set",
			raw:  strings.Replace(goodCase, "run_protocol_diagnostic=ok", "run_protocol_diagnostic=maybe", 1),
			want: "tool outcome",
		},
		{
			name: "a tool off the read-only allowlist",
			raw:  strings.Replace(goodCase, "run_protocol_diagnostic=ok", "reboot_device=ok", 1),
			want: "not on the skill tool allowlist",
		},
		{
			name: "every tool fails, so the method never runs",
			raw: strings.Replace(goodCase, "  - run_protocol_diagnostic=ok",
				"  - run_protocol_diagnostic=error\n  - get_device_state=error\n  - get_rca_verdict=error\n"+
					"  - get_topology_context=error\n  - search_logs=error\n  - recall_investigations=error", 1),
			want: "every tool fails",
		},
		{
			name: "a hop the skill never declares",
			raw:  strings.Replace(goodCase, "  - interface-down rule", "  - mac-flap rule", 1),
			want: "never declares as a next= target",
		},
		{
			name: "a chain that does not start at this skill",
			raw:  strings.Replace(goodCase, "  - bgp-session-down entry", "  - interface-down entry", 1),
			want: "expect_chain must start at",
		},
		{
			name: "a second entry hop",
			raw:  strings.Replace(goodCase, "  - interface-down rule", "  - interface-down entry", 1),
			want: "only the FIRST hop",
		},
		{
			name: "an unknown selection origin",
			raw:  strings.Replace(goodCase, "  - interface-down rule", "  - interface-down guess", 1),
			want: "expect_chain",
		},
		{
			name: "expect_selected contradicts the chain",
			raw:  strings.Replace(goodCase, "expect_selected: rule", "expect_selected: model", 1),
			want: "does not match the last hop",
		},
		{
			name: "a model hop with no scripted directive",
			raw: strings.Replace(strings.Replace(goodCase, "  - interface-down rule", "  - interface-down model", 1),
				"expect_selected: rule", "expect_selected: model", 1),
			want: "needs a model_next",
		},
		{
			name: "the model is offered a skill the author never declared",
			raw:  strings.Replace(goodCase, "expect_selected: rule", "expect_selected: rule\nmodel_next: mac-flap", 1),
			want: "may only pick from the author's own list",
		},
		{
			name: "no verdict is asserted",
			raw:  strings.Replace(goodCase, "expect_verdict:\n  - peer\n", "", 1),
			want: "expect_verdict is required",
		},
		{
			name: "expect_never contradicts expect_chain",
			raw:  strings.Replace(goodCase, "  - mac-flap", "  - interface-down", 1),
			want: "expect_never lists",
		},
		{
			name: "a ui entity nothing can resolve",
			raw:  strings.Replace(goodCase, "correlation_id=case-probe", "vlan=100", 1),
			want: "not a resolvable entity",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSkillCaseFile(sk, tc.raw)
			if err == nil {
				t.Fatalf("expected a load error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestEveryEmbeddedSkillShipsCases is the structural half of "zero cases is a
// load error": the embed itself must carry one file per method directory.
func TestEveryEmbeddedSkillShipsCases(t *testing.T) {
	set := loadTestSkills(t)
	files, err := skillCaseFiles()
	if err != nil {
		t.Fatalf("skillCaseFiles: %v", err)
	}
	if len(files) != set.Len() {
		t.Fatalf("%d embedded %s files for %d skills: %v", len(files), skillCasesFile, set.Len(), files)
	}
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		if len(sk.Cases) == 0 {
			t.Errorf("%s loaded with zero cases", name)
		}
		for _, n := range sk.CaseNames() {
			if strings.TrimSpace(n) == "" {
				t.Errorf("%s: an unnamed case loaded", name)
			}
		}
	}
}
