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
// REAL machinery: the real embedded SKILL.md corpus, the real gather planner,
// the real Policy Engine, the real condition evaluator and the real chain loop.
// The ONLY thing substituted is what the governed tools returned — which is
// exactly the input a fixture is supposed to own.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ---- the fixture registry --------------------------------------------------

// caseTool is a governed tool with a SCRIPTED result. It embeds the REAL tool,
// so its name, module, capability, permissions and freshness — everything the
// Policy Engine reads — are the production ones; only Run is fixture.
type caseTool struct {
	AITool
	res ToolResult
	err error
}

func (t caseTool) Run(_ context.Context, _ Principal, _ ToolArgs) (ToolResult, error) {
	if t.err != nil {
		return ToolResult{}, t.err
	}
	return t.res, nil
}

// errCaseToolFailed is the generic failure behind a `= error` outcome.
var errCaseToolFailed = errors.New("fixture tool failure")

// caseDeps wires every troubleshoot seam so the REAL registry registers every
// tool on the skill allowlist. The functions are never called — caseTool
// replaces Run — but their presence is what makes registration production-shaped.
func caseDeps() TroubleshootDeps {
	d := stubDeps()
	d.ProtocolDiagnostic = func(context.Context, Principal, DiagnosticRequest) (DiagnosticReport, error) {
		return DiagnosticReport{}, nil
	}
	d.SecurityFindings = func(context.Context, Principal, FindingsQuery) ([]SecurityFinding, error) {
		return nil, nil
	}
	d.TopologyContext = func(context.Context, Principal, string) (TopologyContext, error) {
		return TopologyContext{}, nil
	}
	d.CaseTimeline = func(context.Context, Principal, string) ([]TimelineEvent, error) {
		return nil, nil
	}
	d.DeviceState = func(context.Context, Principal, DeviceStateRequest) (DeviceStateReport, error) {
		return DeviceStateReport{}, nil
	}
	d.BGPWatchlist = func(context.Context, Principal) (BGPWatchlistReport, error) {
		return BGPWatchlistReport{}, nil
	}
	d.BGPRPKI = func(context.Context, Principal) (BGPRPKIReport, error) {
		return BGPRPKIReport{}, nil
	}
	d.BGPFeedRecent = func(context.Context, Principal, string, int) (BGPFeedReport, error) {
		return BGPFeedReport{}, nil
	}
	d.RecallInvestigations = func(context.Context, Principal, InvestigationQuery) ([]InvestigationRow, error) {
		return nil, nil
	}
	return d
}

// casePayload is what every ANSWERING tool returns for a case: the evidence
// kinds, the collection notes and the machine signals the fixture declares.
// Facts are turn-global in the chain (chainFacts), so which answering tool
// carries them cannot change a routing decision — only WHETHER they arrived can,
// and that is what the case states.
func casePayload(c SkillCase) ToolResult {
	res := ToolResult{Notes: append([]string(nil), c.Notes...), Signals: append([]string(nil), c.Signals...)}
	for i, kind := range c.Evidence {
		res.Items = append(res.Items, EvidenceItem{
			CitationID: fmt.Sprintf("case-%s-%d", kind, i),
			Kind:       kind,
			Text:       "fixture " + kind + " evidence for " + c.Name,
			Href:       "#/fixture",
		})
	}
	return res
}

// caseOrchestrator builds the turn: the real skill set, the real policy engine,
// and one fixture tool per allowlisted tool carrying this case's scripted
// outcome. `not_wired` is modelled the way production models it — the tool is
// simply not registered on this deployment.
func caseOrchestrator(t *testing.T, set *SkillSet, c SkillCase) (*Orchestrator, *scriptLLM, *[]ToolAuditEntry) {
	t.Helper()
	replies := []string(nil)
	if c.ModelNext != "" {
		replies = []string{"Routing this step.\nNEXT: " + c.ModelNext}
	}
	llm := &scriptLLM{replies: replies, fallback: "Fixture narrative for " + c.Name + "."}

	ds := newMockDS()
	var audit []ToolAuditEntry
	o := &Orchestrator{
		DS: ds, LLM: llm,
		Flags:        func(string) bool { return true },
		Troubleshoot: caseDeps(),
		ToolAudit:    func(e ToolAuditEntry) { audit = append(audit, e) },
	}
	real := Tools(ds)
	real.AddTroubleshootTools(ds, o.Troubleshoot)

	payload := casePayload(c)
	reg := &ToolRegistry{byName: map[string]AITool{}}
	var denied []string
	for _, name := range sortedKeys(skillToolAllowlist) {
		rt, ok := real.Get(name)
		if !ok {
			t.Fatalf("%s is on the skill tool allowlist but the registry does not wire it", name)
		}
		switch c.Tools[name] {
		case "not_wired":
			continue // not registered on this deployment — the runner discloses it
		case "not_found":
			reg.add(caseTool{AITool: rt, err: ErrNotFound})
		case "error":
			reg.add(caseTool{AITool: rt, err: errCaseToolFailed})
		case "denied":
			denied = append(denied, name)
			reg.add(caseTool{AITool: rt, res: payload})
		default: // "" or "ok"
			reg.add(caseTool{AITool: rt, res: payload})
		}
	}
	o.Tools = reg
	o.Policy = NewPolicyEngine(PolicyConfig{DenyTools: denied}, o.Flags)
	o.Skills = set
	return o, llm, &audit
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

func runSkillCase(t *testing.T, set *SkillSet, sk *Skill, c SkillCase) {
	t.Helper()
	o, llm, audit := caseOrchestrator(t, set, c)

	// The ENTRY METHOD: when the case states it, deterministic selection must
	// reach this skill from the operator's own words, with no model involved.
	if c.ExpectSelect != "" {
		m, ok := SelectSkill(set, c.Question, Plan{Intent: c.Intent})
		switch {
		case c.ExpectSelect == caseSelectNone:
			if ok {
				t.Errorf("SelectSkill picked %q for %q; the case says no method applies", m.Skill.Name, c.Question)
			}
		case !ok:
			t.Errorf("SelectSkill picked nothing for %q; the case expects %q", c.Question, c.ExpectSelect)
		case m.Skill.Name != c.ExpectSelect:
			t.Errorf("SelectSkill picked %q for %q; the case expects %q", m.Skill.Name, c.Question, c.ExpectSelect)
		}
	}

	ans, handled := o.answerSkill(context.Background(), runPrincipal(), c.Question,
		Plan{Intent: firstNonEmpty(c.Intent, "troubleshoot")},
		SkillMatch{Skill: sk, Reason: "the case fixture selected " + sk.Name},
		c.UI, nil)
	if !handled {
		t.Fatalf("the turn was not handled — no method in the chain gathered anything")
	}

	// ── the hop path, and HOW each hop was chosen ────────────────────────
	if len(ans.Chain) != len(c.ExpectChain) {
		t.Fatalf("chain = %v, want %v", renderChain(ans.Chain), renderExpect(c.ExpectChain))
	}
	for i, want := range c.ExpectChain {
		got := ans.Chain[i]
		if got.Name != want.Skill || got.Selected != want.Selected {
			t.Fatalf("hop %d = %s (%s), want %s (%s) — full chain %v",
				i+1, got.Name, got.Selected, want.Skill, want.Selected, renderChain(ans.Chain))
		}
		if got.Round != i+1 {
			t.Errorf("hop %d ran in round %d", i+1, got.Round)
		}
	}
	last := ans.Chain[len(ans.Chain)-1]
	wantSelected := caseSelectNone
	if len(ans.Chain) > 1 {
		wantSelected = last.Selected
	}
	if wantSelected != c.ExpectSelected {
		t.Errorf("the last hop was selected by %q, the case says %q", wantSelected, c.ExpectSelected)
	}
	if c.ExpectReason != "" {
		if !strings.Contains(strings.ToLower(last.Reason), strings.ToLower(c.ExpectReason)) {
			t.Errorf("the hop reason shown to the operator is %q, which does not contain %q", last.Reason, c.ExpectReason)
		}
	}
	// A hop must be reconstructible from the audit alone.
	for i, h := range ans.Chain[1:] {
		want := "rule_selected"
		if h.Selected == ChainSelectedModel {
			want = "model_selected"
		}
		if !hasSelectionAudit(*audit, h.Name, h.Selected, want, i+1) {
			t.Errorf("hop to %s (%s) is not in the audit as %s in round %d: %+v", h.Name, h.Selected, want, i+1, selections(*audit))
		}
	}

	// ── the method this evidence must NOT reach ──────────────────────────
	for _, never := range c.ExpectNever {
		for _, h := range ans.Chain {
			if h.Name == never {
				t.Errorf("the chain reached %q, which this evidence must never reach: %v", never, renderChain(ans.Chain))
			}
		}
	}

	// ── the verdict the operator is promised ─────────────────────────────
	final, ok := set.Get(last.Name)
	if !ok {
		t.Fatalf("the final hop %q is not a loaded skill", last.Name)
	}
	if ans.Skill == nil || ans.Skill.Name != final.Name {
		t.Errorf("Answer.Skill = %+v, want the last hop %q", ans.Skill, final.Name)
	}
	var verdictLines []string
	for _, d := range final.Decisions {
		if d.Kind == DecisionVerdict {
			verdictLines = append(verdictLines, d.Reason)
		}
	}
	joined := strings.ToLower(strings.Join(verdictLines, " | "))
	for _, tok := range c.ExpectVerdict {
		if !strings.Contains(joined, strings.ToLower(tok)) {
			t.Errorf("%s's verdict= says %q, which no longer states %q", final.Name, joined, tok)
		}
	}
	if len(llm.systems) == 0 {
		t.Fatal("the narration turn never reached the provider seam")
	}
	system := llm.systems[len(llm.systems)-1]
	for _, vl := range verdictLines {
		if !strings.Contains(system, vl) {
			t.Errorf("the verdict requirement %q never reached the narration prompt", vl)
		}
	}

	// ── the disclosures ──────────────────────────────────────────────────
	disclosed := strings.Join(append(append([]string(nil), ans.MissingEvidence...), ans.Disclaimers...), "\n")
	if len(llm.prompts) > 0 {
		disclosed += "\n" + llm.prompts[len(llm.prompts)-1]
	}
	for _, want := range c.ExpectNotes {
		if !strings.Contains(disclosed, want) {
			t.Errorf("the operator was never told %q; disclosures were:\n%s", want, disclosed)
		}
	}
}

func renderChain(chain []SkillHop) []string {
	out := make([]string, 0, len(chain))
	for _, h := range chain {
		out = append(out, h.Name+"("+h.Selected+")")
	}
	return out
}

func renderExpect(chain []SkillHopExpect) []string {
	out := make([]string, 0, len(chain))
	for _, h := range chain {
		out = append(out, h.Skill+"("+h.Selected+")")
	}
	return out
}

func selections(entries []ToolAuditEntry) []ToolAuditEntry {
	var out []ToolAuditEntry
	for _, e := range entries {
		if e.Tool == "next_skill" {
			out = append(out, e)
		}
	}
	return out
}

func hasSelectionAudit(entries []ToolAuditEntry, skill, selected, reason string, round int) bool {
	for _, e := range selections(entries) {
		if e.Skill == skill && e.Selected == selected && e.Reason == reason && e.Round == round && e.Allowed {
			return true
		}
	}
	return false
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
