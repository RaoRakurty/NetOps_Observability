// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_harness.go — the behavioural case runner (tracker 331), out of test code
// so a customer's runbook can be proven by the same runner as Correlix's own
// methods (tracker 337 N-F2). The test suite calls this function too: there is one
// runner and it cannot drift.
//
// It replays a case through the REAL machinery: the real planner, the real Policy
// Engine, the real condition evaluator and the real chain loop. The ONLY things
// substituted are what the governed tools returned and what the model replied.
//
// It reaches nothing. The provider is scripted, every tool's Run is a fixture, and
// the data sources behind tool registration answer "not found". Nothing in this
// file imports a network package (TestHarnessImportsNoNetworkPackage), and any
// call into those registration-only seams reports through harnessEnv.onTouch, so a
// test fails the moment one is reached.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"netops/backend/internal/irishypo"
)

// HarnessReport is the result of running one skill's cases.
type HarnessReport struct {
	Skill   string      `json:"skill"`
	Version int         `json:"version"`
	Origin  SkillOrigin `json:"origin"`
	Kind    SkillKind   `json:"kind"`
	// NotRun is why no case ran ("" when they did). A skill with nothing proven
	// has not passed.
	NotRun string              `json:"not_run,omitempty"`
	Cases  []HarnessCaseResult `json:"cases"`
}

// Passed reports whether at least one case ran and every case held.
func (r HarnessReport) Passed() bool {
	if r.NotRun != "" || len(r.Cases) == 0 {
		return false
	}
	for _, c := range r.Cases {
		if !c.Passed {
			return false
		}
	}
	return true
}

// HarnessCaseResult is one case's outcome. Failures name what did not hold.
type HarnessCaseResult struct {
	Name     string   `json:"name"`
	Passed   bool     `json:"passed"`
	Failures []string `json:"failures,omitempty"`
	Chain    []string `json:"chain,omitempty"`
	Tools    []string `json:"tools,omitempty"`
}

// RunCases runs every case sk carries, over set, without touching a provider, a
// device or a data store.
func RunCases(set *SkillSet, sk *Skill) HarnessReport {
	return runCases(set, sk, harnessEnv{})
}

func runCases(set *SkillSet, sk *Skill, env harnessEnv) HarnessReport {
	if sk == nil {
		return HarnessReport{NotRun: "no skill was given"}
	}
	rep := HarnessReport{Skill: sk.Name, Version: sk.Version, Origin: sk.Origin, Kind: sk.Kind}
	if sk.isMOP() {
		rep.NotRun = "a " + string(SkillKindMOP) + " is never executed"
		return rep
	}
	if _, ok := set.Get(sk.Name); !ok {
		rep.NotRun = "the skill is not in the given set"
		return rep
	}
	if len(sk.Cases) == 0 {
		rep.NotRun = "the skill carries no cases"
		return rep
	}
	for _, c := range sk.Cases {
		rep.Cases = append(rep.Cases, runCaseGuarded(set, sk, c, env))
	}
	return rep
}

// runCaseGuarded keeps one case's panic from taking the caller down: a runbook is
// customer input (§3), and "this case crashed" is a result.
func runCaseGuarded(set *SkillSet, sk *Skill, c SkillCase, env harnessEnv) (res HarnessCaseResult) {
	defer func() {
		if r := recover(); r != nil {
			res = HarnessCaseResult{Name: c.Name, Failures: []string{fmt.Sprintf("the case crashed the runner: %v", r)}}
		}
	}()
	return runHarnessCase(set, sk, c, env)
}

// ---- the fixture -----------------------------------------------------------

// harnessEnv carries the seam that proves the harness reaches nothing.
type harnessEnv struct {
	// onTouch, when set, is told about any call into a seam the harness only
	// wires for tool registration. Nothing should ever call one.
	onTouch func(what string)
}

func (e harnessEnv) touch(what string) {
	if e.onTouch != nil {
		e.onTouch(what)
	}
}

// harnessProvider is the scripted model: it records what it was sent and replies
// from its script. It has no transport.
type harnessProvider struct {
	replies  []string
	fallback string
	systems  []string
	prompts  []string
}

// Complete implements LLMClient.
func (h *harnessProvider) Complete(_ context.Context, system string, msgs []LLMMessage) (string, string, error) {
	h.systems = append(h.systems, system)
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			h.prompts = append(h.prompts, msgs[i].Content)
			break
		}
	}
	if n := len(h.systems) - 1; n < len(h.replies) {
		return h.replies[n], "harness", nil
	}
	return h.fallback, "harness", nil
}

// harnessTool is a governed tool with a SCRIPTED result. It embeds the REAL tool,
// so its name, module, capability, permissions and freshness — everything the
// Policy Engine reads — are the production ones; only Run is fixture.
type harnessTool struct {
	AITool
	res ToolResult
	err error
}

// Run implements AITool.
func (t harnessTool) Run(_ context.Context, _ Principal, _ ToolArgs) (ToolResult, error) {
	if t.err != nil {
		return ToolResult{}, t.err
	}
	return t.res, nil
}

// errCaseToolFailed is the generic failure behind a `= error` outcome.
var errCaseToolFailed = errors.New("fixture tool failure")

// harnessDS answers the data-source seams tool registration needs. Every Run is a
// harnessTool, so nothing should ever call these.
type harnessDS struct{ env harnessEnv }

// GetProblem implements DataSource.
func (d harnessDS) GetProblem(context.Context, Principal, string) (*Problem, error) {
	d.env.touch("DataSource.GetProblem")
	return nil, ErrNotFound
}

// GetProblemEvidence implements DataSource.
func (d harnessDS) GetProblemEvidence(context.Context, Principal, string) ([]EvidenceItem, error) {
	d.env.touch("DataSource.GetProblemEvidence")
	return nil, ErrNotFound
}

// ListActiveProblems implements DataSource.
func (d harnessDS) ListActiveProblems(context.Context, Principal, int) ([]Problem, error) {
	d.env.touch("DataSource.ListActiveProblems")
	return nil, nil
}

// ModuleQuery implements ModuleDataSource.
func (d harnessDS) ModuleQuery(context.Context, Principal, string, ToolArgs) (ToolResult, error) {
	d.env.touch("ModuleDataSource.ModuleQuery")
	return ToolResult{}, nil
}

// harnessDeps wires every troubleshoot seam so the REAL registry registers every
// tool on the skill allowlist. Their presence is what makes registration
// production-shaped; harnessTool replaces every Run.
func harnessDeps(env harnessEnv, c SkillCase) TroubleshootDeps {
	return TroubleshootDeps{
		ResolveDevice: func(_ context.Context, _ Principal, ref string) (DeviceRef, error) {
			return harnessResolveDevice(c, ref)
		},
		ProtocolDiagnostic: func(context.Context, Principal, DiagnosticRequest) (DiagnosticReport, error) {
			env.touch("ProtocolDiagnostic")
			return DiagnosticReport{}, nil
		},
		SecurityFindings: func(context.Context, Principal, FindingsQuery) ([]SecurityFinding, error) {
			env.touch("SecurityFindings")
			return nil, nil
		},
		TopologyContext: func(context.Context, Principal, string) (TopologyContext, error) {
			env.touch("TopologyContext")
			return TopologyContext{}, nil
		},
		CaseTimeline: func(context.Context, Principal, string) ([]TimelineEvent, error) {
			env.touch("CaseTimeline")
			return nil, nil
		},
		DeviceState: func(context.Context, Principal, DeviceStateRequest) (DeviceStateReport, error) {
			env.touch("DeviceState")
			return DeviceStateReport{}, nil
		},
		BGPWatchlist: func(context.Context, Principal) (BGPWatchlistReport, error) {
			env.touch("BGPWatchlist")
			return BGPWatchlistReport{}, nil
		},
		BGPRPKI: func(context.Context, Principal) (BGPRPKIReport, error) {
			env.touch("BGPRPKI")
			return BGPRPKIReport{}, nil
		},
		BGPFeedRecent: func(context.Context, Principal, string, int) (BGPFeedReport, error) {
			env.touch("BGPFeedRecent")
			return BGPFeedReport{}, nil
		},
		RecallInvestigations: func(context.Context, Principal, InvestigationQuery) ([]InvestigationRow, error) {
			env.touch("RecallInvestigations")
			return nil, nil
		},
		RecentChanges: func(context.Context, Principal, ChangeQuery) (ChangeReport, error) {
			env.touch("RecentChanges")
			return ChangeReport{}, nil
		},
		ConfigDiff: func(context.Context, Principal, ConfigDiffRequest) (ConfigDiffReport, error) {
			env.touch("ConfigDiff")
			return ConfigDiffReport{}, nil
		},
	}
}

// harnessResolveDevice is the fixture inventory: the corpus's own device, plus
// whichever device this case names in its ui: block. Anything else does not exist,
// exactly as an unknown name would not.
func harnessResolveDevice(c SkillCase, ref string) (DeviceRef, error) {
	switch ref {
	case "edge-1", "dev-a":
		return DeviceRef{ID: "dev-a", Name: "edge-1"}, nil
	}
	if ref != "" && (ref == c.UI["device"] || ref == c.UI["device_id"]) {
		return DeviceRef{ID: ref, Name: ref}, nil
	}
	return DeviceRef{}, ErrNotFound
}

// harnessPrincipal holds the read permissions a NOC operator's turn runs with.
func harnessPrincipal() Principal {
	return Principal{Tenant: "harness", Perms: map[string]bool{
		"correlations:read": true, "infrastructure:read": true, "logs:read": true,
	}}
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

// newHarnessTurn builds the turn: the given skill set, the real policy engine, and
// one fixture tool per allowlisted tool carrying this case's scripted outcome.
// `not_wired` is modelled the way production models it — the tool is simply not
// registered on this deployment.
func newHarnessTurn(set *SkillSet, c SkillCase, env harnessEnv) (*Orchestrator, *harnessProvider, *[]ToolAuditEntry, error) {
	var replies []string
	if c.ModelNext != "" {
		replies = []string{"Routing this step.\nNEXT: " + c.ModelNext}
	}
	llm := &harnessProvider{replies: replies, fallback: "Fixture narrative for " + c.Name + "."}

	ds := harnessDS{env: env}
	deps := harnessDeps(env, c)
	var audit []ToolAuditEntry
	o := &Orchestrator{
		DS: ds, LLM: llm,
		Flags:        func(string) bool { return true },
		Troubleshoot: deps,
		ToolAudit:    func(e ToolAuditEntry) { audit = append(audit, e) },
	}
	real := Tools(ds)
	real.AddTroubleshootTools(ds, deps)

	payload := casePayload(c)
	reg := &ToolRegistry{byName: map[string]AITool{}}
	var denied []string
	for _, name := range sortedKeys(skillToolAllowlist) {
		rt, ok := real.Get(name)
		if !ok {
			return nil, nil, nil, fmt.Errorf("%s is on the skill tool allowlist but the registry does not wire it", name)
		}
		switch c.Tools[name] {
		case "not_wired":
			continue // not registered on this deployment — the runner discloses it
		case "not_found":
			reg.add(harnessTool{AITool: rt, err: ErrNotFound})
		case "error":
			reg.add(harnessTool{AITool: rt, err: errCaseToolFailed})
		case "denied":
			denied = append(denied, name)
			reg.add(harnessTool{AITool: rt, res: payload})
		default: // "" or "ok"
			reg.add(harnessTool{AITool: rt, res: payload})
		}
	}
	o.Tools = reg
	o.Policy = NewPolicyEngine(PolicyConfig{DenyTools: denied}, o.Flags)
	o.Skills = set
	return o, llm, &audit, nil
}

// ---- the runner ------------------------------------------------------------

// caseFailures collects what did not hold, in the order it was checked.
type caseFailures struct{ list []string }

func (f *caseFailures) addf(format string, a ...any) {
	f.list = append(f.list, fmt.Sprintf(format, a...))
}

// runHarnessCase runs one case and checks everything it states. A wrong hop path
// ends the checks for that case, because everything after it would be noise.
func runHarnessCase(set *SkillSet, sk *Skill, c SkillCase, env harnessEnv) HarnessCaseResult {
	f := &caseFailures{}
	res := HarnessCaseResult{Name: c.Name}
	finish := func() HarnessCaseResult {
		res.Failures = f.list
		res.Passed = len(f.list) == 0
		return res
	}
	o, llm, audit, err := newHarnessTurn(set, c, env)
	if err != nil {
		f.addf("%v", err)
		return finish()
	}

	assertCaseSelection(f, set, c)

	ans, handled := o.answerSkill(context.Background(), harnessPrincipal(), c.Question,
		Plan{Intent: firstNonEmpty(c.Intent, "troubleshoot")},
		SkillMatch{Skill: sk, Reason: "the case fixture selected " + sk.Name},
		c.UI, nil)
	res.Tools = invokedTools(*audit)
	if !handled {
		f.addf("the turn was not handled — no method in the chain gathered anything")
		return finish()
	}
	res.Chain = renderChain(ans.Chain)

	if !assertCaseChain(f, ans, c) {
		return finish()
	}
	last := ans.Chain[len(ans.Chain)-1]
	wantSelected := caseSelectNone
	if len(ans.Chain) > 1 {
		wantSelected = last.Selected
	}
	if wantSelected != c.ExpectSelected {
		f.addf("the last hop was selected by %q, the case says %q", wantSelected, c.ExpectSelected)
	}
	if c.ExpectReason != "" && !strings.Contains(strings.ToLower(last.Reason), strings.ToLower(c.ExpectReason)) {
		f.addf("the hop reason shown to the operator is %q, which does not contain %q", last.Reason, c.ExpectReason)
	}
	// A hop must be reconstructible from the audit alone.
	for i, h := range ans.Chain[1:] {
		want := "rule_selected"
		if h.Selected == ChainSelectedModel {
			want = "model_selected"
		}
		if !hasSelectionAudit(*audit, h.Name, h.Selected, want, i+1) {
			f.addf("hop to %s (%s) is not in the audit as %s in round %d: %+v", h.Name, h.Selected, want, i+1, selections(*audit))
		}
	}
	for _, never := range c.ExpectNever {
		for _, h := range ans.Chain {
			if h.Name == never {
				f.addf("the chain reached %q, which this evidence must never reach: %v", never, renderChain(ans.Chain))
			}
		}
	}

	assertCaseTools(f, set, c, *audit)
	assertCaseHypotheses(f, c, ans.Hypotheses)

	final, ok := set.Get(last.Name)
	if !ok {
		f.addf("the final hop %q is not a loaded skill", last.Name)
		return finish()
	}
	if ans.Skill == nil || ans.Skill.Name != final.Name {
		f.addf("Answer.Skill = %+v, want the last hop %q", ans.Skill, final.Name)
	}
	if !assertCaseVerdict(f, o, llm, final, c) {
		return finish()
	}
	assertRunbookStaysData(f, set, ans.Chain, llm)

	disclosed := strings.Join(append(append([]string(nil), ans.MissingEvidence...), ans.Disclaimers...), "\n")
	if len(llm.prompts) > 0 {
		disclosed += "\n" + llm.prompts[len(llm.prompts)-1]
	}
	for _, want := range c.ExpectNotes {
		if !strings.Contains(disclosed, want) {
			f.addf("the operator was never told %q; disclosures were:\n%s", want, disclosed)
		}
	}
	return finish()
}

// assertCaseSelection: when the case states it, deterministic selection must reach
// this skill from the operator's own words, with no model involved.
func assertCaseSelection(f *caseFailures, set *SkillSet, c SkillCase) {
	if c.ExpectSelect == "" {
		return
	}
	m, ok := SelectSkill(set, c.Question, Plan{Intent: c.Intent})
	switch {
	case c.ExpectSelect == caseSelectNone:
		if ok {
			f.addf("SelectSkill picked %q for %q; the case says no method applies", m.Skill.Name, c.Question)
		}
	case !ok:
		f.addf("SelectSkill picked nothing for %q; the case expects %q", c.Question, c.ExpectSelect)
	case m.Skill.Name != c.ExpectSelect:
		f.addf("SelectSkill picked %q for %q; the case expects %q", m.Skill.Name, c.Question, c.ExpectSelect)
	}
}

// assertCaseChain checks the hop path and how each hop was chosen. false means the
// path itself is wrong.
func assertCaseChain(f *caseFailures, ans Answer, c SkillCase) bool {
	if len(ans.Chain) != len(c.ExpectChain) {
		f.addf("chain = %v, want %v", renderChain(ans.Chain), renderExpect(c.ExpectChain))
		return false
	}
	for i, want := range c.ExpectChain {
		got := ans.Chain[i]
		if got.Name != want.Skill || got.Selected != want.Selected {
			f.addf("hop %d = %s (%s), want %s (%s) — full chain %v",
				i+1, got.Name, got.Selected, want.Skill, want.Selected, renderChain(ans.Chain))
			return false
		}
		if got.Round != i+1 {
			f.addf("hop %d ran in round %d", i+1, got.Round)
		}
	}
	return true
}

// assertCaseTools checks what was attempted, from the audit: the tools this case
// prohibits, and — for every case — nothing outside what the methods on its
// expected path declare.
func assertCaseTools(f *caseFailures, set *SkillSet, c SkillCase, audit []ToolAuditEntry) {
	declared := map[string]bool{}
	for _, h := range c.ExpectChain {
		if hop, ok := set.Get(h.Skill); ok {
			for _, t := range hop.Tools {
				declared[t] = true
			}
		}
	}
	prohibited := map[string]bool{}
	for _, t := range c.ExpectNeverTools {
		prohibited[t] = true
	}
	for _, t := range invokedTools(audit) {
		if prohibited[t] {
			f.addf("the chain attempted %q, which this case prohibits", t)
		}
		if !declared[t] {
			f.addf("the chain attempted %q, which no method on the expected path declares in tools:", t)
		}
	}
}

func assertCaseHypotheses(f *caseFailures, c SkillCase, set *irishypo.Set) {
	for _, want := range c.ExpectHypotheses {
		found := false
		if set != nil {
			for _, h := range set.Hypotheses {
				if h.ID != want.ID {
					continue
				}
				found = true
				if h.State != want.State {
					f.addf("hypothesis %s ended %s, the case says %s", want.ID, h.State, want.State)
				}
			}
		}
		if !found {
			f.addf("hypothesis %s was never opened; the case says it ends %s", want.ID, want.State)
		}
	}
}

// assertCaseVerdict: the final method's verdict= still states what the case says,
// and that requirement reached the model — in the system prompt for a compiled
// method, in the user message for a customer's runbook. false means there was no
// narration turn to inspect.
func assertCaseVerdict(f *caseFailures, o *Orchestrator, llm *harnessProvider, final *Skill, c SkillCase) bool {
	var verdictLines []string
	for _, d := range final.Decisions {
		if d.Kind == DecisionVerdict {
			verdictLines = append(verdictLines, d.Reason)
		}
	}
	joined := strings.ToLower(strings.Join(verdictLines, " | "))
	for _, tok := range c.ExpectVerdict {
		if !strings.Contains(joined, strings.ToLower(tok)) {
			f.addf("%s's verdict= says %q, which no longer states %q", final.Name, joined, tok)
		}
	}
	if len(llm.systems) == 0 {
		f.addf("the narration turn never reached the provider seam")
		return false
	}
	system := llm.systems[len(llm.systems)-1]
	prompt := ""
	if len(llm.prompts) > 0 {
		prompt = llm.prompts[len(llm.prompts)-1]
	}
	for _, vl := range verdictLines {
		if final.customerAuthored() {
			if !strings.Contains(prompt, o.redact(promptLine(vl))) {
				f.addf("the verdict requirement %q never reached the narration's user message", vl)
			}
			continue
		}
		if !strings.Contains(system, vl) {
			f.addf("the verdict requirement %q never reached the narration prompt", vl)
		}
	}
	return true
}

// runbookLineMinBytes is the shortest authored line assertRunbookStaysData looks
// for: "a" or "check" occurring in a system prompt proves nothing.
const runbookLineMinBytes = 8

// assertRunbookStaysData is the LLM01 proof on every turn a customer's runbook
// touched: no line of it is in any system prompt, and the fence is in the last.
func assertRunbookStaysData(f *caseFailures, set *SkillSet, chain []SkillHop, llm *harnessProvider) {
	if !chainTouchedRunbook(chain) {
		return
	}
	// serverOwned is the text the system prompts legitimately hold, which an author
	// may happen to repeat: it is built without a word the customer wrote.
	var serverOwned strings.Builder
	serverOwned.WriteString((&Orchestrator{}).baseSystemPrompt())
	var runbooks []*Skill
	for _, h := range chain {
		hop, ok := set.Get(h.Name)
		if !ok {
			continue
		}
		serverOwned.WriteString(skillSystemBlock(hop))
		serverOwned.WriteString(chainRouteSystemBlock(hop, hop.NextSkills()))
		if hop.customerAuthored() {
			runbooks = append(runbooks, hop)
		}
	}
	for _, hop := range runbooks {
		for _, line := range authoredRunbookText(hop) {
			if len(line) < runbookLineMinBytes || strings.Contains(serverOwned.String(), line) {
				continue
			}
			for _, sys := range llm.systems {
				if strings.Contains(sys, line) {
					f.addf("the runbook line %q reached a system prompt", line)
					break
				}
			}
		}
	}
	if len(llm.systems) > 0 && !strings.Contains(llm.systems[len(llm.systems)-1], DataNotInstructionsFence()) {
		f.addf("the narration of a turn a customer's runbook touched does not carry the data-not-instructions fence")
	}
}

// authoredRunbookText is the customer's own words, without the labels
// customerRunbookLines adds in the user message.
func authoredRunbookText(sk *Skill) []string {
	out := append([]string(nil), sk.LookFor...)
	for _, d := range sk.Decisions {
		out = append(out, d.Reason)
	}
	out = append(out, strings.Split(sk.Body, "\n")...)
	for i, l := range out {
		out[i] = promptLine(l)
	}
	return out
}

// invokedTools lists every tool the chain attempted, in order. A selection entry
// is not a tool execution.
func invokedTools(entries []ToolAuditEntry) []string {
	var out []string
	for _, e := range entries {
		if e.Tool != "next_skill" {
			out = append(out, e.Tool)
		}
	}
	return out
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
