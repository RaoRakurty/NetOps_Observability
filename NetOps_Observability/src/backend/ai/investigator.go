// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// investigator.go — the read-only Investigator (tracker 337 N-I1, plan §5
// Phase I; design Part 1 §21).
//
// An investigation is NOT a second loop. The bounded skill chain
// (skill_chain.go) already iterates methods with hypotheses, budgets and
// grounding; the agent loop already lets a model choose governed read-only
// tools. What an operator asking "investigate this" also needs, and what this
// file adds, is the STRUCTURE around them, in the plan's order:
//
//	bind → context → existing RCA first → runbook retrieval → plan →
//	passes (each one bounded skill chain) → bounded repeat → diagnosis
//
//   - BIND. The device and incident are resolved ONCE under the caller's tenant
//     (resolveSkillEntities). A page that named a device or incident the caller
//     cannot see is disclosed and dropped, never followed.
//   - EXISTING RCA FIRST. When an incident is in scope its engine verdict is
//     read through the gateway BEFORE any device read, and seeded into every
//     pass: the hypotheses resolve against it (irishypo never lets a hypothesis
//     override the engine), and the narration sees it first.
//   - RUNBOOK RETRIEVAL. The tenant's approved runbooks LINKED to the incident
//     or device (N-F2) are the first candidates, then the method the question
//     selects, then the top-level method. Applicability (DeviceFacts,
//     applies_when) decides which may run; a ruled-out one is shown and skipped.
//   - PASSES. Each candidate runs as one bounded skill chain. A further pass
//     runs only when the previous one concluded nothing (no SUPPORTED line of
//     investigation) and the investigation's own budgets allow it.
//   - BUDGETS. Passes, tool calls, model tokens and wall-clock — each enforced
//     here (the token cap inside completeTier, the clock as a context
//     deadline) and every cut DISCLOSED.
//
// Strictly read-only: every tool is reached through the same gateway and
// policy engine as every other answer, the catalogue holds no write tool, and
// nothing here originates a probe from a customer device (owner 2026-11-13).
// The trace is server-written: step summaries are composed from skill names,
// tool labels and counts, never from model text.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/irishypo"
)

// Investigation budgets. The defaults allow a skill chain of the full per-turn
// size twice over plus a third, smaller pass, inside a wall clock that keeps
// the request well within the ask stream's budget.
const (
	DefaultInvestigationPasses    = 3
	DefaultInvestigationToolCalls = 2 * MaxChainToolCalls
	DefaultInvestigationTokens    = 60_000
	DefaultInvestigationWall      = 100 * time.Second

	// maxInvestigationCandidates bounds the runbook/method candidates shown in
	// the trace (the runnable ones are further bounded by the pass budget).
	maxInvestigationCandidates = 6
	// maxInvestigationSteps bounds the trace itself (§9: every output bounded).
	maxInvestigationSteps = 24
	// investigationPassReserve is the time that must remain before another pass
	// starts, so the investigation keeps enough to narrate what it has.
	investigationPassReserve = 12 * time.Second
	// maxInvestigationQuestion bounds the operator's question kept in the trace.
	maxInvestigationQuestion = 300
)

// UIActionInvestigate is the closed value of the `iris_action` UI-context key
// that asks for a full investigation ("Investigate this").
const (
	UIActionKey         = "iris_action"
	UIActionInvestigate = "investigate"
)

// Investigation statuses (closed).
const (
	InvestigationStatusConcluded    = "concluded"    // a pass found a supported line of investigation
	InvestigationStatusInconclusive = "inconclusive" // evidence gathered, nothing supported
	InvestigationStatusNoEvidence   = "no_evidence"  // nothing could be gathered for the scope
	InvestigationStatusRefused      = "refused"      // not entitled: AI investigations are off
)

// Step kinds (closed): the vocabulary of the trace.
const (
	InvStepBind      = "bind"
	InvStepContext   = "context"
	InvStepRCA       = "rca"
	InvStepRunbooks  = "runbooks"
	InvStepPlan      = "plan"
	InvStepPass      = "pass"
	InvStepAgent     = "agent"
	InvStepStop      = "stop"
	InvStepDiagnosis = "diagnosis"
)

// Step outcomes (closed).
const (
	InvOutcomeOK       = "ok"
	InvOutcomeNone     = "none"
	InvOutcomeSkipped  = "skipped"
	InvOutcomeNotFound = "not_found"
	InvOutcomeDenied   = "denied"
	InvOutcomeError    = "error"
	InvOutcomeCutoff   = "cutoff"
)

// Candidate sources (closed): why a method was considered.
const (
	InvSourceRunbookLink = "runbook_link" // the tenant linked this runbook to the incident or device
	InvSourceSelected    = "selected"     // the method the question selects
	InvSourceEntry       = "entry_method" // the top-level method
)

// Cutoff reasons (closed), in addition to the chain's own.
const (
	InvCutoffPasses    = "passes"
	InvCutoffToolCalls = "tool_calls"
	InvCutoffTokens    = "tokens"
	InvCutoffTime      = "time"
)

// ErrInvestigationTokenBudget is returned by a model call made after the
// investigation's token budget ran out. Every caller already degrades to its
// deterministic answer on a model error.
var ErrInvestigationTokenBudget = errors.New("the investigation's model-token budget is spent")

// InvestigationBudget bounds one investigation.
type InvestigationBudget struct {
	MaxPasses    int           `json:"max_passes"`
	MaxToolCalls int           `json:"max_tool_calls"`
	MaxTokens    int           `json:"max_tokens"`
	Wall         time.Duration `json:"-"`
	WallSeconds  int           `json:"wall_seconds"`
}

// DefaultInvestigationBudget is the platform default.
func DefaultInvestigationBudget() InvestigationBudget {
	return InvestigationBudget{
		MaxPasses: DefaultInvestigationPasses, MaxToolCalls: DefaultInvestigationToolCalls,
		MaxTokens: DefaultInvestigationTokens, Wall: DefaultInvestigationWall,
	}
}

// normalized fills unset fields with the defaults and never lets a field
// exceed them: a caller can only make an investigation SMALLER.
func (b InvestigationBudget) normalized() InvestigationBudget {
	d := DefaultInvestigationBudget()
	clampInt := func(v, max int) int {
		if v <= 0 || v > max {
			return max
		}
		return v
	}
	b.MaxPasses = clampInt(b.MaxPasses, d.MaxPasses)
	b.MaxToolCalls = clampInt(b.MaxToolCalls, d.MaxToolCalls)
	b.MaxTokens = clampInt(b.MaxTokens, d.MaxTokens)
	if b.Wall <= 0 || b.Wall > d.Wall {
		b.Wall = d.Wall
	}
	b.WallSeconds = int(b.Wall / time.Second)
	return b
}

// InvestigationTarget is what the investigation is about, as the SERVER
// resolved it (never as the client named it).
type InvestigationTarget struct {
	DeviceID      string `json:"device_id,omitempty"`
	DeviceName    string `json:"device,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// InvestigationEngine is the correlation engine's verdict read first. It is
// shown beside the investigation, never replaced by it.
type InvestigationEngine struct {
	Tier       string `json:"tier,omitempty"`
	Statement  string `json:"statement,omitempty"`
	CitationID string `json:"citation_id,omitempty"`
}

// InvestigationCandidate is one method or runbook the investigation considered.
type InvestigationCandidate struct {
	Skill            string `json:"skill"`
	Source           string `json:"source"`
	CustomerAuthored bool   `json:"customer_authored,omitempty"`
	Applies          bool   `json:"applies"`
	Why              string `json:"why,omitempty"`
}

// InvestigationPlanStep is what one pass intends to read, before it runs.
type InvestigationPlanStep struct {
	Skill string   `json:"skill"`
	Tools []string `json:"tools"`
}

// InvestigationPass is one bounded skill chain the investigation ran.
type InvestigationPass struct {
	Pass         int        `json:"pass"`
	Entry        string     `json:"entry"`
	Source       string     `json:"source"`
	Chain        []SkillHop `json:"chain,omitempty"`
	Lookups      []string   `json:"lookups,omitempty"`
	ToolCalls    int        `json:"tool_calls"`
	Supported    int        `json:"supported"`
	Rejected     int        `json:"rejected"`
	Inconclusive int        `json:"inconclusive"`
	Answered     bool       `json:"answered"`
}

// InvestigationStep is one line of the trace.
type InvestigationStep struct {
	Seq     int    `json:"seq"`
	Kind    string `json:"kind"`
	Outcome string `json:"outcome"`
	Summary string `json:"summary"`
}

// InvestigationUsage is what the investigation spent.
type InvestigationUsage struct {
	Passes     int   `json:"passes"`
	ToolCalls  int   `json:"tool_calls"`
	Tokens     int   `json:"tokens"`
	DurationMS int64 `json:"duration_ms"`
}

// InvestigationTrace is the structured record of one investigation. Every
// field is server-built; the narrative itself is the answer's Text.
type InvestigationTrace struct {
	ID             string                   `json:"id,omitempty"`
	Status         string                   `json:"status"`
	Question       string                   `json:"question,omitempty"`
	Target         InvestigationTarget      `json:"target"`
	Engine         *InvestigationEngine     `json:"engine,omitempty"`
	ContextApplied bool                     `json:"context_applied"`
	Candidates     []InvestigationCandidate `json:"candidates,omitempty"`
	Plan           []InvestigationPlanStep  `json:"plan,omitempty"`
	Passes         []InvestigationPass      `json:"passes,omitempty"`
	Steps          []InvestigationStep      `json:"steps"`
	Budget         InvestigationBudget      `json:"budget"`
	Used           InvestigationUsage       `json:"used"`
	Cutoffs        []string                 `json:"cutoffs,omitempty"`
	StartedAt      time.Time                `json:"started_at"`
	FinishedAt     time.Time                `json:"finished_at"`
}

// RunbooksForFunc returns the NAMES of the tenant's runbooks linked to the
// investigation's incident or device (N-F2 links). The server derives the
// tenant from the principal; a name is only ever looked up in the caller's
// own skill set, so a foreign name can never run.
type RunbooksForFunc func(ctx context.Context, p Principal, t InvestigationTarget) []string

// InvestigationsOffText is the refusal an operator sees when AI investigations
// are not on for them.
const InvestigationsOffText = "A full investigation needs AI investigations, which are off for this workspace. " +
	"A platform administrator can turn on \"AI investigations\" on the Features page, and a workspace administrator " +
	"enables it for the workspace in Iris settings → workspace access. Iris can still check a specific symptom: " +
	"ask about it directly (for example \"why is BGP down on edge-1\")."

// InvestigationNeedsSwitchNote is added to a troubleshooting answer the planner
// meant as a full investigation for a caller without AI investigations.
const InvestigationNeedsSwitchNote = "This was answered as a single check. A full investigation needs AI investigations, " +
	"which a platform administrator turns on in Features and a workspace administrator enables in Iris settings."

// investigationSeed is the engine verdict read before the first pass, folded
// into every pass's chain state (answerSkill reads it).
type investigationSeed struct {
	tool    string
	signals []string
	items   []EvidenceItem
}

// tokenMeter enforces the investigation's model-token budget across every
// model call the passes make (completeTier consults it).
type tokenMeter struct {
	mu    sync.Mutex
	cap   int
	used  int
	calls int // tool calls the passes ATTEMPTED (runSkillRound counts them)
}

func (m *tokenMeter) allow() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.used < m.cap
}

func (m *tokenMeter) add(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.used += n
	m.mu.Unlock()
}

// addCall counts one attempted tool call.
func (m *tokenMeter) addCall() {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
}

func (m *tokenMeter) toolCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *tokenMeter) spent() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.used
}

func (m *tokenMeter) exhausted() bool { return !m.allow() }

// estimateCallTokens is the provider-reported usage when there is one, else a
// characters/4 estimate of what was sent and received.
func estimateCallTokens(usage TokenUsage, system string, msgs []LLMMessage, text string) int {
	if usage.Reported {
		return int(usage.InputTokens + usage.OutputTokens + usage.ThinkingTokens)
	}
	n := len(system) + len(text)
	for _, m := range msgs {
		n += len(m.Content)
	}
	return n / 4
}

// WantsInvestigation reports whether the UI asked for a full investigation.
func WantsInvestigation(uiContext map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(uiContext[UIActionKey]), UIActionInvestigate)
}

// investigationBuilder accumulates the trace.
type investigationBuilder struct {
	tr *InvestigationTrace
}

func (b *investigationBuilder) step(kind, outcome, summary string) {
	if len(b.tr.Steps) >= maxInvestigationSteps {
		return
	}
	b.tr.Steps = append(b.tr.Steps, InvestigationStep{
		Seq: len(b.tr.Steps) + 1, Kind: kind, Outcome: outcome, Summary: clampText(summary, 300),
	})
}

func (b *investigationBuilder) cutoff(reason string) {
	for _, c := range b.tr.Cutoffs {
		if c == reason {
			return
		}
	}
	b.tr.Cutoffs = append(b.tr.Cutoffs, reason)
}

// Investigate runs one bounded, read-only investigation and returns its answer
// with the trace attached (Answer.Investigation). It never returns an error:
// a refusal, a cut-off and an empty scope are all answers that say so.
func (o *Orchestrator) Investigate(ctx context.Context, p Principal, question string, uiContext map[string]string, budget InvestigationBudget) Answer {
	budget = budget.normalized()
	started := time.Now()
	tr := &InvestigationTrace{
		Status: InvestigationStatusNoEvidence, Budget: budget, StartedAt: started.UTC(),
		Question: clampText(strings.TrimSpace(question), maxInvestigationQuestion),
	}
	b := &investigationBuilder{tr: tr}
	finish := func(ans Answer) Answer {
		tr.FinishedAt = time.Now().UTC()
		tr.Used.DurationMS = time.Since(started).Milliseconds()
		if len(tr.Steps) < maxInvestigationSteps {
			b.step(InvStepDiagnosis, diagnosisOutcome(tr.Status), diagnosisSummary(tr))
		}
		ans.Investigation = tr
		if ans.Intent == "" {
			ans.Intent = "investigate"
		}
		return ans
	}

	if !o.InvestigateAllowed {
		tr.Status = InvestigationStatusRefused
		b.step(InvStepStop, InvOutcomeDenied, "AI investigations are off for this workspace")
		return finish(Answer{
			Mode: ModeUnavailable, Intent: "investigate", Title: "Investigation not available",
			Text: InvestigationsOffText, Modules: []string{}, Citations: []Citation{},
		})
	}

	ctx, cancel := context.WithTimeout(ctx, budget.Wall)
	defer cancel()
	meter := &tokenMeter{cap: budget.MaxTokens}
	o.invMeter = meter
	defer func() { o.invMeter = nil }()

	// 1. BIND — once, under the caller's tenant.
	ui := investigationUI(uiContext)
	ent := o.resolveSkillEntities(ctx, p, question, ui)
	var disc []string
	if v := strings.TrimSpace(firstNonEmpty(ui["device_id"], ui["device"])); v != "" {
		if _, ok := ent.get("device_id"); !ok {
			disc = append(disc, "The device in view is not in this workspace's inventory, so the investigation did not use it.")
		}
	}
	tr.Target = InvestigationTarget{DeviceID: ent.values["device_id"], DeviceName: ent.values["device"], CorrelationID: ent.values["correlation_id"]}
	b.step(InvStepBind, bindOutcome(tr.Target), bindSummary(tr.Target))

	// 2. CONTEXT — the customer's approved network context (N-F1) rides in the
	// system prompt of every model call; the trace says whether there was any.
	tr.ContextApplied = strings.TrimSpace(o.orgContextBlock()) != ""
	if tr.ContextApplied {
		b.step(InvStepContext, InvOutcomeOK, "the workspace's approved network context is applied")
	} else {
		b.step(InvStepContext, InvOutcomeNone, "no approved network context for this workspace")
	}

	// 3. EXISTING RCA FIRST.
	toolCalls := 0
	if id := tr.Target.CorrelationID; id != "" {
		toolCalls++
		seed, eng, outcome := o.readEngineVerdict(ctx, p, id)
		switch outcome {
		case InvOutcomeOK:
			o.invSeed = seed
			tr.Engine = eng
			b.step(InvStepRCA, InvOutcomeOK, engineSummary(eng))
		case InvOutcomeNotFound:
			// Unknown OR another tenant's case — indistinguishable, by design.
			delete(ent.values, "correlation_id")
			tr.Target.CorrelationID = ""
			disc = append(disc, "The incident in view is not in this workspace, so the investigation did not use it.")
			b.step(InvStepRCA, InvOutcomeNotFound, "the incident named is not in this workspace")
		default:
			b.step(InvStepRCA, outcome, "the engine's verdict could not be read; the investigation continues without it")
		}
	} else {
		b.step(InvStepRCA, InvOutcomeNone, "no incident in scope — the investigation starts from the evidence")
	}
	defer func() { o.invSeed = nil }()

	// 4. RUNBOOK RETRIEVAL + method candidates.
	cands := o.investigationCandidates(ctx, p, question, ent, tr.Target)
	tr.Candidates = cands
	b.step(InvStepRunbooks, candidatesOutcome(cands), candidatesSummary(cands))

	// 5. PLAN — what each runnable candidate would read, before anything runs.
	var runnable []InvestigationCandidate
	for _, c := range cands {
		if !c.Applies {
			continue
		}
		sk, ok := o.Skills.Get(c.Skill)
		if !ok {
			continue
		}
		steps := planGather(sk, ent)
		if len(steps) == 0 {
			continue
		}
		runnable = append(runnable, c)
		if len(tr.Plan) < budget.MaxPasses {
			tr.Plan = append(tr.Plan, InvestigationPlanStep{Skill: c.Skill, Tools: plannedTools(steps)})
		}
	}
	if len(tr.Plan) > 0 {
		b.step(InvStepPlan, InvOutcomeOK, planSummary(tr.Plan))
	} else {
		b.step(InvStepPlan, InvOutcomeNone, "no method can read evidence for this scope")
	}

	// 6. PASSES — each a bounded skill chain; repeat only while nothing is
	// concluded and the budgets allow.
	boundUI := boundUIContext(ent)
	plan := Plan{Intent: "troubleshoot", Entities: Classify(question, boundUI).Entities}
	visited := map[string]bool{}
	var best *Answer
	bestScore := -1
	for _, c := range runnable {
		if visited[c.Skill] {
			continue // a previous pass's chain already ran it
		}
		if tr.Used.Passes >= budget.MaxPasses {
			b.cutoff(InvCutoffPasses)
			b.step(InvStepStop, InvOutcomeCutoff, "the investigation stopped at its "+strconv.Itoa(budget.MaxPasses)+"-pass budget")
			break
		}
		if tr.Used.Passes > 0 {
			if best != nil && supportedCount(best) > 0 {
				break // concluded: no further pass
			}
			if toolCalls+meter.toolCalls()+MaxChainToolCalls > budget.MaxToolCalls {
				b.cutoff(InvCutoffToolCalls)
				b.step(InvStepStop, InvOutcomeCutoff, "the investigation stopped at its lookup budget — the remaining methods were not run")
				break
			}
			if meter.exhausted() {
				b.cutoff(InvCutoffTokens)
				b.step(InvStepStop, InvOutcomeCutoff, "the investigation stopped at its model-token budget — the remaining methods were not run")
				break
			}
			if !investigationTimeLeft(ctx) {
				b.cutoff(InvCutoffTime)
				b.step(InvStepStop, InvOutcomeCutoff, "the investigation stopped at its time budget — the remaining methods were not run")
				break
			}
		}
		sk, _ := o.Skills.Get(c.Skill)
		tr.Used.Passes++
		o.trace(TracePlanning)
		ans, handled := o.answerSkill(ctx, p, question, plan, SkillMatch{Skill: sk, Score: 1, Reason: c.Why}, boundUI, nil)
		pass := InvestigationPass{Pass: tr.Used.Passes, Entry: c.Skill, Source: c.Source, Answered: handled}
		if handled {
			pass.Chain, pass.Lookups, pass.ToolCalls = ans.Chain, ans.Lookups, len(ans.Lookups)
			pass.Supported, pass.Rejected, pass.Inconclusive = hypothesisCounts(ans.Hypotheses)
			for _, h := range ans.Chain {
				visited[h.Name] = true
			}
		}
		visited[c.Skill] = true
		tr.Passes = append(tr.Passes, pass)
		b.step(InvStepPass, passOutcome(pass), passSummary(pass))
		if handled {
			if s := answerScore(&ans); s > bestScore {
				a := ans
				best, bestScore = &a, s
			}
		}
	}

	// 7. Nothing gathered by any method: the model-with-tools path, under its
	// own bounds (call cap, wall clock, the tenant's daily budget), when the
	// investigation still has time and tokens for it.
	if best == nil && o.AgentAnswer != nil && investigationTimeLeft(ctx) && !meter.exhausted() {
		ans, err := o.AgentAnswer(ctx, p, investigationAgentQuestion(question, tr.Target), nil)
		switch {
		case err == nil && strings.TrimSpace(ans.Text) != "":
			toolCalls += len(ans.Lookups)
			b.step(InvStepAgent, InvOutcomeOK, "no method applied, so the AI model chose read-only lookups itself")
			a := ans
			best = &a
		default:
			b.step(InvStepAgent, InvOutcomeError, "no method applied and the AI model did not answer")
		}
	}

	tr.Used.ToolCalls = toolCalls + meter.toolCalls()
	tr.Used.Tokens = meter.spent()
	if best == nil {
		tr.Status = InvestigationStatusNoEvidence
		return finish(Answer{
			Mode: ModeTroubleshootFinding, Intent: "investigate", Title: "Investigation: no evidence",
			Text: noEvidenceText(tr), Modules: []string{}, Citations: []Citation{},
			Disclaimers:  append(disc, "No evidence rows were returned for this scope."),
			EvidenceOnly: true,
		})
	}
	ans := *best
	ans.Intent = "investigate"
	ans.Disclaimers = append(disc, ans.Disclaimers...)
	if tr.Engine != nil && !hasCitation(ans.Citations, tr.Engine.CitationID) && len(ans.Citations) < skillMaxCitations {
		// The engine's verdict is always on the answer: it is the frame the
		// investigation's findings are read against, never replaced by them.
		ans.Citations = append(ans.Citations, Citation{ID: tr.Engine.CitationID, Kind: "finding",
			Label: clampText(OneLine(tr.Engine.Statement), 80), Class: ClassCorrelixRCA})
	}
	for _, c := range tr.Cutoffs {
		ans.Disclaimers = append(ans.Disclaimers, cutoffDisclosure(c))
	}
	if supportedCount(&ans) > 0 {
		tr.Status = InvestigationStatusConcluded
	} else {
		tr.Status = InvestigationStatusInconclusive
	}
	return finish(ans)
}

// investigationUI keeps only the UI-context keys an investigation binds from:
// the action flag itself and entity ids. Everything else is dropped.
func investigationUI(ui map[string]string) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"device_id", "device", "correlation_id", "problem_id", "interface", "peer", "prefix", "seam"} {
		if v := strings.TrimSpace(ui[k]); v != "" {
			out[k] = v
		}
	}
	return out
}

// boundUIContext is the server-resolved binding handed to every pass, so a
// pass re-resolves exactly what the investigation bound — never more.
func boundUIContext(ent skillEntitySet) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"device_id", "correlation_id", "interface", "peer", "prefix", "seam"} {
		if v, ok := ent.get(k); ok {
			out[k] = v
		}
	}
	return out
}

// readEngineVerdict reads the engine's verdict for one case through the
// gateway (policy, contract, audit) — the first read of the investigation.
func (o *Orchestrator) readEngineVerdict(ctx context.Context, p Principal, id string) (*investigationSeed, *InvestigationEngine, string) {
	const tool = "get_rca_verdict"
	args := ToolArgs{"correlation_id": id}
	iv := o.Toolbox().Invoke(ctx, p, tool, args)
	o.auditInvocation(tool, args, iv)
	switch {
	case iv.Outcome == OutcomePolicyDenied || iv.Outcome == OutcomeRateLimited:
		return nil, nil, InvOutcomeDenied
	case iv.Outcome == OutcomeNotRegistered:
		return nil, nil, InvOutcomeNone
	case !iv.OK() && errors.Is(iv.Err, ErrNotFound):
		return nil, nil, InvOutcomeNotFound
	case !iv.OK():
		return nil, nil, InvOutcomeError
	}
	seed := &investigationSeed{tool: tool, signals: iv.Result.Signals, items: iv.Result.Items}
	eng := &InvestigationEngine{}
	for _, ev := range iv.Result.Items {
		if strings.HasPrefix(ev.CitationID, engineVerdictCitePrefix) {
			eng.Tier = strings.ToLower(strings.TrimSpace(ev.Verdict))
			eng.Statement = clampText(OneLine(ev.Text), 300)
			eng.CitationID = ev.CitationID
			break
		}
	}
	return seed, eng, InvOutcomeOK
}

// investigationCandidates is runbook retrieval plus method selection, in
// priority order, deduped and checked for applicability.
func (o *Orchestrator) investigationCandidates(ctx context.Context, p Principal, question string, ent skillEntitySet, t InvestigationTarget) []InvestigationCandidate {
	if o.Skills == nil {
		return nil
	}
	facts := newChainFacts()
	facts.device, facts.deviceRead, facts.deviceName = ent.facts, ent.factsRead, ent.values["device"]
	seen := map[string]bool{}
	var out []InvestigationCandidate
	add := func(sk *Skill, source, why string) {
		if sk == nil || seen[sk.Name] || sk.isMOP() || len(out) >= maxInvestigationCandidates {
			return
		}
		seen[sk.Name] = true
		a := facts.applicability(sk)
		c := InvestigationCandidate{Skill: sk.Name, Source: source, CustomerAuthored: sk.customerAuthored(), Applies: a.Applies, Why: why}
		if !a.Applies {
			c.Why = notApplicableNote(sk, a, facts.deviceName, facts.device)
		}
		out = append(out, c)
	}
	// (a) The tenant's runbooks linked to this incident or device. Only names
	// present in the caller's own skill set (approved, runnable, investigative)
	// can be added — a name from anywhere else resolves to nothing.
	if o.RunbooksFor != nil && (t.CorrelationID != "" || t.DeviceID != "") {
		names := o.RunbooksFor(ctx, p, t)
		sort.Strings(names)
		for _, n := range names {
			if sk, ok := o.Skills.Get(n); ok && sk.customerAuthored() {
				add(sk, InvSourceRunbookLink, "your team linked the runbook "+humanizeSkillName(sk.Name)+" to "+linkedTo(t))
			}
		}
	}
	// (b) The method the question selects.
	if m, ok := SelectSkill(o.Skills, question, Plan{Intent: "troubleshoot", Entities: Classify(question, boundUIContext(ent)).Entities}); ok {
		add(m.Skill, InvSourceSelected, m.Reason)
	}
	// (c) The top-level method.
	if m := o.entryMethod(); m != nil {
		add(m, InvSourceEntry, "the top-level method narrows the problem layer by layer")
	}
	return out
}

func linkedTo(t InvestigationTarget) string {
	switch {
	case t.CorrelationID != "" && t.DeviceName != "":
		return "this incident or " + t.DeviceName
	case t.CorrelationID != "":
		return "this incident"
	default:
		return firstNonEmpty(t.DeviceName, "this device")
	}
}

// investigationAgentQuestion gives the model-with-tools path the bound scope
// in words (names the server resolved, never ids it did not).
func investigationAgentQuestion(question string, t InvestigationTarget) string {
	q := strings.TrimSpace(question)
	if q == "" {
		q = "Investigate what is wrong."
	}
	var scope []string
	if t.DeviceName != "" {
		scope = append(scope, "device "+t.DeviceName)
	}
	if t.CorrelationID != "" {
		scope = append(scope, "incident "+t.CorrelationID)
	}
	if len(scope) == 0 {
		return q
	}
	return q + "\n\n(Scope of this investigation: " + strings.Join(scope, " and ") + ".)"
}

// investigationTimeLeft reports whether another pass may start.
func investigationTimeLeft(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	dl, ok := ctx.Deadline()
	return !ok || time.Until(dl) > investigationPassReserve
}

// hypothesisCounts counts a set's terminal states.
func hypothesisCounts(set *irishypo.Set) (supported, rejected, inconclusive int) {
	if set == nil {
		return 0, 0, 0
	}
	for _, h := range set.Hypotheses {
		switch h.State {
		case irishypo.Supported:
			supported++
		case irishypo.Rejected:
			rejected++
		case irishypo.Inconclusive:
			inconclusive++
		}
	}
	return supported, rejected, inconclusive
}

func supportedCount(a *Answer) int {
	if a == nil {
		return 0
	}
	s, _, _ := hypothesisCounts(a.Hypotheses)
	return s
}

// answerScore ranks a pass's answer for the diagnosis: a supported line of
// investigation first, then cited evidence.
func answerScore(a *Answer) int {
	return supportedCount(a)*100 + len(a.Citations)
}

func hasCitation(cs []Citation, id string) bool {
	if id == "" {
		return true
	}
	for _, c := range cs {
		if c.ID == id {
			return true
		}
	}
	return false
}

// ---- server-written trace wording ------------------------------------------

func bindOutcome(t InvestigationTarget) string {
	if t.DeviceID == "" && t.CorrelationID == "" {
		return InvOutcomeNone
	}
	return InvOutcomeOK
}

func bindSummary(t InvestigationTarget) string {
	switch {
	case t.DeviceName != "" && t.CorrelationID != "":
		return "investigating " + t.DeviceName + " within incident " + t.CorrelationID
	case t.DeviceName != "":
		return "investigating " + t.DeviceName
	case t.CorrelationID != "":
		return "investigating incident " + t.CorrelationID
	}
	return "no device or incident named — investigating from the question"
}

func engineSummary(e *InvestigationEngine) string {
	if e == nil || e.Tier == "" {
		return "the engine's case was read first; it holds no verdict yet"
	}
	return "the engine's verdict was read first (" + e.Tier + "): the investigation is read against it, never instead of it"
}

func candidatesOutcome(cs []InvestigationCandidate) string {
	for _, c := range cs {
		if c.Applies {
			return InvOutcomeOK
		}
	}
	return InvOutcomeNone
}

func candidatesSummary(cs []InvestigationCandidate) string {
	if len(cs) == 0 {
		return "no method or runbook matches this scope"
	}
	runbooks, applies := 0, 0
	for _, c := range cs {
		if c.Source == InvSourceRunbookLink {
			runbooks++
		}
		if c.Applies {
			applies++
		}
	}
	s := plural(len(cs), "method") + " considered, " + strconv.Itoa(applies) + " applicable"
	if runbooks > 0 {
		s += "; " + plural(runbooks, "runbook") + " your team linked to this scope"
	}
	return s
}

func planSummary(ps []InvestigationPlanStep) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		labels := make([]string, 0, len(p.Tools))
		for _, t := range p.Tools {
			labels = append(labels, ToolLabel(t))
		}
		parts = append(parts, humanizeSkillName(p.Skill)+" ("+strings.Join(labels, ", ")+")")
	}
	return "plan: " + strings.Join(parts, " → ")
}

func passOutcome(p InvestigationPass) string {
	if !p.Answered {
		return InvOutcomeNone
	}
	return InvOutcomeOK
}

func passSummary(p InvestigationPass) string {
	if !p.Answered {
		return "pass " + strconv.Itoa(p.Pass) + ": the " + humanizeSkillName(p.Entry) + " method gathered no evidence"
	}
	hops := make([]string, 0, len(p.Chain))
	for _, h := range p.Chain {
		hops = append(hops, humanizeSkillName(h.Name))
	}
	return fmt.Sprintf("pass %d: %s — %s; %d supported, %d rejected, %d inconclusive",
		p.Pass, strings.Join(hops, " → "), plural(p.ToolCalls, "lookup"), p.Supported, p.Rejected, p.Inconclusive)
}

func diagnosisOutcome(status string) string {
	switch status {
	case InvestigationStatusConcluded, InvestigationStatusInconclusive:
		return InvOutcomeOK
	case InvestigationStatusRefused:
		return InvOutcomeDenied
	}
	return InvOutcomeNone
}

func diagnosisSummary(tr *InvestigationTrace) string {
	switch tr.Status {
	case InvestigationStatusConcluded:
		return "diagnosis written from what the checks observed; the engine alone names a root cause"
	case InvestigationStatusInconclusive:
		return "evidence gathered, but no line of investigation was supported — the diagnosis says what is still unknown"
	case InvestigationStatusRefused:
		return "no investigation was run"
	}
	return "nothing could be gathered for this scope"
}

func noEvidenceText(tr *InvestigationTrace) string {
	scope := bindSummary(tr.Target)
	return "The investigation could not gather any evidence (" + scope + "). " +
		"No applicable method could read data for this scope, so nothing is concluded. " +
		"Check that the device is monitored and reachable by Correlix, or name the symptom you see."
}

func cutoffDisclosure(c string) string {
	switch c {
	case InvCutoffPasses:
		return "The investigation stopped at its pass budget; methods it did not reach were not run."
	case InvCutoffToolCalls:
		return "The investigation stopped at its lookup budget; methods it did not reach were not run."
	case InvCutoffTokens:
		return "The investigation stopped at its AI-model budget; methods it did not reach were not run."
	case InvCutoffTime:
		return "The investigation stopped at its time budget; methods it did not reach were not run."
	}
	return "The investigation was cut short."
}
