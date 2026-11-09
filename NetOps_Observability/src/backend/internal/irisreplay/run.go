// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
)

// caseBudget bounds one case. Everything is in memory, so it only ever fires on
// a defect, and a defect must not hang the runner.
const caseBudget = 2 * time.Minute

// ModelLeg supplies the model for one case. ScriptedLeg is the only
// implementation: this package never calls a provider. A live leg is a later,
// separately gated item.
type ModelLeg interface {
	// Name is recorded in the report and the fingerprint.
	Name() string
	// Client returns the model for this case.
	Client(c *Case) (ai.LLMClient, error)
}

// ScriptedLeg answers with the case's scripted reply through the mock LLM, or
// fails like a provider that is down.
type ScriptedLeg struct{}

// Name implements ModelLeg.
func (ScriptedLeg) Name() string { return "scripted" }

// errProviderDown is the failure of a case's scripted provider outage.
var errProviderDown = errors.New("replay: provider down")

// Client implements ModelLeg.
func (ScriptedLeg) Client(c *Case) (ai.LLMClient, error) {
	if c.ProviderDown {
		return ai.MockLLM{Err: errProviderDown}, nil
	}
	return ai.MockLLM{Reply: c.ModelReply}, nil
}

// Price is the configured price of one model, per million tokens.
type Price struct {
	InputPerMTok  float64 `json:"input_per_mtok"`
	OutputPerMTok float64 `json:"output_per_mtok"`
}

// Options configures a run.
type Options struct {
	// Leg supplies the model; nil means ScriptedLeg.
	Leg ModelLeg
	// Skills is the method catalog; nil loads the compiled-in one.
	Skills *ai.SkillSet
	// Prices maps "<provider>/<name>" to a price. Without one, cost is censored.
	Prices map[string]Price
	// EngineSemver and CatalogVersion are what the reader runs now, compared
	// with each case's pins. Empty means not checked.
	EngineSemver   string
	CatalogVersion string
	// Now stamps the report (default time.Now).
	Now func() time.Time
}

// toolCall is one call as the gateway traced it.
type toolCall struct {
	Name    string
	Outcome string // the trace vocabulary: ok | denied | not_wired | not_found | error
}

// collector is the trace, audit and score sink of one case.
type collector struct {
	mu            sync.Mutex
	calls         []toolCall
	audit         []ai.ToolAuditEntry
	guards        map[string]int
	providerCalls int
	inTok, outTok int64
	allReported   bool
}

func newCollector() *collector {
	return &collector{guards: map[string]int{}, allReported: true}
}

// Trace implements ai.TraceSink.
func (col *collector) Trace(e ai.TraceEvent) {
	col.mu.Lock()
	defer col.mu.Unlock()
	switch e.Type {
	case ai.TraceToolStarted:
		col.calls = append(col.calls, toolCall{Name: e.Tool})
	case ai.TraceToolFinished:
		for i := len(col.calls) - 1; i >= 0; i-- {
			if col.calls[i].Name == e.Tool && col.calls[i].Outcome == "" {
				col.calls[i].Outcome = e.Outcome
				break
			}
		}
	}
}

func (col *collector) recordAudit(e ai.ToolAuditEntry) {
	col.mu.Lock()
	defer col.mu.Unlock()
	col.audit = append(col.audit, e)
}

// AnswerObserved implements ai.ScoreSink.
func (col *collector) AnswerObserved(ai.AnswerScore) {}

// InvestigationObserved implements ai.ScoreSink.
func (col *collector) InvestigationObserved(ai.InvestigationScore) {}

// GuardObserved implements ai.ScoreSink.
func (col *collector) GuardObserved(guard string, removed int) {
	col.mu.Lock()
	defer col.mu.Unlock()
	col.guards[guard] += removed
}

// ProviderObserved implements ai.ScoreSink.
func (col *collector) ProviderObserved(s ai.ProviderScore) {
	col.mu.Lock()
	defer col.mu.Unlock()
	col.providerCalls++
	if !s.Usage.Reported {
		col.allReported = false
		return
	}
	col.inTok += s.Usage.InputTokens
	col.outTok += s.Usage.OutputTokens
}

// recordingLLM records every prompt and carries the case's scripted usage, so
// that token accounting takes the same seam the server's client takes.
type recordingLLM struct {
	inner           ai.LLMClient
	usage           *ai.ReplayUsage
	mu              sync.Mutex
	prompts, system []string
}

func (l *recordingLLM) record(system string, msgs []ai.LLMMessage) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.system = append(l.system, system)
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			l.prompts = append(l.prompts, msgs[i].Content)
			break
		}
	}
}

// Complete implements ai.LLMClient.
func (l *recordingLLM) Complete(ctx context.Context, system string, msgs []ai.LLMMessage) (string, string, error) {
	l.record(system, msgs)
	return l.inner.Complete(ctx, system, msgs)
}

// CompleteTier implements ai.TieredLLMClient.
func (l *recordingLLM) CompleteTier(ctx context.Context, _ ai.ModelTier, system string, msgs []ai.LLMMessage) (string, string, error) {
	return l.Complete(ctx, system, msgs)
}

// CompleteTierWithUsage implements ai.LLMUsageClient. A scripted call reports
// tokens only when the case states them: nothing here estimates a token.
func (l *recordingLLM) CompleteTierWithUsage(ctx context.Context, _ ai.ModelTier, system string, msgs []ai.LLMMessage) (string, string, ai.TokenUsage, error) {
	text, provider, err := l.Complete(ctx, system, msgs)
	if err != nil || l.usage == nil {
		return text, provider, ai.TokenUsage{}, err
	}
	return text, provider, ai.TokenUsage{InputTokens: l.usage.InputTokens, OutputTokens: l.usage.OutputTokens, Reported: true}, nil
}

// execution is one case's raw result, before it is measured.
type execution struct {
	outcome ai.ReplayOutcome
	col     *collector
	ledger  []aidecision.Entry
	dropped int
	frozen  *Frozen
	elapsed time.Duration
}

// flagsFor is the feature-flag view of a path: the corpus runs the classic ask
// path with optional modules off, and the skill and RCA paths with them on.
func flagsFor(c *Case) ai.FlagLookup {
	on := c.Path != ai.ReplayPathAsk
	return func(string) bool { return on }
}

// execute runs one case through the real answer path over its frozen seams.
func execute(ctx context.Context, c *Case, opt Options, skills *ai.SkillSet) (*execution, error) {
	frozen, err := Freeze(c)
	if err != nil {
		return nil, err
	}
	leg := opt.Leg
	if leg == nil {
		leg = ScriptedLeg{}
	}
	inner, err := leg.Client(c)
	if err != nil {
		return nil, fmt.Errorf("model leg: %w", err)
	}
	llm := &recordingLLM{inner: inner}
	if c.Model != nil {
		llm.usage = c.Model.ScriptedUsage
	}
	col := newCollector()
	flags := flagsFor(c)
	cfg := ai.PolicyConfig{}
	if c.Policy != nil {
		cfg = *c.Policy
	}
	o := &ai.Orchestrator{
		DS:           frozen.DS,
		Tools:        frozen.Registry,
		LLM:          llm,
		Flags:        flags,
		Policy:       ai.NewPolicyEngine(cfg, flags),
		Troubleshoot: frozen.Deps,
		Gateway:      ai.NewToolGateway(),
		Trace:        col,
		ToolAudit:    col.recordAudit,
		Score:        col,
	}
	if c.Path == ai.ReplayPathSkill {
		o.Skills = skills
	}
	if len(c.ContextFacts) > 0 {
		block := strings.Join(c.ContextFacts, "\n")
		o.OrgContext = func() string { return block }
	}

	p := c.CallerPrincipal()
	ctx, cancel := context.WithTimeout(ctx, caseBudget)
	defer cancel()
	started := time.Now()
	ans, notFound, err := answer(ctx, o, p, c)
	if err != nil {
		return nil, err
	}
	askModelRequests(ctx, o, p, c, col)
	elapsed := time.Since(started)

	outcome, err := ai.NewReplayOutcome(ans, notFound, llm.prompts, llm.system)
	if err != nil {
		return nil, err
	}
	ledger, dropped, err := buildLedger(c, ans, col)
	if err != nil {
		return nil, err
	}
	return &execution{outcome: outcome, col: col, ledger: ledger, dropped: dropped, frozen: frozen, elapsed: elapsed}, nil
}

// answer runs the case's path. All three are production code.
func answer(ctx context.Context, o *ai.Orchestrator, p ai.Principal, c *Case) (ai.Answer, bool, error) {
	switch c.Path {
	case ai.ReplayPathAsk:
		ans, err := o.Ask(ctx, p, c.Question, c.UI)
		if err != nil {
			return ai.Answer{}, false, fmt.Errorf("ask: %w", err)
		}
		return ans, ans.Mode == ai.ModeProblemExplanation && ans.Problem == nil, nil
	case ai.ReplayPathSkill:
		ans, handled, err := o.AnswerNamedSkill(ctx, p, c.Question, c.Skill, c.UI)
		if err != nil {
			return ai.Answer{}, false, err
		}
		if !handled {
			return ai.Answer{}, false, errors.New("the skill turn gathered nothing and was not handled")
		}
		return ans, false, nil
	case ai.ReplayPathRCATool:
		return answerRCATool(ctx, o, p, c)
	}
	return ai.Answer{}, false, fmt.Errorf("unknown path %q", c.Path)
}

// answerRCATool runs one RCA tool through the gateway. A tool result is what the
// model is shown, so its lines are the "answer" this path ships into the prompt.
func answerRCATool(ctx context.Context, o *ai.Orchestrator, p ai.Principal, c *Case) (ai.Answer, bool, error) {
	args := ai.ToolArgs{"correlation_id": c.UI["correlation_id"]}
	iv := o.Toolbox().Invoke(ctx, p, c.RCATool, args)
	auditInvocation(o.ToolAudit, c.RCATool, args, iv)
	switch {
	case iv.Outcome == "not_found":
		return ai.Answer{}, true, nil
	case !iv.OK():
		return ai.Answer{}, false, fmt.Errorf("%s: %s", c.RCATool, iv.Outcome)
	}
	var ans ai.Answer
	lines := make([]string, 0, len(iv.Result.Items))
	for _, it := range iv.Result.Items {
		ans.Citations = append(ans.Citations, ai.Citation{ID: it.CitationID, Kind: it.Kind, Label: it.Text, Href: it.Href})
		lines = append(lines, it.Text)
	}
	ans.Text = strings.Join(lines, "\n")
	ans.Disclaimers = iv.Result.Notes
	return ans, false, nil
}

// askModelRequests puts each scripted model tool request to the gateway, as the
// agent loop would. The result is not fed back: this leg has no loop, and what
// it measures is what the gateway did with the request.
func askModelRequests(ctx context.Context, o *ai.Orchestrator, p ai.Principal, c *Case, col *collector) {
	tb := o.Toolbox()
	for _, r := range c.ModelToolRequests {
		args := ai.ToolArgs(r.Args)
		iv := tb.Invoke(ctx, p, r.Tool, args)
		if iv.Outcome != ai.OutcomeNotRegistered {
			auditInvocation(col.recordAudit, r.Tool, args, iv)
		}
	}
}

// auditInvocation is the audit record of a call this runner itself made, built
// the way the orchestrator builds its own.
func auditInvocation(sink func(ai.ToolAuditEntry), tool string, args ai.ToolArgs, iv ai.Invocation) {
	e := ai.ToolAuditEntry{Tool: tool, Allowed: iv.Outcome != ai.OutcomePolicyDenied && iv.Outcome != ai.OutcomeRateLimited,
		Reason: iv.Outcome, ArgsSHA256: ai.HashToolArgs(args), Truncated: iv.Truncated}
	if iv.OK() {
		e.Items, e.ResultSHA256 = len(iv.Result.Items), ai.HashToolResult(iv.Result)
	}
	sink(e)
}

// buildLedger writes what the server's ledger would hold for this decision,
// through the production mapping, so that audit completeness is measured against
// the real vocabulary. Nothing is stored.
func buildLedger(c *Case, ans ai.Answer, col *collector) ([]aidecision.Entry, int, error) {
	rec, err := aidecision.NewRecorder("replay", aidecision.SurfaceAsk)
	if err != nil {
		return nil, 0, fmt.Errorf("ledger: %w", err)
	}
	rec.Add(aidecision.Entry{EventType: aidecision.QuestionReceived, IncidentRef: c.UI["correlation_id"],
		ArgsSHA256: aidecision.SHA256Hex([]byte(c.Question))})
	col.mu.Lock()
	audit := append([]ai.ToolAuditEntry(nil), col.audit...)
	col.mu.Unlock()
	for _, e := range audit {
		rec.AddToolStep(aidecision.ToolStep{Skill: e.Skill, Tool: e.Tool, Selected: e.Selected, Reason: e.Reason,
			Items: e.Items, ArgsSHA256: e.ArgsSHA256, ResultSHA256: e.ResultSHA256, Truncated: e.Truncated}, "replay")
	}
	cites := make([]string, 0, len(ans.Citations))
	for _, ci := range ans.Citations {
		cites = append(cites, ci.ID)
	}
	rec.AddEvidence(cites)
	rec.Add(aidecision.Entry{EventType: aidecision.AnswerReturned})
	return rec.Entries(), rec.Dropped(), nil
}

// answerHash is the SHA-256 of the answer with the ids a run mints removed.
func answerHash(ans ai.Answer) (string, error) {
	ans.AnswerID = ""
	b, err := json.Marshal(ans)
	if err != nil {
		return "", fmt.Errorf("marshal answer: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// promptsHash is the SHA-256 of everything the model was sent.
func promptsHash(systems, prompts []string) string {
	h := sha256.New()
	for _, part := range [][]string{systems, prompts} {
		for _, s := range part {
			h.Write([]byte(s))
			h.Write([]byte{0})
		}
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Run replays the cases in order and returns the report. A case that cannot run
// is a FAIL with the reason, never a skip.
func Run(ctx context.Context, cases []Case, opt Options) (Report, error) {
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	skills := opt.Skills
	if skills == nil {
		s, err := ai.LoadSkills()
		if err != nil {
			return Report{}, fmt.Errorf("load skills: %w", err)
		}
		skills = s
	}
	leg := opt.Leg
	if leg == nil {
		leg = ScriptedLeg{}
	}
	in, err := CurrentInputs(cases, opt, leg)
	if err != nil {
		return Report{}, err
	}
	rep := Report{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   now().UTC().Format(time.RFC3339),
		ModelLeg:      leg.Name(),
		Fingerprint:   ComputeFingerprint(in),
		Limits:        reportLimits(),
	}
	for i := range cases {
		c := &cases[i]
		ex, err := execute(ctx, c, opt, skills)
		rep.Cases = append(rep.Cases, measureCase(c, ex, err, opt))
	}
	rep.Aggregate = aggregate(rep.Cases)
	return rep, nil
}
