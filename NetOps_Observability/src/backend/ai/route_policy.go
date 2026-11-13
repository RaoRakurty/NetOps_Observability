// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// route_policy.go — who answers a question: the deterministic arms or the
// model (owner routing policy, 2026-11-12).
//
// Live lab evidence that day: "Check RCA and identify the one which has
// confirmed" was answered "I didn't quite catch that" with a healthy model
// connected — the deterministic router missed and nobody asked the model; and
// "which tenant are we in and how many devices are connected and how are they
// discovered?" was answered by ONE keyword-matched module ("integrations …
// nothing to report"). The zero-model NLU goal was dropped on 2026-11-09:
// hosted models are expected. The policy:
//
//  1. The deterministic path answers only when it covers the WHOLE question:
//     one recognised intent, or every part of a multi-part question mapped.
//  2. Otherwise — a deterministic miss (no intent), or a multi-part question
//     with a part nothing deterministic answers — the question goes to the
//     model, grounded in the caller's tenant-scoped data (§15: server-owned
//     system prompt, data fenced as data, output verified against the
//     citations it was given, bounded calls and tokens, one strike per request).
//  3. "I didn't quite catch that" is returned only when no model answered —
//     none connected, timed out, paused, or the day's budget spent — and the
//     answer says which.
//  4. Every answer carries the decision (Answer.Routing): the server logs it
//     and counts it by reason, so a miss is visible in the api log.
//
// A problem in view (the RCA workspace passes its correlation_id) is the
// default subject of every question asked there: it is answered by the
// grounded explanation of THAT problem, never by product help, unless the
// question is explicitly about the product's screens (ProblemInView).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"netops/backend/internal/nlquery/lex"
)

// ModeModelAnswer is a question the deterministic arms could not cover,
// answered by the model from the caller's own data (route_policy.go).
const ModeModelAnswer AnswerMode = "model_answer"

// Routing is the routing decision of one answer.
type Routing struct {
	Path   string `json:"path"`   // RoutePath*
	Reason string `json:"reason"` // RouteReason*
}

// Routing paths (closed).
const (
	RoutePathDeterministic    = "deterministic"     // answered without a model deciding the content
	RoutePathModel            = "model"             // the model answered (grounded)
	RoutePathModelUnavailable = "model_unavailable" // the model was needed and did not answer
)

// Routing reasons (closed).
const (
	RouteReasonCovered         = "covered"            // one recognised intent covered the question
	RouteReasonCompoundCovered = "compound_covered"   // every part of a multi-part question was covered
	RouteReasonMiss            = "deterministic_miss" // no deterministic intent at all
	RouteReasonCompound        = "compound_uncovered" // a part of a multi-part question was not covered
	RouteReasonProblemContext  = "problem_context"    // the problem in view is the subject
)

// RoutePaths and RouteReasons are the closed vocabularies (metrics, tests).
var (
	RoutePaths   = []string{RoutePathDeterministic, RoutePathModel, RoutePathModelUnavailable}
	RouteReasons = []string{RouteReasonCovered, RouteReasonCompoundCovered, RouteReasonMiss, RouteReasonCompound, RouteReasonProblemContext,
		RouteReasonPlanner, RouteReasonPlannerUnavailable}
)

// ScopeFacts is the caller's own scope, stamped by the server from the
// authenticated token — never from the question or a request body.
type ScopeFacts struct {
	TenantID   string
	TenantName string
	// AllTenants: the platform owner's cross-tenant "All tenants" view.
	AllTenants bool
	// Provider: the platform owner narrowed to the platform's own rows.
	Provider bool
}

// SourceCount is how many in-scope devices one discovery source reported.
type SourceCount struct {
	Source string // the raw source token ("snmp", "api:vmanage", …)
	Label  string // the operator's words for it
	Count  int
}

// InventoryFacts is the caller's device inventory in aggregate: counts only,
// read through the caller's own visibility (the server's seam).
type InventoryFacts struct {
	Total    int
	BySource []SourceCount // largest first
}

// AgentAnswerFunc is the server's model-with-tools path (the bounded agent
// loop over the same registry and policy engine, copilot_agent.go). It returns
// ErrAgentUnavailable when the caller is not entitled to it, so the in-package
// grounded answer runs instead.
type AgentAnswerFunc func(ctx context.Context, p Principal, question string, prior []string) (Answer, error)

// ErrAgentUnavailable: the agent loop is not available to this caller.
var ErrAgentUnavailable = errors.New("the AI investigation tools are not available to this caller")

// ── multi-part questions ────────────────────────────────────────────────────

var (
	// reScopeQuestion asks which tenant / workspace the caller is in.
	reScopeQuestion = regexp.MustCompile(`(?i)\b(?:which|what)\s+(?:tenant|workspace|org|organi[sz]ation|customer|account)\b[^?]*\b(?:am\s+i|are\s+we|i'?m|we'?re|is\s+this|this\s+is|in)\b|\b(?:my|our|current)\s+(?:tenant|workspace)\b|\bwho\s+am\s+i\b`)
	// reDiscoveryQuestion asks how devices came to be in the inventory.
	reDiscoveryQuestion = regexp.MustCompile(`(?i)\bhow\s+(?:are|were|is|was|did|do)\b[^?]*\b(?:discover\w*|onboard\w*|found|added|learn\w*|imported|detected)\b|\b(?:discovery|onboarding)\s+(?:method|source|type|mode)s?\b|\bwhere\s+(?:do|did)\s+(?:the\s+|my\s+|our\s+)?devices\s+come\s+from\b|\bsources?\s+of\s+(?:the\s+|my\s+|our\s+)?devices\b|\bhow\s+(?:are|were)\s+(?:they|the\s+devices|devices|these)\s+(?:discovered|found|added)\b`)
)

// partAnswer is one answered part of a multi-part question.
type partAnswer struct {
	q    string
	text string
	data DataAnswer
	ok   bool
}

// scopeAnswer answers "which tenant are we in" from the caller's token.
func scopeAnswer(sf ScopeFacts) string {
	switch {
	case sf.AllTenants:
		return "You are in the platform owner's All tenants view: answers cover every tenant, each row labelled with its tenant. Pick a tenant in the tenant switcher to narrow the view."
	case sf.Provider:
		return "You are in the Provider view: the platform's own devices and data, not any customer tenant's."
	}
	name := strings.TrimSpace(sf.TenantName)
	id := strings.TrimSpace(sf.TenantID)
	switch {
	case name != "" && id != "" && !strings.EqualFold(name, id):
		return fmt.Sprintf("You are in tenant %s (%s).", name, id)
	case name != "":
		return fmt.Sprintf("You are in tenant %s.", name)
	case id != "":
		return fmt.Sprintf("You are in tenant %s.", id)
	}
	return "Your sign-in does not name a tenant."
}

// discoveryAnswer answers "how were the devices discovered" from the
// inventory's per-device source.
func discoveryAnswer(inv InventoryFacts) string {
	if inv.Total == 0 {
		return "There are no devices in your inventory yet, so nothing has been discovered."
	}
	srcs := append([]SourceCount(nil), inv.BySource...)
	sort.SliceStable(srcs, func(i, j int) bool { return srcs[i].Count > srcs[j].Count })
	var parts []string
	for _, s := range srcs {
		parts = append(parts, fmt.Sprintf("%d by %s", s.Count, s.Label))
	}
	return fmt.Sprintf("Of the %s in your inventory: %s.", plural(inv.Total, "device"), strings.Join(parts, ", "))
}

// compoundCoverage answers what it can of a multi-part question.
//
// covered: every part answered deterministically. classicOnly: no part is
// answerable here but every part has a recognised classic intent — the
// normal path answers the whole question as before (one briefing covers
// "what's going on? what should we focus on first?"). Anything else is a
// question no deterministic arm covers whole.
func (o *Orchestrator) compoundCoverage(ctx context.Context, p Principal, parts []string) (answers []partAnswer, covered, classicOnly bool) {
	answered, claimable := 0, 0
	for _, part := range parts {
		pa := partAnswer{q: part}
		pl := Classify(part, nil)
		switch {
		case o.Scope != nil && reScopeQuestion.MatchString(part):
			pa.text, pa.ok = scopeAnswer(*o.Scope), true
		case o.Inventory != nil && reDiscoveryQuestion.MatchString(part):
			if inv, err := o.Inventory(ctx, p); err == nil {
				pa.text, pa.ok = discoveryAnswer(inv), true
			}
		case o.NLQuery != nil && pl.Intent != "problem_explanation" && !diagnosticCue.MatchString(part) && !listingCue.MatchString(part):
			// The grammar only: a part is never worth a model compile on its own.
			if d, err := o.NLQuery(ctx, p, part, DataOpts{ClassicIntent: pl.Intent}); err == nil && d.Status == DataAnswered {
				pa.text, pa.data, pa.ok = d.Text, d, true
			}
		}
		if pa.ok {
			answered++
		} else if pl.Intent != "capability" {
			claimable++
		}
		answers = append(answers, pa)
	}
	return answers, answered == len(parts), answered == 0 && claimable == len(parts)
}

// composeParts is the one answer to a multi-part question: each part under
// its own question, in order.
func composeParts(parts []partAnswer) Answer {
	type wirePart struct {
		Question string          `json:"question"`
		Intent   string          `json:"intent,omitempty"`
		Text     string          `json:"text"`
		Data     json.RawMessage `json:"data,omitempty"`
	}
	var text []string
	var cits []Citation
	var notes []string
	seen := map[string]bool{}
	payload := make([]wirePart, 0, len(parts))
	for _, pa := range parts {
		if !pa.ok {
			continue
		}
		text = append(text, pa.q+"\n"+pa.text)
		cits = append(cits, pa.data.Citations...)
		for _, n := range pa.data.Notes {
			if !seen[n] {
				seen[n] = true
				notes = append(notes, n)
			}
		}
		payload = append(payload, wirePart{Question: pa.q, Intent: pa.data.Intent, Text: pa.text, Data: pa.data.Payload})
	}
	if cits == nil {
		cits = []Citation{}
	}
	ans := Answer{Mode: ModeDataQuery, Intent: IntentMultiQuestion, Modules: []string{},
		Text: strings.Join(text, "\n\n"), Citations: cits, Disclaimers: nonEmptyList(notes)}
	if raw, err := json.Marshal(map[string]any{"parts": payload}); err == nil {
		ans.Data = raw // the structured parts for API consumers; the text stands alone without it
	}
	return ans
}

// ── the model path ──────────────────────────────────────────────────────────

// maxModelEvidence bounds the evidence block of one grounded model answer.
const maxModelEvidence = 25

// answerByModel hands a question the deterministic arms could not cover to
// the model, grounded in the caller's data. The agent loop (tools chosen by
// the model, every call re-authorized) runs when the server wired it and the
// caller is entitled; otherwise one strong-tier call answers from a bounded,
// server-gathered evidence block — the caller's active problems, inventory and
// scope — and its citations are verified against that block. ok=false means
// no model answered; err says why (the caller writes the honest answer).
func (o *Orchestrator) answerByModel(ctx context.Context, p Principal, question, intent, reason string) (Answer, bool, error) {
	if o.AgentAnswer != nil {
		ans, err := o.AgentAnswer(ctx, p, question, o.PriorQuestions)
		if err == nil {
			ans.Intent = intent
			ans.Routing = &Routing{Path: RoutePathModel, Reason: reason}
			return ans, true, nil
		}
		if !errors.Is(err, ErrAgentUnavailable) {
			return Answer{}, false, err
		}
	}
	if o.LLM == nil {
		return Answer{}, false, ErrNoProvider
	}
	ev, sc := o.modelEvidence(ctx, p, question)
	o.trace(TraceNarrating)
	text, provider, lerr := o.completeTier(ctx, RouteFor(ModeModelAnswer).Tier, o.systemPrompt(),
		[]LLMMessage{{Role: "user", Content: o.modelAnswerPrompt(question, ev, o.glossaryText(ctx, p))}}, false)
	if lerr != nil || strings.TrimSpace(text) == "" {
		if lerr == nil {
			lerr = &ProviderEmptyError{Provider: provider}
		}
		return Answer{}, false, lerr
	}
	ids := make([]string, 0, len(ev))
	for _, e := range ev {
		ids = append(ids, e.CitationID)
	}
	var badges, disc []string
	text, badges, disc = o.verifyNarrative(strings.TrimSpace(text), ids, badges, disc)
	fallback := "I could not answer that from your Correlix data."
	text, statements, badges, disc := o.applyStatementClasses(text, fallback, ClassCorrelixRCA, sc, badges, disc)
	for i := range statements {
		statements[i].Text = Scrub(statements[i].Text)
	}
	statements = trimStatements(statements)
	if len(statements) > 0 {
		text = joinStatements(statements)
	}
	// Only the evidence the answer actually cites is offered as a citation.
	var cites []Citation
	for _, e := range ev {
		if strings.Contains(text, e.CitationID) {
			cites = append(cites, Citation{ID: e.CitationID, Kind: e.Kind, Label: OneLine(e.Text), Href: e.Href, Class: sc.classOf(e.CitationID)})
		}
	}
	if cites == nil {
		cites = []Citation{}
	}
	disc = append(disc, "Answered by the AI model from your Correlix data; check the cited items before acting.")
	return Answer{
		Mode: ModeModelAnswer, Intent: intent, Modules: []string{}, Text: text, Citations: cites,
		Disclaimers: dedupeLines(disc), Provider: provider, ModeBadges: sortedUnique(badges), Statements: statements,
		Routing: &Routing{Path: RoutePathModel, Reason: reason},
	}, true, nil
}

// maxTopologyEvidence bounds the whole-network topology items one grounded
// model answer carries, so the active problems keep at least
// maxModelEvidence - 2 - maxTopologyEvidence (13) slots.
const maxTopologyEvidence = 10

// reTopologyQuestion recognises a question about how the caller's network is
// built — the one family the scope/inventory/problems block cannot answer
// ("you are just listing the devices", owner, 2026-11-12). CLOSED and tested.
var reTopologyQuestion = regexp.MustCompile(`(?i)\btopolog(?:y|ies)\b|\bhow\s+(?:is|are)\s+(?:my|our|the|this|these)?\s*(?:network|devices|routers|switches|sites|edges)\s+(?:connected|wired|laid\s+out|built|designed|interconnected)\b|\bnetwork\s+(?:design|layout|architecture|diagram|map)\b|\b(?:overlay|underlay|full[- ]mesh|hub[- ]and[- ]spoke|partial[- ]mesh)\b|\bwhat\s+(?:connects|is\s+connected)\s+to\s+what\b|\bconnected\s+to\s+each\s+other\b`)

// modelEvidence gathers the bounded evidence block of a grounded model
// answer: the caller's scope, inventory and active problems — and, for a
// question about how the network is built, the whole-network topology read
// through the governed tool path (the same gateway gate as every tool). Every
// read is the caller's own (the tenant-scoped DataSource and the server's
// seams).
func (o *Orchestrator) modelEvidence(ctx context.Context, p Principal, question string) ([]EvidenceItem, *statementContext) {
	sc := &statementContext{perIncident: true}
	var ev []EvidenceItem
	if o.Scope != nil {
		ev = append(ev, EvidenceItem{CitationID: "scope:caller", Kind: "scope", Text: scopeAnswer(*o.Scope)})
	}
	if o.Inventory != nil {
		if inv, err := o.Inventory(ctx, p); err == nil {
			ev = append(ev, EvidenceItem{CitationID: "inventory:devices", Kind: "inventory", Text: discoveryAnswer(inv)})
		}
	}
	if o.forceTopology || reTopologyQuestion.MatchString(question) {
		ev = append(ev, o.topologyEvidence(ctx, p, sc)...)
	}
	if o.DS != nil {
		probs, err := o.DS.ListActiveProblems(ctx, p, 100)
		if err != nil {
			// A failed read is said to the model (and so to the operator),
			// never hidden: the other facts can still answer the question.
			ev = append(ev, EvidenceItem{CitationID: "problems:unread", Kind: "finding", Text: "The active problems could not be read right now."})
			return ev, sc
		}
		ranked := append([]Problem(nil), probs...)
		sort.SliceStable(ranked, func(i, j int) bool { return PriorityScore(ranked[i]) > PriorityScore(ranked[j]) })
		for _, pr := range ranked {
			if len(ev) >= maxModelEvidence {
				break
			}
			line := incidentLine(pr)
			if len(pr.Devices) > 0 {
				line += "; devices: " + strings.Join(firstN(pr.Devices, 5), ", ")
			}
			cid := "problem:" + pr.ID
			ev = append(ev, EvidenceItem{CitationID: cid, Kind: "finding", Text: line, Href: "#/monitoring/correlations?id=" + pr.ID})
			sc.stampIncident(cid, pr.ID, pr.Verdict, line)
		}
		if len(probs) == 0 {
			ev = append(ev, EvidenceItem{CitationID: "problems:none", Kind: "finding", Text: "No active problems in scope right now."})
		}
	}
	return ev, sc
}

// topologyEvidence runs get_network_topology through the Toolbox (policy +
// contract gateway, exactly as a platform-chosen tool step) and returns its
// first maxTopologyEvidence items, stamped into the statement context under
// the tool's class (with the per-item DERIVED downgrades the tool set). A
// tool that is not wired or not permitted contributes nothing; a failed read
// is said, never hidden.
func (o *Orchestrator) topologyEvidence(ctx context.Context, p Principal, sc *statementContext) []EvidenceItem {
	const tool = "get_network_topology"
	iv := o.Toolbox().Invoke(ctx, p, tool, ToolArgs{})
	switch {
	case !iv.Registered || iv.Outcome == OutcomePolicyDenied:
		return nil
	case !iv.OK():
		it := EvidenceItem{CitationID: NetworkTopologyCitationPrefix + "unread", Kind: "topology",
			Text: "The network topology could not be read right now, so how the devices connect is UNKNOWN for this answer."}
		sc.stamp(it, tool)
		return []EvidenceItem{it}
	}
	items := iv.Result.Items
	if len(items) > maxTopologyEvidence {
		items = items[:maxTopologyEvidence]
	}
	out := make([]EvidenceItem, 0, len(items))
	for _, it := range items {
		sc.stamp(it, tool)
		out = append(out, it)
	}
	return out
}

// hasTopologyEvidence: the block carries whole-network topology items.
func hasTopologyEvidence(ev []EvidenceItem) bool {
	for _, e := range ev {
		if strings.HasPrefix(e.CitationID, NetworkTopologyCitationPrefix) {
			return true
		}
	}
	return false
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

// modelAnswerPrompt is the grounded user message of a model answer. Every
// interpolated value passes promptLine (prompt_fence.go); the whole message is
// redacted before egress (LLM06).
func (o *Orchestrator) modelAnswerPrompt(question string, ev []EvidenceItem, glossary string) string {
	var b strings.Builder
	if len(o.PriorQuestions) > 0 {
		b.WriteString("EARLIER QUESTIONS IN THIS CONVERSATION (context only, oldest first):\n")
		for _, q := range lastN(o.PriorQuestions, 4) {
			fmt.Fprintf(&b, "- %s\n", promptLine(q))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Question: %s\n\nEVIDENCE (cite ids):\n", promptLine(question))
	for _, e := range ev {
		fmt.Fprintf(&b, "- [%s] %s\n", promptCitationID(e.CitationID), promptLine(e.Text))
	}
	b.WriteString("\nAnswer the operator's question using ONLY the evidence above, citing the ids you use in square brackets. " +
		"A problem's verdict (confirmed, suspected, undetermined) is Correlix's own; never upgrade it. " +
		"If the evidence does not answer the question, say plainly which Correlix data would answer it. Be concise.")
	if glossary != "" {
		// The caller's generated vocabulary, after the instructions and fenced
		// as data: it helps read the question, it is never evidence to cite.
		b.WriteString("\n\n" + glossary + "\n(The vocabulary is for understanding the question only — it is not evidence; cite only the ids above.)")
	}
	if hasTopologyEvidence(ev) {
		b.WriteString(" For the topology: explain how the network is built in network terms — the overlay and its transports, " +
			"what is adjacent to what, the roles and sites, and what each role likely runs. Items that say \"appears\", \"inferred\" or " +
			"\"likely\" are Iris's reading of the evidence: keep that wording when you use them. Describe; do not use cause wording " +
			"(caused, due to, resulting in, led to) — a topology is a map, not a diagnosis.")
	}
	return o.redact(b.String())
}

func lastN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[len(xs)-n:]
	}
	return xs
}

// ModelUnavailableNote is the one line an answer carries when the model was
// needed and did not answer (rule 3), naming why.
func ModelUnavailableNote(err error) string {
	switch ClassifyProviderError(err) {
	case ProvNoProvider:
		return "No AI model is connected, so I can only answer the questions I recognise."
	case ProvTimeout:
		return "The AI model timed out, so I could only try the questions I recognise."
	case ProvBreakerOpen:
		return "The AI model is paused after repeated failures, so I could only try the questions I recognise."
	case ProvBudget:
		return "Today's AI budget for this workspace is spent, so I could only try the questions I recognise."
	}
	return "The AI model did not answer, so I could only try the questions I recognise."
}

// modelUnavailable marks a deterministic fallback answer with why the model
// did not answer it.
func modelUnavailable(ans Answer, reason string, err error) Answer {
	ans.Routing = &Routing{Path: RoutePathModelUnavailable, Reason: reason}
	ans.ProviderNote = ModelUnavailableNote(err)
	return ans
}

// ── the problem in view ─────────────────────────────────────────────────────

// reProductUI names the product's own screens: with a problem in view, only a
// question about the UI itself ("how do I export this page", "what does this
// column mean") is product help.
var reProductUI = regexp.MustCompile(`(?i)\b(?:page|screen|tab|panel|column|button|widget|dashboard|menu|sidebar|setting|settings)s?\b|\bthis\s+view\b|\bhow\s+do\s+i\s+(?:export|download|print|share|open|close|navigate)\b`)

// reAboutTheProblem points at the problem in view itself ("why is THIS only
// suspected", "what happened HERE", "is IT still open").
var reAboutTheProblem = regexp.MustCompile(`(?i)\b(?:this|here|it|the\s+(?:problem|incident|rca|issue|correlation|outage))\b`)

// skillClaims reports a troubleshooting method that claims the whole question.
func (o *Orchestrator) skillClaims(question string, plan Plan) bool {
	if o.Skills == nil {
		return false
	}
	_, ok := SelectSkill(o.Skills, question, plan)
	return ok
}

// ProblemInView returns the id of the problem in view ("" for none), unless the
// question is explicitly about the product's screens.
func ProblemInView(question string, uiContext map[string]string) string {
	id := strings.TrimSpace(firstNonEmpty(uiContext["problem_id"], uiContext["correlation_id"]))
	if id == "" || reProductUI.MatchString(question) {
		return ""
	}
	return id
}

// withoutSubject is uiContext without the problem in view (a product question
// asked in the RCA workspace is classified as one).
func withoutSubject(uiContext map[string]string) map[string]string {
	out := make(map[string]string, len(uiContext))
	for k, v := range uiContext {
		if k != "problem_id" && k != "correlation_id" {
			out[k] = v
		}
	}
	return out
}

// answerSubject answers a question about the problem in view: the grounded
// explanation of that problem over its own tenant-scoped evidence, with the
// question passed to the narration (one strong-tier model call; no data arm,
// no tie-break, no rephrase, no skill chain — a contextual answer waits for
// one model budget at most). A problem the caller cannot see — another
// tenant's id included — is the honest not-found answer, with no evidence.
func (o *Orchestrator) answerSubject(ctx context.Context, p Principal, question string, plan Plan) (Answer, error) {
	o.routed(ArmClassic, ModeProblemExplanation)
	plan.Intent, plan.Mode = "problem_explanation", ModeProblemExplanation
	plan.Modules = []string{"correlations_rca"}
	plan.Tools = []string{"get_problem", "get_problem_evidence", "get_ticket_status"}
	pe := o.policy()
	var disc []string
	if d := pe.EvaluateModule("correlations_rca", p); !d.Allow {
		return Answer{
			Mode: ModeUnavailable, Intent: plan.Intent, Modules: plan.Modules,
			Text:      AccessDeniedText,
			Citations: []Citation{}, Disclaimers: []string{capitalize(d.Reason) + "."},
			Routing: &Routing{Path: RoutePathDeterministic, Reason: RouteReasonProblemContext},
		}, nil
	}
	ans, err := o.answerProblem(ctx, p, question, plan, disc)
	if err != nil {
		return ans, err
	}
	switch {
	case ans.Problem == nil:
		ans.Routing = &Routing{Path: RoutePathDeterministic, Reason: RouteReasonProblemContext} // not found: nothing to narrate
	case ans.EvidenceOnly:
		ans.Routing = &Routing{Path: RoutePathModelUnavailable, Reason: RouteReasonProblemContext}
	default:
		ans.Routing = &Routing{Path: RoutePathModel, Reason: RouteReasonProblemContext}
	}
	return ans, nil
}

// compoundByModel hands a multi-part question with an uncovered part to the
// model. When no model answers, the parts answered here are kept, the rest
// are named, and the answer says why the model did not take them.
func (o *Orchestrator) compoundByModel(ctx context.Context, p Principal, question string, plan Plan, answers []partAnswer) Answer {
	ans, ok, err := o.answerByModel(ctx, p, question, IntentMultiQuestion, RouteReasonCompound)
	if ok {
		return ans
	}
	var missed []string
	for _, pa := range answers {
		if !pa.ok {
			missed = append(missed, "“"+pa.q+"”")
		}
	}
	out := composeParts(answers)
	if strings.TrimSpace(out.Text) == "" {
		out = o.answerCapability(plan)
	} else {
		out.Text += "\n\nI could not answer " + strings.Join(missed, " or ") + " from the questions I recognise."
	}
	return modelUnavailable(out, RouteReasonCompound, err)
}

// splitQuestion is the multi-part reading the router uses (lex.SplitClauses).
func splitQuestion(q string) []string { return lex.SplitClauses(q) }
