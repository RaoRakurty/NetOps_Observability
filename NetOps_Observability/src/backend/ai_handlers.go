// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/aiscore"
	"netops/backend/internal/entityalias"
	"netops/backend/internal/irisconvo"
	"netops/backend/internal/irishypo"
	"netops/backend/internal/irisquerylog"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/chips"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/explain"
	"netops/backend/internal/nlquery/modelc"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/resolve"
	"netops/backend/internal/nlquery/validate"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/tac"
	"netops/backend/models"
)

// ai_handlers.go — the Iris AI HTTP surface. POST /api/ai/ask runs the
// orchestrator (classify → route → Policy Engine → tenant-scoped evidence →
// grounded answer). Read-only (v1); FEATURE_AI gates it (off by default).

// aiEnabled gates the Iris AI endpoints. ON BY DEFAULT (owner directive,
// 2026-07-04): key-free grounded mode is in-process, deterministic, and makes
// NO external calls — external LLM answers still require a provider key, so no
// data leaves the host without explicit config (LLM06). Disable explicitly
// with FEATURE_AI=false or FEATURE_COPILOT=false. FEATURE_AI wins when both are
// set; the legacy FEATURE_COPILOT is honored for existing deployments.
func aiEnabled() bool {
	if v := os.Getenv("FEATURE_AI"); v != "" {
		return v == "true"
	}
	if v := os.Getenv("FEATURE_COPILOT"); v != "" {
		return v == "true"
	}
	return true
}

// envFlagLookup answers module-availability flags (ENABLE_*) from the env.
func envFlagLookup(flag string) bool { return os.Getenv(flag) == "true" }

// aiKB is the Network Expert Knowledge Base, parsed once from the embedded
// playbooks at startup (curated, offline, no tenant data). Shared read-only
// across requests.
var aiKB = ai.LoadKB()

// aiDocsIndex is the documentation retriever (intelligence plan P1): the whole
// docs portal + the curated product knowledge + the copilot runbook brief in ONE
// BM25 index, built once from embedded markdown. Both assistant brains ground
// product/how-to answers in it and cite real /docs pages.
var aiDocsIndex = ai.LoadDocsIndex(
	ai.ExtraDoc{Name: "kb/runbook", Markdown: appKnowledge, Tier: ai.DocTierRunbook},
)

// aiSkills is the IRIS troubleshooting-method catalog (ai/skills/*/SKILL.md),
// parsed and whole-set validated once at startup. Like aiKB and aiDocsIndex it
// is embedded, immutable, tenant-free content shared read-only across requests.
//
// Unlike them, LoadSkills can FAIL — its validation is the CI gate that keeps a
// method from naming a tool, an argument or a handoff the platform does not
// have. A failure is content drift, identical on every deployment, and it is
// logged LOUDLY rather than swallowed: the orchestrator then runs with
// Skills=nil, which disables the skills layer and keeps every pre-existing
// answer path intact. Silently degrading with no log line is the one outcome
// that would be unacceptable — an operator would see the assistant get worse
// with no way to find out why.
var aiSkills = loadAISkills()

// aiExplanations is the authored UI-EXPLANATION corpus (ai/skills/explain/*.md,
// the 2026-09-06 "fewer words, Iris explains" programme). Same stance as
// aiSkills: embedded, immutable, tenant-free content, loaded once and shared
// read-only — and a load failure is content drift, logged loudly, leaving the
// layer nil rather than degrading an answer silently.
var aiExplanations = loadAIExplanations()

func loadAIExplanations() *ai.ExplainSet {
	set, err := ai.LoadExplanations()
	if err != nil {
		log.Printf("FATAL-GRADE CONFIG ERROR: iris UI explanations failed to load — the (i) affordance will report no authored explanation: %v", err)
		return nil
	}
	return set
}

func loadAISkills() *ai.SkillSet {
	set, err := ai.LoadSkills()
	if err != nil {
		log.Printf("FATAL-GRADE CONFIG ERROR: iris skills failed to load — the troubleshooting-method layer is DISABLED for this process: %v", err)
		return nil
	}
	return set
}

type aiAskRequest struct {
	Question string            `json:"question"`
	Context  map[string]string `json:"context,omitempty"` // e.g. {"correlation_id": "<uuid>"}
	// ConversationID (optional, N-C7/N-E4): the caller's own Iris conversation;
	// follow-ups ("that device") resolve against its server-held state.
	ConversationID string `json:"conversation_id,omitempty"`
}

func (s *server) handleAIAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !aiEnabled() {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Iris AI is disabled — set FEATURE_AI=true"))
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	// Per-principal rate limit — each ask may be a paid provider call (SR-021).
	if !s.copilotLimiter.AllowN(claims.Tenant+"|"+claims.Sub, envInt("COPILOT_RATE_PER_MIN", 20)) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("Iris AI rate limit exceeded — slow down"))
		return
	}
	// N-A7: ai.chat (tier mapping ∩ flags ∩ the tenant's own switch; cross-
	// tenant principals are not tenant-gated). The data arm additionally
	// needs ai.nlquery — see aiNLQueryWith.
	if !s.requireAIEntitlement(w, claims, aientitlement.Chat) {
		return
	}
	// Bound the request before decoding (LLM10: no unbounded input).
	r.Body = http.MaxBytesReader(w, r.Body, copilotBodyCap)
	var req aiAskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Question) == "" && req.Context["correlation_id"] == "" && req.Context["problem_id"] == "" {
		writeError(w, http.StatusBadRequest, errors.New("question (or a context id) required"))
		return
	}
	// Bound the CONTENT as well as the body (LLM04). The body cap above stops a
	// huge upload; it does not stop a single ~256 KiB question riding into the
	// prompt and the provider's token bill. The copilot path has had this cap
	// since SanitizeMessages — this is the same budget, applied to the one
	// free-text field this handler forwards.
	if len(req.Question) > ai.MaxInputChars {
		writeError(w, http.StatusBadRequest, fmt.Errorf("question too large (max %d characters)", ai.MaxInputChars))
		return
	}

	// Slash commands (HLD §5) resolve to the SAME intent path as natural language:
	// "/status" becomes the canonical "what is going on right now" before Classify,
	// so there is one intent system, not two. "/help" lists the commands.
	question := req.Question
	if ai.IsCommand(question) {
		canonical, cmd, ok := ai.ResolveCommand(question)
		if !ok || cmd.Intent == "help" {
			writeJSON(w, http.StatusOK, aiHelpAnswer())
			return
		}
		question = canonical
	}

	// A conversation, when named, must be the caller's own and live: another
	// principal's id, a stale one and a malformed one are the same 404, and
	// the client starts a new conversation.
	//
	// N-A7: Iris conversations are part of ai.nlquery. A caller holding
	// ai.chat without it gets a plain ask — the named conversation is neither
	// read nor appended to, and the answer carries no conversation_id, so the
	// client drops it.
	var conv *irisconvo.Conversation
	if id := strings.TrimSpace(req.ConversationID); id != "" && s.aiEntitled(claims, aientitlement.NLQuery) {
		c, status, err := s.askConversation(r, claims, id)
		if err != nil {
			writeError(w, status, err)
			return
		}
		conv = &c
	}
	// The decision ledger (N-A6): from here on this question is one decision,
	// and every seam below adds its steps through the request context.
	r, rec := s.aiDecisionStart(r, claims, req)
	orch := s.newOrchestrator(r, claims)
	var ran nlqRan
	if conv != nil && orch.NLQuery != nil {
		orch.NLQuery = s.aiNLQueryWith(r, claims, &conv.State, conv.ID, &ran)
	}
	ans, err := orch.Ask(r.Context(), s.aiPrincipal(claims), question, req.Context)
	if err != nil {
		s.aiDecisionFinish(r, claims, rec, nil, err)
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if conv != nil {
		s.recordAskTurn(r, claims, conv, question, &ans, &ran)
	}
	// N-B3: hold the investigation's hypotheses under the decision's id, in the
	// asker's tenant — before the ledger closes, so it records them.
	s.aiHypothesesHold(r, claims, rec, &ans)
	decisionID := s.aiDecisionFinish(r, claims, rec, &ans, nil)
	// AI audit (best-effort): who asked, intent, modules, provider — never the
	// question text or any retrieved data (no PII/secret in the audit line).
	logInfo("ai", "ask", map[string]any{
		"tenant": claims.Tenant, "sub": claims.Sub,
		"intent": ans.Intent, "mode": ans.Mode, "modules": ans.Modules,
		"provider": ans.Provider, "tier": ai.RouteFor(ans.Mode).Tier, // §10 model-router tier
		"decision_id": decisionID,
	})
	writeJSON(w, http.StatusOK, ans)
}

// newOrchestrator builds the grounded engine for one request — shared by
// /api/ai/ask and the copilot provider-down fallback (the engine answers when
// no LLM can). All reads ride the caller's tenant-scoped aiDataSource.
func (s *server) newOrchestrator(r *http.Request, claims jwtClaims) *ai.Orchestrator {
	ds := aiDataSource{srv: s, ctx: r.Context(), scope: s.chTenantScope(r), claims: claims}
	// IRIS Phase A: the read-only troubleshooting tools, wired to the seams this
	// deployment actually has. A nil seam means the tool is NOT registered, so
	// the assistant can never answer from a capability that is absent.
	deps := s.aiTroubleshootDeps(r, claims)
	// Tracker 337 N-A5 — one brain, one registry: this is the ONLY place an
	// Iris tool registry is built. The copilot agent loop takes its tools and
	// its policy engine from this orchestrator (orch.Toolbox()), so a tool
	// exists on both paths or on neither.
	tools := ai.BuildToolRegistry(ds, deps, aiDocsIndex)
	// Every audited tool step also lands in the decision ledger when this
	// request is a ledgered decision (nil Recorder otherwise: a no-op).
	toolAudit, ledger := s.aiToolAudit(claims), aidecision.FromContext(r.Context())
	return &ai.Orchestrator{
		DS:       ds,
		Tools:    tools,
		LLM:      aiLLM{srv: s, claims: claims},
		Flags:    envFlagLookup,
		Policy:   ai.NewPolicyEngine(ai.PolicyConfig{}, envFlagLookup), // safe default: read-only
		Redactor: ai.Redact,                                            // outbound DLP: secrets + direct identifiers (LLM06)
		KB:       aiKB,                                                 // Network Expert KB (supporting knowledge)
		Docs:     aiDocsIndex,                                          // docs-portal retriever (real page citations)
		TAC:      s.aiTACKnowledge(),                                   // vendor TAC knowledge Iris reads before answering
		Skills:   aiSkills,                                             // troubleshooting methods (nil = layer disabled)
		Explain:  aiExplanations,                                       // authored UI explanations (the AskIris (i))

		Troubleshoot: deps, // tenant-scoped Phase-A reads
		// One audit line per tool step (arg NAMES only) + its ledger entries
		// (argument/result HASHES only).
		ToolAudit: func(e ai.ToolAuditEntry) { toolAudit(e); aiLedgerToolEntry(ledger, e) },
		// IRIS Phase B: where a CONCLUDED investigation goes. It is held (in
		// memory, per principal) until an operator judges it on /api/ai/feedback;
		// only then is a tenant-scoped memory row written.
		RecordInvestigation: s.aiRecordInvestigation(claims),
		// Production scorecard (tracker 337 N-A3): counts, enums and durations
		// only — nothing tenant- or entity-identifying crosses this seam.
		Score: s.aiScoreSink(),
		// The question router's DATA arm (tracker 337 N-G4): nil when the
		// catalog is absent or the caller may not read infrastructure data.
		NLQuery: s.aiNLQuery(r, claims),
	}
}

// aiNLQuery binds the router's data arm to the caller: the same compiler,
// validator, scope and executor as /api/ai/query, and the same
// infrastructure:read gate (which /api/ai/ask itself does not require).
func (s *server) aiNLQuery(r *http.Request, claims jwtClaims) ai.NLQueryFunc {
	return s.aiNLQueryWith(r, claims, nil, "", nil)
}

// nlqRan records the query the data arm ran in this request, so a
// conversation turn can carry its state forward.
type nlqRan struct {
	q  *nlqast.AST
	rs *plan.ResultSet
	// logID is the query-log record of that answer ("" when capture failed):
	// a later chip edit of it is filed there as a correction.
	logID string
}

// aiNLQueryWith is aiNLQuery inside a conversation: st (may be nil) is the
// server-held state follow-ups resolve against, convID ("" outside one) is
// recorded on the query log, and ran (may be nil) receives the query that
// answered.
func (s *server) aiNLQueryWith(r *http.Request, claims jwtClaims, st *irisconvo.State, convID string, ran *nlqRan) ai.NLQueryFunc {
	if s.nlqCatalog == nil || s.roles == nil || !s.roles.Allows(claims.Role, "infrastructure", LevelRead) {
		return nil
	}
	// N-A7: reaching the NL query engine needs ai.nlquery — an ask may hold
	// ai.chat without it and then keeps the classic path.
	if !s.aiEntitled(claims, aientitlement.NLQuery) {
		return nil
	}
	return func(ctx context.Context, _ ai.Principal, question string, opts ai.DataOpts) (ai.DataAnswer, error) {
		start := time.Now()
		rq := r.WithContext(ctx)
		cx := compile.Context{Loc: time.UTC, Now: time.Now()}
		if st != nil {
			cx.PriorAST = st.LastAST
			cx.Conv = &compile.Conversation{Entities: st.Entities, Actors: st.Actors, ChangeIDs: st.ChangeIDs}
		}
		ledger := aidecision.FromContext(ctx)
		c, err := s.nlqCompile(rq, claims, question, cx, opts.AllowModel)
		if err != nil {
			rec := irisquerylog.Record{Source: irisquerylog.SourceRouter, Question: question, Outcome: irisquerylog.OutcomeError, ConversationID: convID}
			s.nlqCapture(rq, claims, &rec, start)
			ledger.Add(aidecision.Entry{EventType: aidecision.PlanCreated, Tool: nlqLedgerTool,
				ArgsSHA256: aidecision.SHA256Hex([]byte(question)), Outcome: irisquerylog.OutcomeError})
			return ai.DataAnswer{}, err
		}
		rec := c.record(irisquerylog.SourceRouter, question)
		rec.ConversationID = convID
		ledger.Add(nlqPlanEntry(ledger, question, c, rec))
		d, err := s.nlqDataAnswer(rq, claims, c, ran, &rec)
		if err != nil {
			rec.Outcome = irisquerylog.OutcomeError
		}
		id := s.nlqCapture(rq, claims, &rec, start)
		if id != "" && err == nil {
			d.Payload = withQueryLogID(d.Payload, id)
		}
		if ran != nil && err == nil {
			ran.logID = id
		}
		return d, err
	}
}

// askConversation loads the caller's own live conversation for /api/ai/ask.
func (s *server) askConversation(r *http.Request, claims jwtClaims, id string) (irisconvo.Conversation, int, error) {
	if s.nlqConvos == nil || !irisconvo.ValidID(id) {
		return irisconvo.Conversation{}, http.StatusNotFound, errors.New("not found")
	}
	tenant, _ := principalTenant(claims)
	c, err := s.nlqConvos.Get(r.Context(), tenant, claims.Sub, id)
	if errors.Is(err, irisconvo.ErrNotFound) {
		return irisconvo.Conversation{}, http.StatusNotFound, errors.New("not found")
	}
	if err != nil {
		logError("iris.convo", "read failed", errf(err))
		return irisconvo.Conversation{}, http.StatusInternalServerError, errors.New("the conversation could not be read")
	}
	return c, 0, nil
}

// recordAskTurn appends one /api/ai/ask turn. Only an answer that RAN a query
// moves the state forward; every other answer is recorded as a turn and
// leaves the references where they were. A failure to record never costs the
// operator the answer — it is disclosed instead.
func (s *server) recordAskTurn(r *http.Request, claims jwtClaims, conv *irisconvo.Conversation, question string, ans *ai.Answer, ran *nlqRan) {
	turn := irisconvo.Turn{Question: question, Intent: ans.Intent, Outcome: irisconvo.OutcomeAnswered}
	if ans.Mode == ai.ModeUnavailable {
		turn.Outcome = irisconvo.OutcomeUnparsed
	}
	next := conv.State
	if ran.rs != nil {
		next = irisconvo.Next(s.nlqCatalog, conv.State, ran.q, ran.rs)
		next.LastLogID = ran.logID
		turn.ASTHash, turn.QueryID, turn.Rows = ran.rs.ASTHash, ran.rs.QueryID, len(ran.rs.Rows)+len(ran.rs.Series)
	}
	tenant, _ := principalTenant(claims)
	_, err := s.nlqConvos.Append(r.Context(), tenant, claims.Sub, conv.ID, turn, next)
	switch {
	case err == nil:
		ans.ConversationID = conv.ID
	case errors.Is(err, irisconvo.ErrFull):
		ans.Disclaimers = append(ans.Disclaimers, "This conversation is full — your next question starts a new one.")
	default:
		logError("iris.convo", "append failed", errf(err))
		ans.Disclaimers = append(ans.Disclaimers, "This answer could not be added to the conversation, so a follow-up may not know about it.")
	}
}

// nlqAnswerable are the validation refusals that ARE the answer to a question
// Iris understood ("that window is too long", "that is too broad"). Any other
// refusal hands the question back to the classic path.
var nlqAnswerable = map[string]bool{
	validate.CodeWindowTooLarge: true, validate.CodeTooBroad: true, validate.CodeInvalidTime: true,
	validate.CodeScopeUnavailable: true, validate.CodeUnmappedProvider: true,
}

// nlqDataAnswer turns one compiled question into the data arm's answer; rec
// (never nil) receives what the run produced — counts only.
func (s *server) nlqDataAnswer(r *http.Request, claims jwtClaims, c nlqCompiled, ran *nlqRan, rec *irisquerylog.Record) (ai.DataAnswer, error) {
	notData := ai.DataAnswer{Status: ai.DataNotData}
	switch {
	case c.res.Decline != "" || c.res.Unparsed:
		return notData, nil
	case len(c.res.Clarify) > 0:
		var names []string
		for _, ref := range c.res.Clarify {
			names = append(names, ref.EntityID)
		}
		payload, err := json.Marshal(c.body())
		if err != nil {
			return ai.DataAnswer{}, err
		}
		return ai.DataAnswer{Status: ai.DataClarify, Intent: c.res.Intent, Payload: payload,
			Text: "More than one thing matches that name — which did you mean: " + strings.Join(names, ", ") + "?"}, nil
	case c.res.AST == nil:
		return notData, nil
	case c.checked == nil:
		var msgs []string
		for _, e := range c.vr.Errors {
			if !nlqAnswerable[e.Code] {
				return notData, nil
			}
			msgs = append(msgs, firstNonBlank(e.Message, e.Code))
		}
		payload, err := json.Marshal(c.body())
		if err != nil {
			return ai.DataAnswer{}, err
		}
		return ai.DataAnswer{Status: ai.DataAnswered, Intent: c.res.Intent, Payload: payload,
			Text: "I understood the question but can't run it as asked: " + strings.Join(msgs, "; ") + "."}, nil
	}
	rs, err := s.nlqRun(r, claims, c.checked, *c.vr)
	nlqLedgerRun(aidecision.FromContext(r.Context()), c, rs, err)
	if errors.Is(err, plan.ErrNotFound) {
		rec.Outcome = irisquerylog.OutcomeError
		return ai.DataAnswer{Status: ai.DataAnswered, Intent: c.res.Intent, Text: "Nothing by that name is visible to you."}, nil
	}
	if err != nil {
		return ai.DataAnswer{}, err
	}
	rec.Answered(rs)
	if ran != nil {
		ran.q, ran.rs = c.checked, rs
	}
	body := c.body()
	body["result"] = rs
	payload, err := json.Marshal(body)
	if err != nil {
		return ai.DataAnswer{}, err
	}
	var notes []string
	if c.source == modelc.SourceModel {
		// The grammar did not understand this question; a model interpreted it.
		// The query shown with the answer is what ran — say so, first.
		notes = append(notes, nlqModelDisclosure)
	}
	for _, k := range c.vr.Constraints {
		notes = append(notes, "Adjusted: "+k.Reason)
	}
	tenant, _ := principalTenant(claims)
	logInfo("iris.router", "data answer", map[string]any{"tenant": tenant, "sub": claims.Sub, "intent": c.res.Intent,
		"query_type": string(c.checked.Type), "rows": len(rs.Rows), "series": len(rs.Series), "source": c.source})
	return ai.DataAnswer{Status: ai.DataAnswered, Intent: c.res.Intent, Payload: payload, Notes: notes,
		Text:      plan.Summarize(s.nlqCatalog, c.checked, rs),
		Citations: []ai.Citation{{ID: "query:" + rs.QueryID, Kind: "query", Label: "Query " + rs.ASTHash, Href: ""}}}, nil
}

// ---- production AI scorecard (tracker 337 N-A3, design item 19) -------------

// aiScoreSink adapts internal/aiscore to the ai package's ScoreSink seam. The two
// packages never import each other; the integrator owns the mapping. A server
// without a scorecard (tests, tools) returns nil, which disables the layer.
func (s *server) aiScoreSink() ai.ScoreSink {
	if s == nil || s.aiScore == nil {
		return nil
	}
	return aiScoreAdapter{m: s.aiScore}
}

type aiScoreAdapter struct{ m *aiscore.Metrics }

func (a aiScoreAdapter) AnswerObserved(sc ai.AnswerScore) {
	a.m.ObserveAnswer(sc.Citations > 0, sc.Citations, sc.Duration.Seconds())
}

func (a aiScoreAdapter) InvestigationObserved(sc ai.InvestigationScore) {
	a.m.ObserveInvestigation(aiscore.Investigation{
		Outcome: sc.Outcome, Seconds: sc.Duration.Seconds(), Hops: sc.Hops,
		HopsRejected: sc.HopsRejected, ToolCalls: sc.ToolOutcomes, Cutoffs: sc.Cutoffs,
		EvidenceBacked: sc.EvidenceBacked,
	})
}

func (a aiScoreAdapter) GuardObserved(guard string, removed int) { a.m.ObserveGuard(guard, removed) }

func (a aiScoreAdapter) ProviderObserved(sc ai.ProviderScore) {
	a.m.ObserveProviderCall(aiscore.ProviderCall{
		InputTokens: sc.Usage.InputTokens, OutputTokens: sc.Usage.OutputTokens,
		Reported: sc.Usage.Reported, Investigation: sc.Investigation,
	})
}

// aiScorePrice reads the operator-configured model price, in US dollars per
// MILLION tokens (the unit providers publish). Unset, unparsable or negative
// means "not configured": the cost metric is then CENSORED with a reason rather
// than computed from a price nobody set.
func aiScorePrice() aiscore.Price {
	parse := func(key string) float64 {
		v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(key)), 64)
		if err != nil || v < 0 {
			return 0
		}
		return v
	}
	return aiscore.Price{
		InputUSDPerMTok:  parse("AI_PRICE_INPUT_USD_PER_MTOK"),
		OutputUSDPerMTok: parse("AI_PRICE_OUTPUT_USD_PER_MTOK"),
	}
}

// aiScoreLog is the sampler's structured logger (key/value pairs → fields).
func aiScoreLog(msg string, kv ...any) {
	fields := make(map[string]any, len(kv)/2+1)
	for i := 0; i < len(kv); i += 2 {
		key := fmt.Sprint(kv[i])
		if i+1 < len(kv) {
			fields[key] = kv[i+1]
		} else {
			fields[key] = ""
		}
	}
	logInfo("ai.scorecard", msg, fields)
}

// newIrisInvestigationStore picks the investigation-memory backend (IRIS Phase
// B): RLS-scoped Postgres (migration 0040) under STORE_BACKEND=postgres, else
// the tenant-keyed file store — the same two-backend shape every other
// tenant-scoped register in this codebase uses. It is called from newServer's
// IRIS-MEMORY block; it lives here so the whole memory surface stays in the AI
// lane.
func newIrisInvestigationStore() ai.InvestigationStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return ai.NewPGInvestigationStore(ps.DB())
	}
	return ai.NewInvestigationFileStore(envOr("IRIS_MEMORY_FILE", "/data/iris_investigations.json"))
}

// aiPrincipal maps the coarse RBAC grid (overview/explore/alerts/infrastructure/
// topology/reports/administration) to the ai package's logical permission names,
// so the ai package stays decoupled from the server's RBAC vocabulary. Cross-
// tenant principals hold everything (ai.Principal.Cross).
func (s *server) aiPrincipal(claims jwtClaims) ai.Principal {
	tenant, cross := principalTenant(claims)
	can := func(module string) bool { return s.roles.Allows(claims.Role, module, LevelRead) }
	perms := map[string]bool{
		"infrastructure:read": can("infrastructure"),
		"correlations:read":   can("infrastructure"), // correlation reads are gated by infrastructure
		"applications:read":   can("infrastructure"),
		"topology:read":       can("topology"),
		"events:read":         can("alerts"),
		"incident:read":       can("alerts"),
		"flows:read":          can("explore"),
		"logs:read":           can("explore"),
		"reports:read":        can("reports"),
		"administration:read": can("administration"),
		"overview:read":       can("overview"),
	}
	return ai.Principal{Tenant: tenant, Cross: cross, Perms: perms}
}

// handleAIModules: GET /api/ai/modules — the Application Knowledge Layer's view
// for this caller (which modules are enabled + their question categories), so the
// UI can show what Iris AI can answer. Read-only, any authenticated user.
func (s *server) handleAIModules(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	if !s.requireAIEntitlement(w, claims, aientitlement.Chat) {
		return
	}
	type modView struct {
		ID                 string   `json:"id"`
		DisplayName        string   `json:"display_name"`
		Description        string   `json:"description"`
		Enabled            bool     `json:"enabled"`
		QuestionCategories []string `json:"question_categories"`
	}
	var out []modView
	for _, m := range ai.Modules() {
		out = append(out, modView{
			ID: m.ID, DisplayName: m.DisplayName, Description: m.Description,
			Enabled: ai.IsModuleEnabled(m.ID, envFlagLookup), QuestionCategories: m.QuestionCategories,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": aiEnabled(), "modules": out})
}

// handleAICommands: GET /api/ai/commands — the slash-command registry for the
// "/" menu (read-only, any authenticated user). /commands/suggestions filters by
// a typed fragment for live suggestions.
func (s *server) handleAICommands(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	if !s.requireAIEntitlement(w, claims, aientitlement.Chat) {
		return
	}
	if strings.HasSuffix(r.URL.Path, "/suggestions") {
		writeJSON(w, http.StatusOK, map[string]any{"commands": ai.SuggestCommands(r.URL.Query().Get("q"))})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": ai.Commands()})
}

// handleAIFeedback: POST /api/ai/feedback — record a thumbs up/down on an answer.
// v1 audits it (no PII / no answer text); a persisted feedback loop is a later
// phase. Rating is "up" | "down".
func (s *server) handleAIFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet { // GET = the tenant-scoped feedback aggregate
		s.handleAIFeedbackStats(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	if !s.requireAIEntitlement(w, claims, aientitlement.Chat) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var req struct {
		ConversationID string `json:"conversation_id"`
		Intent         string `json:"intent"`
		Rating         string `json:"rating"` // up | down
		// AnswerID names the answer being judged (Answer.answer_id, IRIS Phase
		// B). Optional: when absent the rating is taken to judge THIS
		// principal's most recent concluded investigation, which is what the
		// shipped UI (one thumbs control on the latest answer) means by it.
		AnswerID string `json:"answer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rating := strings.ToLower(strings.TrimSpace(req.Rating))
	if rating != "up" && rating != "down" {
		writeError(w, http.StatusBadRequest, errors.New("rating must be 'up' or 'down'"))
		return
	}
	// Persist the rating (privacy-safe: no question/answer text) so answer quality
	// can be measured over time — the feedback loop. Owner stamped from the token.
	tenant, _ := principalTenant(claims)
	if s.aiFeedback != nil {
		row := ai.FeedbackRow{
			TenantID: tenant, ID: randID(), ConversationID: req.ConversationID,
			Sub: claims.Sub, Intent: req.Intent, Rating: rating, At: time.Now().UTC(),
		}
		if err := s.aiFeedback.Put(r.Context(), row); err != nil {
			log.Printf("ai feedback persist: %v", err) // best-effort; still audit below
		}
	}
	// IRIS Phase B: a rating is also the JUDGEMENT that turns the answer's
	// concluded investigation into tenant-scoped memory. Only a rated
	// conclusion is remembered — memory whose outcome is unknown would be a
	// claim we cannot stand behind.
	remembered := s.rememberJudgedInvestigation(r, claims, tenant, rating, req.AnswerID)
	logInfo("ai", "feedback", map[string]any{
		"tenant": claims.Tenant, "sub": claims.Sub,
		"conversation_id": req.ConversationID, "intent": req.Intent, "rating": rating,
		"investigation_remembered": remembered,
	})
	w.WriteHeader(http.StatusNoContent)
}

// rememberJudgedInvestigation writes ONE investigation-memory row for the
// answer this rating judged (IRIS Phase B, design §3.5). It reports whether a
// row was written, for the audit line.
//
// It is deliberately BEST-EFFORT: the operator's rating is already recorded and
// audited, and failing their request because a memory write failed would be the
// wrong trade. A failure is LOGGED, never swallowed (§10).
//
// The owner is the tenant derived from the TOKEN (§3a rule 2) — the pending
// buffer is keyed by (tenant, subject), so a rating can only ever judge an
// investigation this principal itself concluded.
//
// The other write trigger the design names — a correlation case CLOSING with a
// verdict — is NOT wired, because there is no in-process hook for it: case
// closure is authored by the Python correlation engine and lands in ClickHouse;
// the Go backend only ever reads that state, and the one Go writer
// (corrCurrentReconcileLoop's bulk orphan-close) has no per-object seam. Adding
// a state-transition detector is a correlation-lane change, not an AI-lane one,
// so Phase B ships the operator-judgement trigger only.
func (s *server) rememberJudgedInvestigation(r *http.Request, claims jwtClaims, tenant, rating, answerID string) bool {
	if s.irisMemory == nil || s.irisPending == nil {
		return false
	}
	inv, ok := s.irisPending.Take(tenant, claims.Sub, answerID)
	if !ok {
		return false
	}
	outcome := ai.OutcomeConfirmed
	if rating == "down" {
		outcome = ai.OutcomeWrong
	}
	row := ai.InvestigationRowFrom(tenant, inv, outcome, time.Now().UTC())
	if err := s.irisMemory.Record(r.Context(), row); err != nil {
		log.Printf("iris investigation memory persist: %v", err)
		return false
	}
	return true
}

// handleAIFeedbackStats: GET /api/ai/feedback — the tenant-scoped feedback
// aggregate (up/down totals + per-intent breakdown) for the quality loop.
func (s *server) handleAIFeedbackStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "administration", LevelRead)
	if !ok || !s.requireAIEntitlement(w, claims, aientitlement.Chat) {
		return
	}
	if s.aiFeedback == nil {
		writeJSON(w, http.StatusOK, ai.FeedbackStats{ByIntent: map[string]*ai.UpDownCounts{}})
		return
	}
	tenant, cross := principalTenant(claims)
	since := int(durationQuery(r, "since", 30*24*time.Hour).Seconds())
	st, err := s.aiFeedback.Stats(r.Context(), tenant, cross, since)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// aiHelpAnswer is the deterministic answer for "/help" — lists the commands so
// the UI can render them without a provider call.
func aiHelpAnswer() map[string]any {
	cmds := ai.Commands()
	lines := make([]string, 0, len(cmds))
	for _, c := range cmds {
		lines = append(lines, c.Command+" — "+c.Description)
	}
	return map[string]any{
		"mode":     "help",
		"intent":   "help",
		"text":     "Ask Correlix in plain English, or use a command:",
		"commands": cmds,
		"items":    lines,
	}
}

// aiTACKnowledge adapts the TAC catalogue to Iris's knowledge seam. The
// catalogue is curated, version-pinned reference data with no tenant content,
// so it needs no scoping. nil when the TAC service is not wired, which leaves
// every Iris answer exactly as it was.
func (s *server) aiTACKnowledge() ai.TACKnowledgeSource {
	svc := s.tacSvc()
	if svc == nil || svc.Catalog() == nil {
		return nil
	}
	return aiTACCatalog{cat: svc.Catalog()}
}

type aiTACCatalog struct{ cat *tac.Catalog }

func (a aiTACCatalog) Lookup(query string, limit int) []ai.TACKnowledgeHit {
	hits := a.cat.Lookup(query, limit)
	out := make([]ai.TACKnowledgeHit, 0, len(hits))
	for _, h := range hits {
		kh := ai.TACKnowledgeHit{ClassID: h.ClassID, Title: h.Title, Protocol: h.Protocol,
			Summary: h.Summary, FirstLook: h.FirstLook, Dialect: h.Dialect}
		for _, in := range h.Intents {
			kh.Intents = append(kh.Intents, ai.TACKnowledgeIntent{Title: in.Title, Command: in.Command,
				Verified: in.Verified == tac.VerifiedCapture, Consent: in.Consent})
		}
		out = append(out, kh)
	}
	return out
}

// ---- Iris NL: entity aliases + resolution (tracker 337 N-C2) ----------------
//
// /api/ai/aliases        GET own aliases · PUT create/re-point · DELETE ?entity_type=&alias=
// /api/ai/entities/resolve  POST {text, types[], suggest?} → the resolution ladder's answer
//      suggest=true additionally asks the AI model for the name the operator
//      probably meant when every deterministic rung found nothing; its
//      candidates are disclosed as the model's and always need confirmation.
//
// §3a: per-tenant DATA → requirePerm + tenant filter. The owning tenant is
// stamped from the principal, never the body; a Global (cross-tenant) view
// has no tenant to write for and must pick a workspace first. An alias may
// only point at an entity the caller can SEE (provider / application ids are
// tenant-scoped names that the alias itself defines).

const nlqBodyCap = 8 << 10

func (s *server) handleAIAliases(w http.ResponseWriter, r *http.Request) {
	if s.nlqCatalog == nil || s.nlqAliases == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the Iris query catalog is not available on this deployment"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok || !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
			return
		}
		tenant, cross := principalTenant(claims)
		list := s.nlqAliases.List(tenant, cross)
		sort.Slice(list, func(i, j int) bool { return list[i].Key() < list[j].Key() })
		writeJSON(w, http.StatusOK, map[string]any{"aliases": list, "max": entityalias.MaxPerTenant})
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok || !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
			return
		}
		tenant, cross := principalTenant(claims)
		if cross {
			writeError(w, http.StatusBadRequest, errors.New("choose a workspace first — an alias belongs to one workspace"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, nlqBodyCap)
		var req struct {
			EntityType string `json:"entity_type"`
			EntityID   string `json:"entity_id"`
			Alias      string `json:"alias"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields() // a smuggled tenant_id is an error, not a silent no-op
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		a := entityalias.Alias{TenantID: tenant, EntityType: req.EntityType, EntityID: req.EntityID, Alias: req.Alias, CreatedBy: claims.Sub}
		if err := s.nlqAliases.Validate(&a); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if a.EntityType != "provider" && a.EntityType != "application" {
			vis, err := s.nlqScopeFor(r, claims).Visible(r.Context(), nlqast.EntityRef{Type: a.EntityType, ID: a.EntityID})
			if err != nil {
				writeError(w, http.StatusInternalServerError, errors.New("could not check the entity"))
				return
			}
			if !vis {
				writeError(w, http.StatusNotFound, errors.New("no such "+a.EntityType+" is visible to you"))
				return
			}
		}
		saved, err := s.nlqAliases.Put(a)
		switch {
		case errors.Is(err, entityalias.ErrFull):
			writeError(w, http.StatusConflict, err)
		case errors.Is(err, entityalias.ErrInvalid):
			writeError(w, http.StatusBadRequest, err)
		case err != nil:
			logError("iris.aliases", "alias write failed", errf(err))
			writeError(w, http.StatusInternalServerError, errors.New("the alias could not be saved"))
		default:
			writeJSON(w, http.StatusOK, saved)
		}
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok || !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
			return
		}
		tenant, cross := principalTenant(claims)
		q := r.URL.Query()
		if err := s.nlqAliases.Delete(tenant, cross, q.Get("entity_type"), q.Get("alias")); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

func (s *server) handleAIEntityResolve(w http.ResponseWriter, r *http.Request) {
	if s.nlqCatalog == nil || s.nlqAliases == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the Iris query catalog is not available on this deployment"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok || !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, nlqBodyCap)
	var req struct {
		Text    string   `json:"text"`
		Types   []string `json:"types"`
		Suggest bool     `json:"suggest"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len([]rune(req.Text)) > 128 || len(req.Types) > 10 {
		writeError(w, http.StatusBadRequest, errors.New("text is at most 128 characters and types at most 10"))
		return
	}
	for _, t := range req.Types {
		if _, ok := s.nlqCatalog.Entity(t); !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown entity type "+t))
			return
		}
	}
	// A request that may reach a model rides the same per-principal limit as
	// every other Iris model path (LLM04); a plain lookup does not.
	if req.Suggest && !s.copilotLimiter.AllowN(claims.Tenant+"|"+claims.Sub, envInt("COPILOT_RATE_PER_MIN", 20)) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("Iris AI rate limit exceeded — slow down"))
		return
	}
	res, err := s.nlqResolverWith(r, claims, req.Suggest).Resolve(r.Context(), req.Text, req.Types)
	if err != nil {
		logError("iris.resolve", "entity resolution failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("entity resolution is unavailable"))
		return
	}
	if res.SuggestionError != "" {
		// The deterministic answer stands; the missing suggestion is said in
		// the response and recorded here (§10: no silent failure).
		logWarn("iris.resolve", "model name suggestion unavailable", map[string]any{"reason": res.SuggestionError})
	}
	if req.Suggest {
		s.aiSuggestAudit(r, claims, res)
	}
	writeJSON(w, http.StatusOK, res)
}

// aiSuggestAudit enters one model-suggestion request into the platform audit
// trail: who asked and how it ended (suggested / none / unavailable / not
// needed) — never the typed text or the suggested names.
func (s *server) aiSuggestAudit(r *http.Request, claims jwtClaims, res resolve.Result) {
	if s.audit == nil {
		return
	}
	outcome := "not_needed" // a deterministic rung answered; no model was asked
	switch {
	case res.SuggestionError != "":
		outcome = "unavailable"
	case res.Disclosure != "":
		outcome = "suggested"
	case len(res.Refs) == 0:
		outcome = "none"
	}
	tenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross, SessionID: claims.Sid,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: map[string]any{"action": "ai.entity_suggest", "outcome": outcome, "candidates": len(res.Refs)},
	})
}

// nlqResolver builds the resolution ladder over the caller's own aliases,
// visible inventory and adjacency. The model-suggestion rung is NOT wired:
// this is the ladder the query compiler uses, and nothing a model suggests is
// ever applied to a query without the operator confirming it first.
func (s *server) nlqResolver(r *http.Request, claims jwtClaims) resolve.Resolver {
	return s.nlqResolverWith(r, claims, false)
}

// nlqResolverWith is nlqResolver, plus — when suggest is set, Iris is on and
// the caller may use a model — the model-suggestion rung, on the caller's own
// provider chain and daily budget (nlqModel: credential-shaped text redacted
// before it leaves, LLM06; budget refused before any call, LLM04).
func (s *server) nlqResolverWith(r *http.Request, claims jwtClaims, suggest bool) resolve.Resolver {
	l := newNLQLookups(s, r, claims)
	res := resolve.Resolver{Cat: s.nlqCatalog, L: l, Topo: l}
	if suggest {
		if fb := s.nlqModelFallback(r, claims); fb.Model != nil {
			res.Suggest = modelc.NameSuggester{Model: fb.Model}
		} else {
			res.Suggest = nlqNoSuggester{}
		}
	}
	return res
}

// nlqNoSuggester answers a suggestion request on a deployment (or for a
// caller) with no usable model: the response says the suggestion was
// unavailable rather than pretending the model found nothing.
type nlqNoSuggester struct{}

func (nlqNoSuggester) SuggestNames(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("no model is available to this caller")
}

// nlqLookups implements resolve.Lookups and resolve.Topology from the
// caller's own scope. One value serves one request: the query compiler asks
// the ladder once per word group, so the reads that are not already in
// memory (the application seeds, the adjacency set) are made once and kept
// for that request only (cache) — never across requests or callers.
type nlqLookups struct {
	s      *server
	h      *nlqScope
	claims jwtClaims
	cache  *nlqLookupCache
}

type nlqLookupCache struct {
	appsOnce sync.Once
	apps     []resolve.Named
	appsErr  error

	linksOnce sync.Once
	links     []topoLink
	linksErr  error
}

func newNLQLookups(s *server, r *http.Request, claims jwtClaims) nlqLookups {
	return nlqLookups{s: s, h: s.nlqScopeFor(r, claims), claims: claims, cache: &nlqLookupCache{}}
}

func (l nlqLookups) Aliases(context.Context) ([]resolve.Alias, error) {
	tenant, cross := principalTenant(l.claims)
	var out []resolve.Alias
	for _, a := range l.s.nlqAliases.List(tenant, cross) {
		out = append(out, resolve.Alias{EntityType: a.EntityType, EntityID: a.EntityID, Alias: a.Alias})
	}
	return out, nil
}

func (l nlqLookups) Inventory(ctx context.Context, types []string) ([]resolve.Named, error) {
	want := stringSet(types)
	var out []resolve.Named
	if want["site"] && l.s.sites != nil {
		tenant, cross := principalTenant(l.claims)
		for _, st := range l.s.sites.All(tenant, cross) {
			out = append(out, resolve.Named{Type: "site", ID: "site:" + st.Slug, Names: []string{st.Name, st.Slug}})
		}
	}
	if want["device"] {
		for _, d := range l.h.visibleDevices() {
			out = append(out, resolve.Named{Type: "device", ID: "device:" + d.ID, Names: []string{d.Name, d.ID}})
		}
	}
	if want["circuit"] {
		// The caller's visible circuits (the same projection nlqScope.Circuits reads).
		_, all, err := l.s.wanProject(ctx, l.s.deviceVisibilityFor(l.claims))
		if err != nil {
			return nil, err
		}
		for _, c := range all {
			out = append(out, resolve.Named{Type: "circuit", ID: "circuit:" + c.ID, Names: []string{c.ID, c.Local.Device + " " + c.Local.Interface}})
		}
	}
	if want["application"] {
		// Application seeding (N-C2): the applications the caller's OWN data
		// names. Providers are not listed here — a carrier is named through
		// the caller's aliases or the catalog's public seeds (resolve rung 5).
		apps, err := l.appSeeds(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, apps...)
	}
	return out, nil
}

func (l nlqLookups) appSeeds(ctx context.Context) ([]resolve.Named, error) {
	if l.cache == nil {
		return l.h.appSeeds(ctx)
	}
	l.cache.appsOnce.Do(func() { l.cache.apps, l.cache.appsErr = l.h.appSeeds(ctx) })
	return l.cache.apps, l.cache.appsErr
}

// Neighbors implements resolve.Topology: the devices adjacent to deviceID in
// the deduped LLDP/CDP/BGP-LS link set built over the caller's VISIBLE
// devices only (the same gather /api/topology/view uses), so a neighbour
// outside the caller's inventory can never be returned. An unreadable
// adjacency source is an error — the rung must not report "no neighbours"
// for "unknown".
func (l nlqLookups) Neighbors(ctx context.Context, deviceID string) ([]resolve.Named, error) {
	id := strings.TrimPrefix(deviceID, "device:")
	devs := l.s.visibleDevicesFor(l.claims)
	byID := make(map[string]resolve.Named, len(devs))
	for _, d := range devs {
		// The role the inventory knows: an explicit role label, else the
		// inferred device type. "generic" is the inference saying it does
		// not know — passed on as unknown, so the rung asks rather than
		// excludes (or includes) the device on a guess.
		role := strings.TrimSpace(d.Labels["role"])
		if role == "" {
			if role = inferDeviceType(d); role == "generic" {
				role = ""
			}
		}
		byID[d.ID] = resolve.Named{Type: "device", ID: "device:" + d.ID, Names: []string{d.Name, d.ID}, Role: role}
	}
	if _, ok := byID[id]; !ok {
		return nil, nil
	}
	links, err := l.topoLinks(ctx, devs)
	if err != nil {
		return nil, err
	}
	var out []resolve.Named
	for _, ln := range links {
		other := ""
		switch id {
		case ln.Source:
			other = ln.Target
		case ln.Target:
			other = ln.Source
		}
		if n, ok := byID[other]; ok && other != id {
			out = append(out, n)
		}
	}
	return out, nil
}

func (l nlqLookups) topoLinks(ctx context.Context, devs []models.Device) ([]topoLink, error) {
	read := func() ([]topoLink, error) {
		tctx, cancel := context.WithTimeout(ctx, aiTopoTimeout)
		defer cancel()
		return l.s.gatherTopoLinks(tctx, devs)
	}
	if l.cache == nil {
		return read()
	}
	l.cache.linksOnce.Do(func() { l.cache.links, l.cache.linksErr = read() })
	return l.cache.links, l.cache.linksErr
}

func (l nlqLookups) Visible(ctx context.Context, entityType, id string) (bool, error) {
	return l.h.Visible(ctx, nlqast.EntityRef{Type: entityType, ID: id})
}

// aiCompileQuery binds the compile_query tool (tracker 337 N-C5) to the caller:
// the same compiler, model fallback, validator and scope as
// /api/ai/query/compile, behind the same infrastructure:read gate. It returns
// the interpretation only — nothing is executed. nil when the catalog is
// absent or the caller may not read infrastructure (the tool then does not
// register).
func (s *server) aiCompileQuery(r *http.Request, claims jwtClaims) func(context.Context, ai.Principal, string) (ai.QueryInterpretation, error) {
	if s.nlqCatalog == nil || s.roles == nil || !s.roles.Allows(claims.Role, "infrastructure", LevelRead) {
		return nil
	}
	// N-A7: reaching the NL query engine needs ai.nlquery — an ask may hold
	// ai.chat without it and then keeps the classic path.
	if !s.aiEntitled(claims, aientitlement.NLQuery) {
		return nil
	}
	return func(ctx context.Context, _ ai.Principal, question string) (ai.QueryInterpretation, error) {
		c, err := s.nlqCompileQuestion(r.WithContext(ctx), claims, question, compile.Context{Loc: time.UTC, Now: time.Now()})
		if err != nil {
			return ai.QueryInterpretation{}, err
		}
		in := ai.QueryInterpretation{Intent: c.res.Intent, Source: c.source, NotUnderstood: c.res.NotUnderstood}
		for _, e := range c.res.Entities {
			in.Entities = append(in.Entities, e.EntityID)
		}
		switch {
		case c.res.Decline != "":
			in.Status = ai.QueryDeclined
		case len(c.res.Clarify) > 0:
			in.Status = ai.QueryClarify
			for _, e := range c.res.Clarify {
				in.Clarify = append(in.Clarify, e.EntityID)
			}
		case c.res.AST == nil:
			in.Status = ai.QueryNotUnderstood
		case c.checked == nil:
			in.Status = ai.QueryInvalid
			if in.Query, err = c.res.AST.Canonical(); err != nil {
				return ai.QueryInterpretation{}, err
			}
			for _, e := range c.vr.Errors {
				in.ValidationCodes = append(in.ValidationCodes, e.Code)
			}
		default:
			in.Status = ai.QueryCompiled
			if in.Query, err = c.checked.Canonical(); err != nil {
				return ai.QueryInterpretation{}, err
			}
			for _, k := range c.vr.Constraints {
				in.Constraints = append(in.Constraints, k.Reason)
			}
		}
		return in, nil
	}
}

// nlqModelDisclosure is the note every model-compiled answer carries.
const nlqModelDisclosure = "Interpreted by the AI model, not the built-in question grammar — check the query shown with this answer before relying on it."

// nlqModelFallbackTier is the model tier the fallback asks for: turning a
// question into a checked query is structured reasoning, not a headline.
const nlqModelFallbackTier = ai.TierStrong

// nlqModelFallback binds the model fallback (tracker 337 N-C5) to the caller:
// their own aliases and inventory, and their own provider chain and daily
// budget through aiLLM. With Iris off, IRIS_NLQ_MODEL_FALLBACK=false, or no
// provider this caller may use, Model stays nil and the fallback is silently
// unavailable — the grammar's answer stands, key-free.
func (s *server) nlqModelFallback(r *http.Request, claims jwtClaims) modelc.Fallback {
	f := modelc.Fallback{Cat: s.nlqCatalog, L: newNLQLookups(s, r, claims)}
	if !aiEnabled() || strings.EqualFold(strings.TrimSpace(os.Getenv("IRIS_NLQ_MODEL_FALLBACK")), "false") ||
		s.aiTenantCfg == nil || s.copilotCfg == nil || len(s.providerCandidatesForTier(claims, nlqModelFallbackTier)) == 0 {
		return f
	}
	f.Model = nlqModel{llm: aiLLM{srv: s, claims: claims}}
	return f
}

// nlqModel adapts aiLLM to modelc.Model: the server-owned system prompt goes
// in its own channel, every turn is stripped of credential-shaped text before
// it crosses the provider boundary (LLM06), and the call is charged to the
// caller's tenant budget — an exhausted budget refuses before any provider is
// called (LLM04).
type nlqModel struct{ llm aiLLM }

func (m nlqModel) Complete(ctx context.Context, system string, msgs []modelc.Message) (string, error) {
	lm := make([]ai.LLMMessage, 0, len(msgs))
	for _, x := range msgs {
		lm = append(lm, ai.LLMMessage{Role: x.Role, Content: ai.RedactSecrets(x.Content)})
	}
	text, _, _, err := m.llm.CompleteTierWithUsage(ctx, nlqModelFallbackTier, system, lm)
	return text, err
}

// ---- Iris NL: compile + execute (tracker 337 N-C5) ---------------------------
//
// POST /api/ai/query/compile  {question, incident_id?, prior_ast?, tz?}
//      → intent, resolved entities, the VALIDATED (constrained) query, or a
//        clarification / decline / "not understood" — never a guess.
// POST /api/ai/query/execute  {ast}
//      → the typed ResultSet, after the query is decoded strictly and
//        validated AGAIN (a client-supplied or client-edited query is
//        untrusted exactly like a model-written one).
//
// Gates, same as /api/ai/ask: Iris enabled, authenticated, per-principal rate
// limit, tenant entitlement, plus infrastructure:read (these read inventory
// and telemetry). The tenant is NEVER in the request: every read runs through
// nlqScope, bound to the caller's claims.

const (
	nlqQuestionMax = 1000
	nlqQueryBody   = 16 << 10
)

// nlqGate runs the shared gates and returns the caller's claims.
func (s *server) nlqGate(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return jwtClaims{}, false
	}
	if !aiEnabled() {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Iris AI is disabled — set FEATURE_AI=true"))
		return jwtClaims{}, false
	}
	if s.nlqCatalog == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the Iris query catalog is not available on this deployment"))
		return jwtClaims{}, false
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return jwtClaims{}, false
	}
	if !s.copilotLimiter.AllowN(claims.Tenant+"|"+claims.Sub, envInt("COPILOT_RATE_PER_MIN", 20)) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("Iris AI rate limit exceeded — slow down"))
		return jwtClaims{}, false
	}
	if !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
		return jwtClaims{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, nlqQueryBody)
	return claims, true
}

func (s *server) handleAIQueryCompile(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.nlqGate(w, r)
	if !ok {
		return
	}
	var req struct {
		Question   string          `json:"question"`
		IncidentID string          `json:"incident_id"`
		PriorAST   json.RawMessage `json:"prior_ast"`
		TZ         string          `json:"tz"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if q := strings.TrimSpace(req.Question); q == "" || len([]rune(q)) > nlqQuestionMax {
		writeError(w, http.StatusBadRequest, fmt.Errorf("question is 1 to %d characters", nlqQuestionMax))
		return
	}
	loc := time.UTC
	if req.TZ != "" {
		l, err := time.LoadLocation(req.TZ)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("tz must be an IANA time zone"))
			return
		}
		loc = l
	}
	cx := compile.Context{Loc: loc, Now: time.Now(), IncidentID: strings.TrimSpace(req.IncidentID)}
	if cx.IncidentID != "" && !isUUIDToken(cx.IncidentID) {
		writeError(w, http.StatusBadRequest, errors.New("incident_id is not an incident id"))
		return
	}
	if len(req.PriorAST) > 0 && string(req.PriorAST) != "null" {
		prior, err := nlqast.Decode(req.PriorAST)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("prior_ast: %w", err))
			return
		}
		cx.PriorAST = prior
	}
	start := time.Now()
	c, err := s.nlqCompileQuestion(r, claims, req.Question, cx)
	if err != nil {
		logError("iris.nlquery", "compile failed", errf(err))
		rec := irisquerylog.Record{Source: irisquerylog.SourceQueryCompile, Question: req.Question, Outcome: irisquerylog.OutcomeError}
		s.nlqCapture(r, claims, &rec, start)
		writeError(w, http.StatusInternalServerError, errors.New("the question could not be compiled"))
		return
	}
	tenant, _ := principalTenant(claims)
	logInfo("iris.nlquery", "compile", map[string]any{"tenant": tenant, "sub": claims.Sub, "intent": c.res.Intent,
		"unparsed": c.res.Unparsed, "declined": c.res.Decline != "", "source": c.source, "question_chars": len(req.Question)})
	out := c.body()
	rec := c.record(irisquerylog.SourceQueryCompile, req.Question)
	if id := s.nlqCapture(r, claims, &rec, start); id != "" {
		out["query_log_id"] = id
	}
	writeJSON(w, http.StatusOK, out)
}

// nlqCompiled is one question compiled and validated against the caller's scope.
type nlqCompiled struct {
	res     compile.Result
	checked *nlqast.AST      // the validated query; nil unless it is valid
	vr      *validate.Result // nil when nothing compiled
	// source is modelc.SourceModel when the model fallback compiled the
	// question (the grammar's queries carry none); the UI and the router's
	// data arm disclose it.
	source string
}

// nlqCompileQuestion runs the compiler and the validator for the caller. When
// the grammar cannot parse the question, the model fallback (tracker 337 N-C5)
// may: only then, only with a provider this caller may use, and only with a
// query that passes the same validator in the same scope.
func (s *server) nlqCompileQuestion(r *http.Request, claims jwtClaims, question string, cx compile.Context) (nlqCompiled, error) {
	return s.nlqCompile(r, claims, question, cx, true)
}

// nlqCompile is nlqCompileQuestion with the model fallback optional
// (allowModel=false: grammar only — the /ask data arm on product-help
// questions).
func (s *server) nlqCompile(r *http.Request, claims jwtClaims, question string, cx compile.Context, allowModel bool) (nlqCompiled, error) {
	res, err := compile.Compiler{Cat: s.nlqCatalog, R: s.nlqResolver(r, claims)}.Compile(r.Context(), question, cx)
	if err != nil {
		return nlqCompiled{}, err
	}
	if res.Unparsed && allowModel {
		scope := s.nlqScopeFor(r, claims)
		o, err := s.nlqModelFallback(r, claims).Compile(r.Context(), question, cx, scope, res)
		if err != nil {
			return nlqCompiled{}, err
		}
		tenant, _ := principalTenant(claims)
		if o.Calls > 0 {
			// Counts and closed reasons only — never the question or the reply.
			logInfo("iris.nlquery", "model fallback", map[string]any{"tenant": tenant, "sub": claims.Sub,
				"accepted": o.Accepted(), "refusal": o.Refusal, "calls": o.Calls})
		}
		if o.Accepted() {
			vr := o.Validation
			return nlqCompiled{res: o.Result, checked: o.Checked, vr: &vr, source: o.Source}, nil
		}
	}
	out := nlqCompiled{res: res}
	if res.AST != nil {
		checked, vr := validate.Validate(r.Context(), s.nlqCatalog, s.nlqScopeFor(r, claims), res.AST)
		out.vr = &vr
		if vr.Valid {
			out.checked = checked
		}
	}
	return out, nil
}

// record starts the query-log record for this compiled question: the
// validated query is kept, attributed to the model when the fallback wrote it
// (so the disclosure outlives the answer — GET /api/ai/query/{id}/explain).
func (c nlqCompiled) record(source, question string) irisquerylog.Record {
	rec := irisquerylog.FromCompile(source, question, c.res, c.checked, c.vr)
	if c.source == modelc.SourceModel {
		rec.ByModel()
	}
	return rec
}

// body is the compile answer: what was understood, and the query — the
// validated one, or the invalid one shown (never executed) so the operator
// sees what was understood.
func (c nlqCompiled) body() map[string]any {
	out := map[string]any{"intent": c.res.Intent, "entities": c.res.Entities, "clarify": c.res.Clarify,
		"decline": c.res.Decline, "unparsed": c.res.Unparsed, "not_understood": c.res.NotUnderstood}
	if c.source != "" {
		out["source"] = c.source // "model": interpreted by the model, not the grammar
	}
	if c.res.AST != nil {
		out["validation"] = *c.vr
		if c.checked != nil {
			out["ast"] = c.checked
		} else {
			out["ast"] = c.res.AST
		}
	}
	return out
}

// nlqRun executes a VALIDATED query in the caller's scope.
func (s *server) nlqRun(r *http.Request, claims jwtClaims, checked *nlqast.AST, vr validate.Result) (*plan.ResultSet, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	return plan.Planner{Cat: s.nlqCatalog}.Execute(ctx, s.nlqScopeFor(r, claims), checked, vr.Constraints)
}

func (s *server) handleAIQueryExecute(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.nlqGate(w, r)
	if !ok {
		return
	}
	var req struct {
		AST json.RawMessage `json:"ast"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	q, err := nlqast.Decode(req.AST)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	start := time.Now()
	scope := s.nlqScopeFor(r, claims)
	checked, vr := validate.Validate(r.Context(), s.nlqCatalog, scope, q)
	rec := irisquerylog.FromQuery(q, checked, vr)
	if !vr.Valid {
		out := map[string]any{"validation": vr}
		if id := s.nlqCapture(r, claims, &rec, start); id != "" {
			out["query_log_id"] = id
		}
		writeJSON(w, http.StatusUnprocessableEntity, out)
		return
	}
	rs, err := s.nlqRun(r, claims, checked, vr)
	switch {
	case errors.Is(err, plan.ErrNotFound):
		rec.Outcome = irisquerylog.OutcomeError
		s.nlqCapture(r, claims, &rec, start)
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	case err != nil:
		logError("iris.nlquery", "execute failed", errf(err))
		rec.Outcome = irisquerylog.OutcomeError
		s.nlqCapture(r, claims, &rec, start)
		writeError(w, http.StatusInternalServerError, errors.New("the query could not be run"))
		return
	}
	tenant, _ := principalTenant(claims)
	logInfo("iris.nlquery", "execute", map[string]any{"tenant": tenant, "sub": claims.Sub, "query_type": string(checked.Type),
		"ast_hash": rs.ASTHash, "catalog": rs.CatalogVersion, "rows": len(rs.Rows), "series": len(rs.Series),
		"truncated": rs.Truncated, "duration_ms": rs.Provenance.DurationMs})
	out := map[string]any{"result": rs, "validation": vr}
	rec.Answered(rs)
	if id := s.nlqCapture(r, claims, &rec, start); id != "" {
		out["query_log_id"] = id
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- Iris NL: conversations (tracker 337 N-C7) --------------------------------
//
// POST /api/ai/conversations                 start one (owner + tenant scope from claims)
// GET  /api/ai/conversations/{id}            its turns — the owner's own only; otherwise 404
// POST /api/ai/conversations/{id}/messages   {question, tz?, incident_id?} → the compile
//      answer + the result, compiled against the SERVER-HELD state of earlier
//      turns ("that device", "what else did they change"); an answered turn
//      carries the editable filter chips of the query it ran
// POST /api/ai/conversations/{id}/edits      {base, chip, op, value?} → one
//      chip edit, regenerated and validated server-side (see below)
//
// §3a: a conversation belongs to one principal in one tenant scope; another
// user of the same tenant, the same user in another scope, and an id that
// never existed all get the same 404. The state (entity ids, actors, the last
// validated query) never leaves the server and is never accepted from the
// client; every query built from it is validated again against the caller's
// CURRENT visibility before it runs.

// newIrisConvoStore picks the conversation store: Postgres (RLS) when the
// platform database is active, otherwise memory — conversations are working
// state, and a restart simply starts new ones.
func newIrisConvoStore() irisconvo.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return irisconvo.NewPGStore(ps.DB())
	}
	return irisconvo.NewMemStore()
}

func (s *server) handleAIConversations(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.nlqGate(w, r)
	if !ok {
		return
	}
	if s.nlqConvos == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("Iris conversations are not available on this deployment"))
		return
	}
	tenant, _ := principalTenant(claims)
	c, err := s.nlqConvos.Create(r.Context(), tenant, claims.Sub)
	switch {
	case errors.Is(err, irisconvo.ErrInvalid):
		writeError(w, http.StatusBadRequest, errors.New("a conversation needs a signed-in user and a workspace"))
		return
	case err != nil:
		logError("iris.convo", "create failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the conversation could not be started"))
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// handleAIConversation serves /api/ai/conversations/{id}[/messages].
func (s *server) handleAIConversation(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/ai/conversations/")
	id, sub, _ := strings.Cut(rest, "/")
	if !irisconvo.ValidID(id) || (sub != "" && sub != "messages" && sub != "edits") {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	switch sub {
	case "messages":
		s.handleAIConversationMessage(w, r, id)
		return
	case "edits":
		s.handleAIConversationEdit(w, r, id)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	if !aiEnabled() {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Iris AI is disabled — set FEATURE_AI=true"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok || !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
		return
	}
	if s.nlqConvos == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("Iris conversations are not available on this deployment"))
		return
	}
	tenant, _ := principalTenant(claims)
	c, err := s.nlqConvos.Get(r.Context(), tenant, claims.Sub, id)
	switch {
	case errors.Is(err, irisconvo.ErrNotFound):
		writeError(w, http.StatusNotFound, errors.New("not found"))
	case err != nil:
		logError("iris.convo", "read failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the conversation could not be read"))
	default:
		writeJSON(w, http.StatusOK, c)
	}
}

func (s *server) handleAIConversationMessage(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := s.nlqGate(w, r)
	if !ok {
		return
	}
	if s.nlqConvos == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("Iris conversations are not available on this deployment"))
		return
	}
	var req struct {
		Question   string `json:"question"`
		IncidentID string `json:"incident_id"`
		TZ         string `json:"tz"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // no client-supplied state, prior query or tenant
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if q := strings.TrimSpace(req.Question); q == "" || len([]rune(q)) > nlqQuestionMax {
		writeError(w, http.StatusBadRequest, fmt.Errorf("question is 1 to %d characters", nlqQuestionMax))
		return
	}
	loc := time.UTC
	if req.TZ != "" {
		l, err := time.LoadLocation(req.TZ)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("tz must be an IANA time zone"))
			return
		}
		loc = l
	}
	incident := strings.TrimSpace(req.IncidentID)
	if incident != "" && !isUUIDToken(incident) {
		writeError(w, http.StatusBadRequest, errors.New("incident_id is not an incident id"))
		return
	}
	tenant, _ := principalTenant(claims)
	conv, err := s.nlqConvos.Get(r.Context(), tenant, claims.Sub, id)
	if errors.Is(err, irisconvo.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if err != nil {
		logError("iris.convo", "read failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the conversation could not be read"))
		return
	}
	st := conv.State
	start := time.Now()
	cx := compile.Context{Loc: loc, Now: time.Now(), IncidentID: incident, PriorAST: st.LastAST,
		Conv: &compile.Conversation{Entities: st.Entities, Actors: st.Actors, ChangeIDs: st.ChangeIDs}}
	c, err := s.nlqCompileQuestion(r, claims, req.Question, cx)
	if err != nil {
		logError("iris.nlquery", "compile failed", errf(err))
		rec := irisquerylog.Record{Source: irisquerylog.SourceConversation, Question: req.Question, Outcome: irisquerylog.OutcomeError, ConversationID: id}
		s.nlqCapture(r, claims, &rec, start)
		writeError(w, http.StatusInternalServerError, errors.New("the question could not be compiled"))
		return
	}
	rec := c.record(irisquerylog.SourceConversation, req.Question)
	rec.ConversationID = id
	turn := irisconvo.Turn{Question: req.Question, Intent: c.res.Intent}
	out := c.body()
	next := st
	status := http.StatusOK
	switch {
	case c.res.Decline != "":
		turn.Outcome = irisconvo.OutcomeDeclined
	case len(c.res.Clarify) > 0:
		turn.Outcome = irisconvo.OutcomeClarify
	case c.res.Unparsed || c.res.AST == nil:
		turn.Outcome = irisconvo.OutcomeUnparsed
	case c.checked == nil:
		turn.Outcome = irisconvo.OutcomeInvalid
	default:
		next, status = s.nlqConvoRun(r, claims, st, c.checked, *c.vr, &turn, &rec, out)
	}
	// The question is recorded whether or not the turn can be appended: it
	// was compiled (and possibly run) either way.
	logID := s.nlqCapture(r, claims, &rec, start)
	if logID != "" {
		out["query_log_id"] = logID
	}
	if turn.Outcome == irisconvo.OutcomeAnswered {
		next.LastLogID = logID
	}
	s.nlqConvoSave(w, r, claims, id, turn, next, out, status)
}

// nlqConvoRun runs a VALIDATED query as a conversation turn: it fills the
// turn, the record and the answer, and returns the state the turn leaves (st
// unchanged unless the query answered) and the response status.
func (s *server) nlqConvoRun(r *http.Request, claims jwtClaims, st irisconvo.State, checked *nlqast.AST, vr validate.Result,
	turn *irisconvo.Turn, rec *irisquerylog.Record, out map[string]any) (irisconvo.State, int) {
	next, status := st, http.StatusOK
	rs, err := s.nlqRun(r, claims, checked, vr)
	switch {
	case errors.Is(err, plan.ErrNotFound):
		// An ANSWER ("no such incident"), recorded as a turn — not a 404,
		// which the client reads as "this conversation is gone".
		turn.Outcome = irisconvo.OutcomeError
		out["error"] = "not found"
	case err != nil:
		logError("iris.nlquery", "execute failed", errf(err))
		turn.Outcome, status = irisconvo.OutcomeError, http.StatusInternalServerError
		out["error"] = "the query could not be run"
	default:
		turn.Outcome, turn.ASTHash, turn.QueryID = irisconvo.OutcomeAnswered, rs.ASTHash, rs.QueryID
		turn.Rows = len(rs.Rows) + len(rs.Series)
		next = irisconvo.Next(s.nlqCatalog, st, checked, rs)
		out["result"] = rs
		rec.Answered(rs)
	}
	if turn.Outcome == irisconvo.OutcomeError {
		rec.Outcome = irisquerylog.OutcomeError
	}
	return next, status
}

// nlqConvoSave appends the turn and writes the answer. An answered turn also
// carries the filter chips of the query it ran (built from the state as
// STORED, so the chips and the query an edit is checked against are the same)
// and chips_for, the hash of that query, which an edit must echo.
func (s *server) nlqConvoSave(w http.ResponseWriter, r *http.Request, claims jwtClaims, id string,
	turn irisconvo.Turn, next irisconvo.State, out map[string]any, status int) {
	tenant, _ := principalTenant(claims)
	saved, err := s.nlqConvos.Append(r.Context(), tenant, claims.Sub, id, turn, next)
	switch {
	case errors.Is(err, irisconvo.ErrFull):
		writeError(w, http.StatusConflict, err)
		return
	case errors.Is(err, irisconvo.ErrNotFound):
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	case err != nil:
		logError("iris.convo", "append failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the conversation could not be saved"))
		return
	}
	out["conversation_id"] = saved.ID
	out["turn"] = saved.Turns[len(saved.Turns)-1]
	if turn.Outcome == irisconvo.OutcomeAnswered && saved.State.LastAST != nil {
		out["chips"] = chips.Build(s.nlqCatalog, saved.State.LastAST, s.nlqChipKnown(r, claims, saved.State))
		out["chips_for"] = saved.State.LastAST.Hash()
	}
	logInfo("iris.convo", "turn", map[string]any{"tenant": tenant, "sub": claims.Sub, "intent": turn.Intent,
		"outcome": turn.Outcome, "edited": turn.Edited, "turns": len(saved.Turns), "question_chars": len(turn.Question)})
	writeJSON(w, status, out)
}

// ---- Iris NL: editable filter chips (tracker 337 N-C7 / N-C8) ---------------
//
// POST /api/ai/conversations/{id}/edits  {base, chip, op, value?}
//      → the answer to the query REGENERATED from one chip edit of the
//        conversation's last answer, as a new turn of the same conversation.
//
// The client never sends a query. It names a chip the server built for the
// query the SERVER holds (base = that query's hash, so an edit of an answer
// that is no longer the latest is refused), an op (set / remove) and, for
// set, one of the values the server offered for that chip. The regenerated
// query is then validated exactly like a compiled one — in the caller's
// CURRENT scope, so a foreign or vanished entity is unknown_entity — before
// anything runs. A valid edit is also filed as a wrong_filter correction on
// the query-log record of the answer it edited, carrying the regenerated
// query (offline evaluation only).
//
// §3a: the conversation is the caller's own (another tenant, a colleague and
// an as_tenant walk get the same 404 as an unknown id); entity options come
// from the caller's own conversation and scoped inventory.

const nlqChipEditBody = 2 << 10

func (s *server) handleAIConversationEdit(w http.ResponseWriter, r *http.Request, id string) {
	claims, ok := s.nlqGate(w, r)
	if !ok {
		return
	}
	if s.nlqConvos == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("Iris conversations are not available on this deployment"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, nlqChipEditBody)
	var req struct {
		Base  string `json:"base"`
		Chip  string `json:"chip"`
		Op    string `json:"op"`
		Value string `json:"value"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // no query, state or tenant from the client — ever
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Chip == "" || len(req.Chip) > 64 || len(req.Base) != 64 || len(req.Value) > 256 {
		writeError(w, http.StatusBadRequest, errors.New("an edit names the answer (base), a chip, an op and — to change it — a value"))
		return
	}
	tenant, _ := principalTenant(claims)
	conv, err := s.nlqConvos.Get(r.Context(), tenant, claims.Sub, id)
	if errors.Is(err, irisconvo.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if err != nil {
		logError("iris.convo", "read failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the conversation could not be read"))
		return
	}
	st := conv.State
	if st.LastAST == nil || st.LastAST.Hash() != req.Base {
		writeError(w, http.StatusConflict, errors.New("that answer is no longer the latest in this conversation — edit the filters of the newest answer"))
		return
	}
	start := time.Now()
	q, chip, err := chips.Apply(s.nlqCatalog, st.LastAST, s.nlqChipKnown(r, claims, st),
		chips.Edit{Chip: req.Chip, Op: req.Op, Value: req.Value})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	desc := chips.Describe(chip, chips.Edit{Chip: req.Chip, Op: req.Op, Value: req.Value})
	// Untrusted exactly like a compiled or client-written query.
	checked, vr := validate.Validate(r.Context(), s.nlqCatalog, s.nlqScopeFor(r, claims), q)
	rec := irisquerylog.FromChipEdit(desc, id, q, checked, vr)
	turn := irisconvo.Turn{Question: desc, Intent: "edit_filter", Edited: true}
	out := map[string]any{"intent": "edit_filter", "validation": vr, "edit": desc}
	next, status := st, http.StatusOK
	if !vr.Valid || checked == nil {
		turn.Outcome = irisconvo.OutcomeInvalid
		out["ast"] = q // shown, never run
	} else {
		out["ast"] = checked
		next, status = s.nlqConvoRun(r, claims, st, checked, vr, &turn, &rec, out)
		out["correction"] = s.nlqChipCorrection(r, claims, st.LastLogID, desc, checked)
	}
	logID := s.nlqCapture(r, claims, &rec, start)
	if logID != "" {
		out["query_log_id"] = logID
	}
	if turn.Outcome == irisconvo.OutcomeAnswered {
		next.LastLogID = logID
	}
	s.nlqConvoSave(w, r, claims, id, turn, next, out, status)
}

// nlqChipCorrection files a valid chip edit as a wrong_filter correction on
// the caller's own record of the answer it edited, carrying the regenerated
// (validated) query. It never fails the edit: the outcome is reported —
// "recorded", "full" (the record holds its maximum), or "unavailable" (no
// record: its capture failed, it expired, or capture is off).
func (s *server) nlqChipCorrection(r *http.Request, claims jwtClaims, logID, desc string, checked *nlqast.AST) string {
	if s.nlqQueryLog == nil || logID == "" {
		return "unavailable"
	}
	tenant, _ := principalTenant(claims)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), nlqCaptureTimeout)
	defer cancel()
	_, err := s.nlqQueryLog.Correct(ctx, tenant, claims.Sub, logID,
		irisquerylog.Correction{Kind: irisquerylog.KindWrongFilter, By: claims.Sub, Note: desc, CorrectedAST: checked})
	switch {
	case err == nil:
		s.nlqQueryLogMetrics.Corrected(irisquerylog.KindWrongFilter)
		return "recorded"
	case errors.Is(err, irisquerylog.ErrFull):
		return "full"
	case errors.Is(err, irisquerylog.ErrNotFound):
		return "unavailable"
	default:
		logError("iris.querylog", "chip-edit correction failed", map[string]any{"tenant": tenant, "error": err.Error()})
		return "unavailable"
	}
}

// nlqChipMaxInventory bounds the inventory read behind one entity chip.
const nlqChipMaxInventory = chips.MaxOptions

// nlqChipKnown is what an entity chip may be changed to: the entities this
// conversation already showed (most recent first), then — for sites and
// devices — the caller's own visible inventory. Everything here is the
// caller's: the conversation is theirs and the inventory is read through
// their scope; whatever is picked is validated again before it runs.
func (s *server) nlqChipKnown(r *http.Request, claims jwtClaims, st irisconvo.State) chips.Known {
	cache := map[string][]chips.Option{}
	return func(typ string) []chips.Option {
		if v, ok := cache[typ]; ok {
			return v
		}
		names := map[string]string{}
		var inv []chips.Option
		if typ == "site" || typ == "device" {
			named, err := newNLQLookups(s, r, claims).Inventory(r.Context(), []string{typ})
			if err != nil {
				logError("iris.nlquery", "chip options unavailable", errf(err))
			}
			for _, n := range named {
				if len(inv) == nlqChipMaxInventory {
					break
				}
				label := n.ID
				if len(n.Names) > 0 && n.Names[0] != "" {
					label = n.Names[0]
				}
				names[n.ID] = label
				inv = append(inv, chips.Option{Value: n.ID, Label: label})
			}
			sort.Slice(inv, func(i, j int) bool { return inv[i].Label < inv[j].Label })
		}
		var out []chips.Option
		scope := s.nlqScopeFor(r, claims)
		for _, e := range st.Entities {
			if e.Type != typ {
				continue
			}
			// Cached state is not trusted: an entity is offered only while
			// the caller can still see it (an edit is validated again anyway).
			ok, err := scope.Visible(r.Context(), e)
			if err != nil {
				// A failed check is not "invisible": it is logged, and the
				// entity is withheld (fail closed) rather than offered unchecked.
				logError("iris.nlquery", "chip option visibility check failed", errf(err))
				continue
			}
			if !ok {
				continue // no longer the caller's to see
			}
			out = append(out, chips.Option{Value: e.ID, Label: names[e.ID]})
		}
		out = append(out, inv...)
		cache[typ] = out
		return out
	}
}

// ---- Iris NL: query capture + operator corrections (tracker 337 N-C8) -------
//
// Every compiled question — from the /api/ai/ask data arm, the query API and
// conversations — leaves one record (internal/irisquerylog): the question,
// intent, outcome, query hash, catalog version, validation codes, entities and
// how they resolved, counts and duration. Never result rows, never prose.
//
// GET  /api/ai/queries[?scope=tenant][&limit=N]  the caller's own recent
//      questions; scope=tenant (a workspace admin) lists the whole tenant's
// POST /api/ai/queries/{id}/corrections  {kind, note?, ast?} — "that's not what
//      I meant", on the caller's OWN record only; a corrected query is decoded
//      strictly and validated in the caller's scope before it is kept
//
// §3a: the tenant and principal come from the token, never the request; a
// record of another tenant or (for corrections) another person is the same
// 404 as one that never existed. Corrections are stored for OFFLINE
// evaluation only — nothing feeds them back into the compiler.

// newIrisQueryLogStore picks the query-log store: Postgres (RLS) when the
// platform database is active, otherwise memory.
func newIrisQueryLogStore() irisquerylog.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return irisquerylog.NewPGStore(ps.DB())
	}
	return irisquerylog.NewMemStore()
}

// nlqCaptureTimeout bounds one capture write; the operator is waiting on it.
const nlqCaptureTimeout = 3 * time.Second

// nlqCapture stores rec for the caller and returns its id, or "" when capture
// is off or failed. A failure NEVER fails the operator's question: it is
// counted (netops_iris_query_capture_total{result="failed"}) and logged.
func (s *server) nlqCapture(r *http.Request, claims jwtClaims, rec *irisquerylog.Record, start time.Time) string {
	if s.nlqQueryLog == nil {
		return ""
	}
	tenant, _ := principalTenant(claims)
	rec.Principal = claims.Sub
	rec.TenantID = tenant
	if rec.CatalogVersion == "" && s.nlqCatalog != nil {
		rec.CatalogVersion = s.nlqCatalog.Version()
	}
	rec.Took(start)
	// Detached from the request's cancellation: an operator who closes the
	// drawer mid-answer still leaves the record the evaluation needs.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), nlqCaptureTimeout)
	defer cancel()
	saved, err := s.nlqQueryLog.Record(ctx, tenant, *rec)
	s.nlqQueryLogMetrics.Captured(err == nil)
	if err != nil {
		logError("iris.querylog", "capture failed", map[string]any{"tenant": tenant, "source": rec.Source, "error": err.Error()})
		return ""
	}
	return saved.ID
}

// withQueryLogID adds "query_log_id" to a data-arm payload (a JSON object the
// server itself encoded), so the answer can be corrected. Anything that is not
// an object is returned unchanged.
func withQueryLogID(payload json.RawMessage, id string) json.RawMessage {
	var obj map[string]json.RawMessage
	if len(payload) == 0 || json.Unmarshal(payload, &obj) != nil || obj == nil {
		return payload
	}
	enc, err := json.Marshal(id)
	if err != nil {
		return payload
	}
	obj["query_log_id"] = enc
	out, err := json.Marshal(obj)
	if err != nil {
		return payload
	}
	return out
}

func (s *server) handleAIQueries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	if !aiEnabled() {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Iris AI is disabled — set FEATURE_AI=true"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok || !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
		return
	}
	if s.nlqQueryLog == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the Iris query log is not available on this deployment"))
		return
	}
	q := r.URL.Query()
	scope := q.Get("scope")
	f := irisquerylog.ListFilter{Principal: claims.Sub}
	switch scope {
	case "", "mine":
		scope = "mine"
	case "tenant":
		// The whole workspace's questions: its admins only. The tenant is
		// still the caller's own — there is no cross-tenant listing.
		if s.roles == nil || !s.roles.Allows(claims.Role, "administration", LevelAdmin) {
			writeError(w, http.StatusForbidden, errors.New("only a workspace admin can see everyone's questions"))
			return
		}
		f.Principal = ""
	default:
		writeError(w, http.StatusBadRequest, errors.New("scope is mine or tenant"))
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > irisquerylog.MaxListLimit {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit is 1 to %d", irisquerylog.MaxListLimit))
			return
		}
		f.Limit = n
	}
	tenant, _ := principalTenant(claims)
	recs, err := s.nlqQueryLog.List(r.Context(), tenant, f)
	if err != nil {
		logError("iris.querylog", "list failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("recent questions could not be read"))
		return
	}
	// The workspace view shows WHAT was asked about and how it went — intent,
	// outcome, entities, counts, when — never a colleague's own words: the
	// question text and correction notes of someone else's record are
	// withheld (they are that person's typed text, not operational data).
	if scope == "tenant" {
		for i := range recs {
			if recs[i].Principal != claims.Sub {
				withholdColleagueText(&recs[i])
			}
		}
	}
	// The list is a summary: the query itself is read one record at a time
	// (GET /api/ai/query/{id}); compiled_by stays, so a model-written query
	// is disclosed in the list too.
	for i := range recs {
		recs[i].Query = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"queries": recs, "scope": scope,
		"retention_days": int(irisquerylog.Retention.Hours() / 24), "kinds": irisquerylog.Kinds})
}

// handleAIQueryCorrection serves POST /api/ai/queries/{id}/corrections.
func (s *server) handleAIQueryCorrection(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/ai/queries/")
	id, sub, _ := strings.Cut(rest, "/")
	if !irisquerylog.ValidID(id) || sub != "corrections" {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	claims, ok := s.nlqGate(w, r)
	if !ok {
		return
	}
	if s.nlqQueryLog == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the Iris query log is not available on this deployment"))
		return
	}
	var req struct {
		Kind string          `json:"kind"`
		Note string          `json:"note"`
		AST  json.RawMessage `json:"ast"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a smuggled tenant or principal is an error, not a silent no-op
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !irisquerylog.ValidKind(req.Kind) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("kind is one of %s", strings.Join(irisquerylog.Kinds, ", ")))
		return
	}
	if len([]rune(req.Note)) > irisquerylog.MaxNoteLen {
		writeError(w, http.StatusBadRequest, fmt.Errorf("note is at most %d characters", irisquerylog.MaxNoteLen))
		return
	}
	// The corrected query is untrusted exactly like a model-written one: it is
	// decoded strictly and validated against what the caller can see NOW.
	checked, vr, err := irisquerylog.CheckCorrectedAST(r.Context(), s.nlqCatalog, s.nlqScopeFor(r, claims), req.AST)
	switch {
	case errors.Is(err, irisquerylog.ErrRejected):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"validation": vr})
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _ := principalTenant(claims)
	rec, err := s.nlqQueryLog.Correct(r.Context(), tenant, claims.Sub, id,
		irisquerylog.Correction{Kind: req.Kind, By: claims.Sub, Note: req.Note, CorrectedAST: checked})
	switch {
	case errors.Is(err, irisquerylog.ErrNotFound):
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	case errors.Is(err, irisquerylog.ErrFull):
		writeError(w, http.StatusConflict, err)
		return
	case errors.Is(err, irisquerylog.ErrInvalid):
		writeError(w, http.StatusBadRequest, err)
		return
	case err != nil:
		logError("iris.querylog", "correction failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the correction could not be saved"))
		return
	}
	s.nlqQueryLogMetrics.Corrected(req.Kind)
	// No note text in the log line — only what kind of wrong it was.
	logInfo("iris.querylog", "correction", map[string]any{"tenant": tenant, "sub": claims.Sub, "kind": req.Kind,
		"with_query": checked != nil, "note_chars": len(req.Note), "corrections": len(rec.Corrections)})
	writeJSON(w, http.StatusCreated, rec)
}

// withholdColleagueText blanks what a colleague TYPED — the question and
// their correction notes — from a record a workspace admin reads. What was
// asked about and how it went (intent, outcome, entities, the query) stays:
// that is operational data, not the person's own words.
func withholdColleagueText(rec *irisquerylog.Record) {
	rec.Question = ""
	for j := range rec.Corrections {
		rec.Corrections[j].Note = ""
	}
}

// ---- Iris NL: one query, and what it does (tracker 337 N-C5) ----------------
//
// GET /api/ai/query/{id}          one query-log record: the question, the
//      outcome, the VALIDATED query and who wrote it (compiled_by: grammar,
//      model or supplied) — a model-written query carries the disclosure
// GET /api/ai/query/{id}/explain  that query in plain language (metric,
//      entities, filters, window, grouping, …), whether the grammar or the
//      model wrote it (source=model disclosed), and whether it still validates
//      for the caller NOW
//
// §3a: the tenant and principal come from the token, never the request; the
// record is read inside the caller's tenant only (RLS iris_query_log + the
// store's tenant key), so another tenant's id — and an as_tenant walk into
// another org — is the same 404 as an id that never existed. A colleague's
// record is 404 too, except to a workspace admin, who reads it exactly as the
// workspace list shows it: without the colleague's own words.

func (s *server) handleAIQueryRecord(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/ai/query/")
	id, sub, _ := strings.Cut(rest, "/")
	if !irisquerylog.ValidID(id) || (sub != "" && sub != "explain") {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	if !aiEnabled() {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Iris AI is disabled — set FEATURE_AI=true"))
		return
	}
	// N-A7: reading a captured query back (and explaining it) is part of
	// ai.nlquery, like the query log it reads.
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok || !s.requireAIEntitlement(w, claims, aientitlement.NLQuery) {
		return
	}
	if s.nlqQueryLog == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the Iris query log is not available on this deployment"))
		return
	}
	if sub == "explain" {
		if s.nlqCatalog == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("the Iris query catalog is not available on this deployment"))
			return
		}
		// Explaining re-validates the query against the caller's inventory:
		// it shares the per-principal Iris budget.
		if !s.copilotLimiter.AllowN(claims.Tenant+"|"+claims.Sub, envInt("COPILOT_RATE_PER_MIN", 20)) {
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("Iris AI rate limit exceeded — slow down"))
			return
		}
	}
	rec, ok := s.nlqReadRecord(w, r, claims, id)
	if !ok {
		return
	}
	if sub == "" {
		writeJSON(w, http.StatusOK, nlqRecordView{Record: rec, Disclosure: nlqDisclosureFor(rec)})
		return
	}
	writeJSON(w, http.StatusOK, s.nlqExplainRecord(r, claims, rec))
}

// nlqRecordView is one record as GET /api/ai/query/{id} returns it.
type nlqRecordView struct {
	irisquerylog.Record
	Disclosure string `json:"disclosure,omitempty"`
}

// nlqDisclosureFor is the model disclosure for a model-written record, else "".
func nlqDisclosureFor(rec irisquerylog.Record) string {
	if rec.CompiledBy == irisquerylog.CompiledByModel {
		return nlqModelDisclosure
	}
	return ""
}

// nlqReadRecord reads one record for the caller, writing the error response
// itself. The tenant is the caller's own; the principal filter is the
// caller's, unless the caller is a workspace admin (then the colleague's
// typed text is withheld).
func (s *server) nlqReadRecord(w http.ResponseWriter, r *http.Request, claims jwtClaims, id string) (irisquerylog.Record, bool) {
	tenant, _ := principalTenant(claims)
	principal := claims.Sub
	if s.roles != nil && s.roles.Allows(claims.Role, "administration", LevelAdmin) {
		principal = "" // the workspace's records — still this tenant's only
	}
	if strings.TrimSpace(claims.Sub) == "" || strings.TrimSpace(tenant) == "" {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return irisquerylog.Record{}, false
	}
	rec, err := s.nlqQueryLog.Get(r.Context(), tenant, principal, id)
	switch {
	case errors.Is(err, irisquerylog.ErrNotFound):
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return irisquerylog.Record{}, false
	case err != nil:
		logError("iris.querylog", "read failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the question could not be read"))
		return irisquerylog.Record{}, false
	}
	if rec.Principal != claims.Sub {
		withholdColleagueText(&rec)
	}
	return rec, true
}

// nlqExplainRecord explains rec's query for the caller.
func (s *server) nlqExplainRecord(r *http.Request, claims jwtClaims, rec irisquerylog.Record) map[string]any {
	out := map[string]any{"id": rec.ID, "asked_via": rec.Source, "outcome": rec.Outcome, "question": rec.Question,
		"query_type": rec.QueryType, "compiled_by": rec.CompiledBy, "catalog_version": rec.CatalogVersion,
		"catalog_current": rec.CatalogVersion == "" || rec.CatalogVersion == s.nlqCatalog.Version()}
	if rec.CompiledBy == irisquerylog.CompiledByModel {
		out["source"] = modelc.SourceModel // interpreted by the model, not the grammar
		out["disclosure"] = nlqModelDisclosure
	}
	tenant, _ := principalTenant(claims)
	logInfo("iris.nlquery", "explain", map[string]any{"tenant": tenant, "sub": claims.Sub, "id": rec.ID,
		"own": rec.Principal == claims.Sub, "compiled_by": rec.CompiledBy, "outcome": rec.Outcome})
	if rec.Query == nil {
		out["explanation"] = nil
		out["reason"] = nlqNoQueryReason(rec.Outcome)
		out["validation_codes"] = rec.ValidationCodes
		return out
	}
	scope := s.nlqScopeFor(r, claims)
	// The stored query is re-validated against what the caller can see NOW:
	// an entity they lost access to since is reported, never silently run.
	_, vr := validate.Validate(r.Context(), s.nlqCatalog, scope, rec.Query)
	out["query"] = rec.Query
	out["still_valid"] = vr.Valid
	out["validation"] = vr
	out["explanation"] = explain.Explain(s.nlqCatalog, rec.Query, s.nlqDeviceNamer(r.Context(), scope, rec.Query))
	return out
}

// nlqDeviceNamer names the query's devices from the caller's VISIBLE inventory
// only: a device the caller cannot see (any more) is shown by its id, which
// the record already carries — never by a name looked up past their scope.
func (s *server) nlqDeviceNamer(ctx context.Context, scope *nlqScope, q *nlqast.AST) explain.Namer {
	var ids []string
	for _, ref := range q.Refs {
		if ref.Type == "device" {
			ids = append(ids, strings.TrimPrefix(ref.ID, "device:"))
		}
	}
	if len(ids) == 0 {
		return nil
	}
	devs, err := scope.Devices(ctx, plan.DeviceFilter{IDs: ids})
	if err != nil {
		logError("iris.nlquery", "explain: device names unavailable", errf(err))
		return nil
	}
	names := make(map[string]string, len(devs))
	for _, d := range devs {
		names["device:"+d.ID] = d.Name
	}
	return func(ref nlqast.EntityRef) string { return names[ref.ID] }
}

// nlqNoQueryReason says, for a record without a query, why there is none.
func nlqNoQueryReason(outcome string) string {
	switch outcome {
	case irisquerylog.OutcomeClarify:
		return "Iris needed you to choose between matches, so no query was built."
	case irisquerylog.OutcomeDeclined:
		return "Iris declined this question, so no query was built."
	case irisquerylog.OutcomeUnparsed:
		return "Iris did not understand this question, so no query was built."
	case irisquerylog.OutcomeInvalid:
		return "The query Iris built did not pass its checks, so it was never run. The check codes say why."
	case irisquerylog.OutcomeError:
		return "Iris failed while answering this question, before a query was kept."
	}
	return "No query was kept for this question."
}

// ---- the Iris AI decision ledger (tracker 337 N-A6,
// internal/aidecision, migration 0056).
//
// Every accepted POST /api/ai/ask is one DECISION: a Recorder rides the
// request context, and each seam the decision passes through adds its steps —
//
//	QUESTION_RECEIVED       the handler (SHA-256 of the question, the incident
//	                        id the UI named)
//	INVESTIGATION_STARTED   the first troubleshooting method of a chain
//	PLAN_CREATED            a next method chosen (rule / model), or a typed
//	                        query compiled by the data arm (result = its hash)
//	TOOL_SELECTED           a tool the plan named that is not wired here
//	POLICY_EVALUATED        every Policy Engine verdict on a tool (allow / deny)
//	TOOL_EXECUTED           every tool run, with SHA-256 of its arguments and
//	                        of its result
//	EVIDENCE_ADDED          the citations the answer rests on (hash of the ids)
//	RECOMMENDATION_CREATED  the next actions it recommends (hash)
//	ANSWER_RETURNED         the answer: mode, intent, the model that answered
//	                        (provider, model name, tier), hash of the answer,
//	                        the persisted answer id / query-log id
//
// — and the handler appends them in ONE transaction at the end. Hashes only:
// no question text, no tool values, no results, no prose (§8, §15 LLM06).
//
// A ledger write is best-effort for the operator — a failed append never
// costs them the answer — but never silent: it is counted
// (netops_ai_decision_ledger_decisions_total{result="failed"}), logged, and the
// answer then carries NO decision_id, so the UI never points at a record that
// does not exist.
//
// The ask also enters the platform AUDIT TRAIL with its decision id (aiAskAudit),
// beside the request envelope withAudit already writes: the trail says who asked
// and how it ended; the ledger says how the answer was reached.
//
// GET /api/ai/decisions[?decision_id=][&before=RFC3339][&limit=N] — workspace
// admins read their own tenant's ledger; the platform owner reads every
// tenant's. Tenant and scope come from the token only (§3a).

// newAIDecisionStore picks the ledger store: Postgres (append-only, RLS) when
// the platform database is active, otherwise the bounded in-memory store.
func newAIDecisionStore() aidecision.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return aidecision.NewPGStore(ps.DB())
	}
	return aidecision.NewMemStore()
}

// aiDecisionAppendTimeout bounds the one ledger write per decision.
const aiDecisionAppendTimeout = 3 * time.Second

// aiToolVersion is the version of every compiled-in tool: the build itself.
// "unknown" stays visible (build_provenance.go: never invent a revision).
func aiToolVersion() string {
	sha := buildSHA
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return aidecision.Token(version + "+" + sha)
}

// aiDecisionStart opens the ledger record for one accepted question and
// returns the request carrying it. Without a ledger store it returns r
// unchanged and a nil Recorder (every Recorder method is nil-safe).
func (s *server) aiDecisionStart(r *http.Request, claims jwtClaims, req aiAskRequest) (*http.Request, *aidecision.Recorder) {
	if s.aiDecisions == nil {
		return r, nil
	}
	rec, err := aidecision.NewRecorder(claims.Sub, aidecision.SurfaceAsk)
	if err != nil {
		logError("ai.ledger", "decision id unavailable — this ask is not ledgered", errf(err))
		s.aiDecisionMetrics.Failed()
		return r, nil
	}
	incident := req.Context["correlation_id"]
	if incident == "" {
		incident = req.Context["problem_id"]
	}
	rec.Add(aidecision.Entry{
		EventType:   aidecision.QuestionReceived,
		IncidentRef: incident,
		ArgsSHA256:  aidecision.SHA256Hex([]byte(req.Question)),
	})
	return r.WithContext(aidecision.WithRecorder(r.Context(), rec)), rec
}

// aiLedgerToolEntry hands one audited tool step to the request's Recorder
// (the event mapping is aidecision.Recorder.AddToolStep). The orchestrator's
// ToolAudit hook calls it; rec is nil outside a ledgered request.
func aiLedgerToolEntry(rec *aidecision.Recorder, e ai.ToolAuditEntry) {
	rec.AddToolStep(aidecision.ToolStep{Skill: e.Skill, Tool: e.Tool, Selected: e.Selected, Reason: e.Reason,
		Items: e.Items, ArgsSHA256: e.ArgsSHA256, ResultSHA256: e.ResultSHA256}, aiToolVersion())
}

// nlqLedgerTool names the data arm's query execution in the ledger.
const nlqLedgerTool = "nl_query"

// nlqPlanEntry is the data arm's PLAN_CREATED: the question (hashed) became a
// typed query (its hash is the result) — or did not (the outcome says why).
// When the model fallback wrote the query, the model that did is named.
func nlqPlanEntry(ledger *aidecision.Recorder, question string, c nlqCompiled, rec irisquerylog.Record) aidecision.Entry {
	e := aidecision.Entry{EventType: aidecision.PlanCreated, Intent: c.res.Intent, Tool: nlqLedgerTool,
		ArgsSHA256: aidecision.SHA256Hex([]byte(question)), Outcome: rec.Outcome}
	if rec.ASTHash != "" && aidecision.ValidSHA256(rec.ASTHash) {
		e.ResultSHA256 = rec.ASTHash
	}
	if rec.CatalogVersion != "" {
		e.ToolVersion = "catalog:" + rec.CatalogVersion
	}
	if c.source == modelc.SourceModel {
		m, _ := ledger.Model()
		e.ModelProvider, e.ModelName, e.ModelTier = m.Provider, m.Name, m.Tier
	}
	return e
}

// nlqLedgerRun is the data arm's TOOL_EXECUTED: the validated query (its hash
// is the arguments) ran, and this is the hash of the result set it returned.
func nlqLedgerRun(ledger *aidecision.Recorder, c nlqCompiled, rs *plan.ResultSet, runErr error) {
	if ledger == nil || c.checked == nil {
		return
	}
	e := aidecision.Entry{EventType: aidecision.ToolExecuted, Intent: c.res.Intent, Tool: nlqLedgerTool,
		ArgsSHA256: c.checked.Hash(), Outcome: "ok"}
	if !aidecision.ValidSHA256(e.ArgsSHA256) {
		e.ArgsSHA256 = ""
	}
	switch {
	case errors.Is(runErr, plan.ErrNotFound):
		e.Outcome = "not_found"
	case runErr != nil:
		e.Outcome = "tool_error"
	case rs != nil:
		e.ItemCount = len(rs.Rows) + len(rs.Series)
		if rs.CatalogVersion != "" {
			e.ToolVersion = "catalog:" + rs.CatalogVersion
		}
		if b, err := json.Marshal(rs); err == nil {
			e.ResultSHA256 = aidecision.SHA256Hex(b)
		}
	}
	ledger.Add(e)
}

// aiDecisionFinish closes the decision: the evidence, recommendation and
// answer entries, then ONE append; on success the answer is stamped with its
// decision id. ans is nil when the orchestrator failed (askErr). It also
// writes the ask into the platform audit trail. Returns the stored decision id
// ("" when nothing was stored).
func (s *server) aiDecisionFinish(r *http.Request, claims jwtClaims, rec *aidecision.Recorder, ans *ai.Answer, askErr error) string {
	stored := ""
	if rec != nil {
		model, _ := rec.Model()
		final := aidecision.Entry{EventType: aidecision.AnswerReturned,
			ModelProvider: model.Provider, ModelName: model.Name, ModelTier: model.Tier}
		if ans != nil {
			aiLedgerAnswerEntries(rec, ans)
			final.Intent, final.Mode = ans.Intent, string(ans.Mode)
			if final.ModelTier == "" {
				// No provider answered: the tier the router chose for this mode
				// (a deterministic mode says so).
				final.ModelTier = string(ai.RouteFor(ans.Mode).Tier)
			}
			if final.ModelProvider == "" {
				final.ModelProvider = ans.Provider
			}
			if ans.Skill != nil {
				final.Skill = ans.Skill.Name
			}
			final.ItemCount = len(ans.Citations)
			final.AnswerID = ans.AnswerID
			final.QueryLogID = aidecision.QueryLogID(ans.Data)
			final.Outcome = "answered"
			if ans.Mode == ai.ModeUnavailable {
				final.Outcome = "unavailable"
			}
			// The hash is of the answer as returned, before the decision id is
			// stamped on it (the id names the record; it cannot be inside it).
			body, err := json.Marshal(ans)
			if err != nil {
				logError("ai.ledger", "answer not hashable", errf(err))
			} else {
				final.ResultSHA256 = aidecision.SHA256Hex(body)
			}
		} else {
			final.Outcome = "error"
		}
		rec.Add(final)
		if s.aiDecisionAppend(r, claims, rec) {
			stored = rec.DecisionID()
			if ans != nil {
				ans.DecisionID = stored
			}
		}
	}
	s.aiAskAudit(r, claims, stored, ans, askErr)
	return stored
}

// aiLedgerAnswerEntries records what the answer rests on and recommends.
func aiLedgerAnswerEntries(rec *aidecision.Recorder, ans *ai.Answer) {
	if ans.Skill != nil {
		// No-op when a gather step already opened the investigation.
		rec.StartInvestigation(ans.Skill.Name, "entry")
	}
	ids := make([]string, 0, len(ans.Citations))
	for _, c := range ans.Citations {
		ids = append(ids, c.ID)
	}
	rec.AddEvidence(ids)
	aiLedgerHypotheses(rec, ans.Hypotheses)
	if len(ans.NextActions) > 0 {
		b, err := json.Marshal(ans.NextActions)
		if err != nil {
			logError("ai.ledger", "next actions not hashable", errf(err))
			return
		}
		rec.AddRecommendation(b, len(ans.NextActions))
	}
}

// aiDecisionAppend stores the decision. Detached from the request's
// cancellation (an operator who closes the drawer still leaves the record) and
// bounded by aiDecisionAppendTimeout. Reports whether it was stored.
func (s *server) aiDecisionAppend(r *http.Request, claims jwtClaims, rec *aidecision.Recorder) bool {
	tenant, _ := principalTenant(claims)
	s.aiDecisionMetrics.Dropped(rec.Dropped())
	entries := rec.Entries()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), aiDecisionAppendTimeout)
	defer cancel()
	if err := s.aiDecisions.Append(ctx, tenant, entries); err != nil {
		s.aiDecisionMetrics.Failed()
		logError("ai.ledger", "decision append failed", map[string]any{"tenant": tenant, "entries": len(entries), "error": err.Error()})
		return false
	}
	s.aiDecisionMetrics.Appended(len(entries))
	return true
}

// aiAskAudit enters one /api/ai/ask into the platform audit trail: who asked,
// the decision id, how it ended (intent, mode, provider, tier) — never the
// question or any retrieved data.
func (s *server) aiAskAudit(r *http.Request, claims jwtClaims, decisionID string, ans *ai.Answer, askErr error) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	detail := map[string]any{"action": "ai.ask", "decision_id": decisionID}
	status, decision := http.StatusOK, "allow"
	if askErr != nil || ans == nil {
		status, decision = http.StatusBadGateway, "error"
	} else {
		detail["intent"] = aidecision.Token(ans.Intent)
		detail["mode"] = string(ans.Mode)
		detail["provider"] = aidecision.Token(ans.Provider)
		detail["tier"] = string(ai.RouteFor(ans.Mode).Tier)
		if ans.AnswerID != "" {
			detail["answer_id"] = aidecision.Token(ans.AnswerID)
		}
	}
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross, SessionID: claims.Sid,
		Method: r.Method, Path: r.URL.Path, Status: status, Decision: decision,
		Remote: auditClientIP(r), Detail: detail,
	})
}

// aiLedgerHypotheses records the investigation's hypotheses (tracker 337
// N-B3): one HYPOTHESIS_CREATED per hypothesis — its id and final state, the
// method that opened it, the tool that tested it, and the hash of the
// hypothesis exactly as shown — plus HYPOTHESIS_REJECTED for each one its tool
// rejected. Iris never records ROOT_CAUSE_SELECTED: the engine owns the cause.
func aiLedgerHypotheses(rec *aidecision.Recorder, set *irishypo.Set) {
	if rec == nil || set == nil {
		return
	}
	for _, h := range set.Hypotheses {
		skill, tool := "", ""
		if len(h.Transitions) > 0 {
			skill, tool = h.Transitions[0].Skill, h.Transitions[0].Tool
		}
		e := aidecision.Entry{EventType: aidecision.HypothesisCreated, Skill: skill, Tool: tool,
			Outcome: h.ID + ":" + strings.ToLower(string(h.State))}
		if b, err := json.Marshal(h); err == nil {
			e.ResultSHA256 = aidecision.SHA256Hex(b)
		} else {
			logError("ai.ledger", "hypothesis not hashable", errf(err))
		}
		rec.Add(e)
		if h.State == irishypo.Rejected {
			rec.Add(aidecision.Entry{EventType: aidecision.HypothesisRejected, Skill: skill, Tool: tool, Outcome: h.ID})
		}
	}
}

// aiHypothesesHoldTimeout bounds the one hypothesis-store write per answer.
const aiHypothesesHoldTimeout = 2 * time.Second

// aiHypothesesHold names the answer's hypothesis set and holds it in the
// asker's tenant (tracker 337 N-B3). The id is the decision's when the ask is
// ledgered (one id names the investigation everywhere), else a fresh one; the
// tenant is the token's, never anything in the request. A set that cannot be
// held keeps no id — the answer still carries it inline — and the failure is
// logged, never fatal to the answer.
func (s *server) aiHypothesesHold(r *http.Request, claims jwtClaims, rec *aidecision.Recorder, ans *ai.Answer) {
	if ans == nil || ans.Hypotheses == nil {
		return
	}
	ans.Hypotheses.ID = ""
	if s.aiHypotheses == nil {
		return
	}
	id := rec.DecisionID()
	if id == "" {
		fresh, err := aidecision.NewID()
		if err != nil {
			logError("ai.hypotheses", "no id — this investigation's hypotheses are not held", errf(err))
			return
		}
		id = fresh
	}
	set := *ans.Hypotheses
	set.ID = id
	tenant, _ := principalTenant(claims)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), aiHypothesesHoldTimeout)
	defer cancel()
	if err := s.aiHypotheses.Put(ctx, tenant, set); err != nil {
		logError("ai.hypotheses", "hold failed", map[string]any{"tenant": tenant, "error": err.Error()})
		return
	}
	ans.Hypotheses.ID = id
}

// handleAIHypotheses serves GET /api/ai/hypotheses/{id}: one investigation's
// hypotheses, in the caller's own tenant (the platform owner: any tenant).
// Another tenant's id, an expired one and a malformed one are the same 404.
// Gated by ai.investigate — hypotheses exist only where the investigation loop
// runs — and by infrastructure:read, which every read they were built from
// needs.
func (s *server) handleAIHypotheses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	if !aiEnabled() {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Iris AI is disabled — set FEATURE_AI=true"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok || !s.requireAIEntitlement(w, claims, aientitlement.Investigate) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/ai/hypotheses/")
	if !irishypo.ValidID(id) {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if s.aiHypotheses == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("investigation hypotheses are not held on this deployment"))
		return
	}
	tenant, cross := principalTenant(claims)
	set, err := s.aiHypotheses.Get(r.Context(), tenant, cross, id)
	switch {
	case errors.Is(err, irishypo.ErrNotFound):
		writeError(w, http.StatusNotFound, errors.New("not found"))
	case err != nil:
		logError("ai.hypotheses", "read failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the investigation's hypotheses could not be read"))
	default:
		writeJSON(w, http.StatusOK, set)
	}
}

// handleAIDecisions serves GET /api/ai/decisions.
func (s *server) handleAIDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	// A workspace admin (own tenant) or the platform owner (every tenant). The
	// ledger is an audit record: it is readable whether or not Iris is on now.
	claims, ok := s.requirePerm(w, r, "administration", LevelAdmin)
	if !ok {
		return
	}
	if s.aiDecisions == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the AI decision ledger is not available on this deployment"))
		return
	}
	q := r.URL.Query()
	var f aidecision.ListFilter
	if v := strings.TrimSpace(q.Get("decision_id")); v != "" {
		if !aidecision.ValidID(v) {
			writeError(w, http.StatusBadRequest, errors.New("decision_id is a decision id"))
			return
		}
		f.DecisionID = v
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > aidecision.MaxListLimit {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit is 1 to %d", aidecision.MaxListLimit))
			return
		}
		f.Limit = n
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("before is an RFC 3339 time"))
			return
		}
		f.Before = t
	}
	tenant, cross := principalTenant(claims)
	entries, err := s.aiDecisions.List(r.Context(), tenant, cross, f)
	if err != nil {
		logError("ai.ledger", "list failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the AI decision ledger could not be read"))
		return
	}
	scope := "platform"
	if !cross {
		scope = "tenant"
		for i := range entries {
			entries[i].TenantID = "" // the caller's own tenant; never echoed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": entries, "scope": scope,
		"event_types": aidecision.EventTypes})
}
