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
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aiscore"
	"netops/backend/internal/entityalias"
	"netops/backend/internal/irisconvo"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/resolve"
	"netops/backend/internal/nlquery/validate"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/tac"
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
	// Per-tenant entitlement (§3a): cross-tenant principals are never gated.
	if !s.aiAssistantAllowed(claims) {
		writeError(w, http.StatusForbidden, errAITenantDisabled)
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
	var conv *irisconvo.Conversation
	if id := strings.TrimSpace(req.ConversationID); id != "" {
		c, status, err := s.askConversation(r, claims, id)
		if err != nil {
			writeError(w, status, err)
			return
		}
		conv = &c
	}
	orch := s.newOrchestrator(r, claims)
	var ran nlqRan
	if conv != nil && orch.NLQuery != nil {
		orch.NLQuery = s.aiNLQueryWith(r, claims, &conv.State, &ran)
	}
	ans, err := orch.Ask(r.Context(), s.aiPrincipal(claims), question, req.Context)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if conv != nil {
		s.recordAskTurn(r, claims, conv, question, &ans, &ran)
	}
	// AI audit (best-effort): who asked, intent, modules, provider — never the
	// question text or any retrieved data (no PII/secret in the audit line).
	logInfo("ai", "ask", map[string]any{
		"tenant": claims.Tenant, "sub": claims.Sub,
		"intent": ans.Intent, "mode": ans.Mode, "modules": ans.Modules,
		"provider": ans.Provider, "tier": ai.RouteFor(ans.Mode).Tier, // §10 model-router tier
	})
	writeJSON(w, http.StatusOK, ans)
}

// newOrchestrator builds the grounded engine for one request — shared by
// /api/ai/ask and the copilot provider-down fallback (the engine answers when
// no LLM can). All reads ride the caller's tenant-scoped aiDataSource.
func (s *server) newOrchestrator(r *http.Request, claims jwtClaims) *ai.Orchestrator {
	ds := aiDataSource{srv: s, ctx: r.Context(), scope: s.chTenantScope(r), claims: claims}
	tools := ai.Tools(ds)
	// IRIS Phase A: the read-only troubleshooting tools, wired to the seams this
	// deployment actually has. A nil seam means the tool is NOT registered, so
	// the assistant can never answer from a capability that is absent.
	deps := s.aiTroubleshootDeps(r, claims)
	tools.AddTroubleshootTools(ds, deps)
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

		Troubleshoot: deps,                  // tenant-scoped Phase-A reads
		ToolAudit:    s.aiToolAudit(claims), // one audit line per gather step (arg NAMES only)
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
	return s.aiNLQueryWith(r, claims, nil, nil)
}

// nlqRan records the query the data arm ran in this request, so a
// conversation turn can carry its state forward.
type nlqRan struct {
	q  *nlqast.AST
	rs *plan.ResultSet
}

// aiNLQueryWith is aiNLQuery inside a conversation: st (may be nil) is the
// server-held state follow-ups resolve against, and ran (may be nil) receives
// the query that answered.
func (s *server) aiNLQueryWith(r *http.Request, claims jwtClaims, st *irisconvo.State, ran *nlqRan) ai.NLQueryFunc {
	if s.nlqCatalog == nil || s.roles == nil || !s.roles.Allows(claims.Role, "infrastructure", LevelRead) {
		return nil
	}
	return func(ctx context.Context, _ ai.Principal, question string) (ai.DataAnswer, error) {
		cx := compile.Context{Loc: time.UTC, Now: time.Now()}
		if st != nil {
			cx.PriorAST = st.LastAST
			cx.Conv = &compile.Conversation{Entities: st.Entities, Actors: st.Actors, ChangeIDs: st.ChangeIDs}
		}
		c, err := s.nlqCompileQuestion(r.WithContext(ctx), claims, question, cx)
		if err != nil {
			return ai.DataAnswer{}, err
		}
		return s.nlqDataAnswer(r.WithContext(ctx), claims, c, ran)
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

// nlqDataAnswer turns one compiled question into the data arm's answer.
func (s *server) nlqDataAnswer(r *http.Request, claims jwtClaims, c nlqCompiled, ran *nlqRan) (ai.DataAnswer, error) {
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
	if errors.Is(err, plan.ErrNotFound) {
		return ai.DataAnswer{Status: ai.DataAnswered, Intent: c.res.Intent, Text: "Nothing by that name is visible to you."}, nil
	}
	if err != nil {
		return ai.DataAnswer{}, err
	}
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
	for _, k := range c.vr.Constraints {
		notes = append(notes, "Adjusted: "+k.Reason)
	}
	tenant, _ := principalTenant(claims)
	logInfo("iris.router", "data answer", map[string]any{"tenant": tenant, "sub": claims.Sub, "intent": c.res.Intent,
		"query_type": string(c.checked.Type), "rows": len(rs.Rows), "series": len(rs.Series)})
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
	if _, ok := userFrom(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
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
	if _, ok := userFrom(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
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
	if !ok {
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
// /api/ai/entities/resolve  POST {text, types[]} → the resolution ladder's answer
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
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		list := s.nlqAliases.List(tenant, cross)
		sort.Slice(list, func(i, j int) bool { return list[i].Key() < list[j].Key() })
		writeJSON(w, http.StatusOK, map[string]any{"aliases": list, "max": entityalias.MaxPerTenant})
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
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
		if !ok {
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
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, nlqBodyCap)
	var req struct {
		Text  string   `json:"text"`
		Types []string `json:"types"`
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
	res, err := s.nlqResolver(r, claims).Resolve(r.Context(), req.Text, req.Types)
	if err != nil {
		logError("iris.resolve", "entity resolution failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("entity resolution is unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// nlqResolver builds the resolution ladder over the caller's own aliases and
// visible inventory.
func (s *server) nlqResolver(r *http.Request, claims jwtClaims) resolve.Resolver {
	return resolve.Resolver{Cat: s.nlqCatalog, L: nlqLookups{s: s, h: s.nlqScopeFor(r, claims), claims: claims}}
}

// nlqLookups implements resolve.Lookups from the caller's own scope.
type nlqLookups struct {
	s      *server
	h      *nlqScope
	claims jwtClaims
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
	return out, nil
}

func (l nlqLookups) Visible(ctx context.Context, entityType, id string) (bool, error) {
	return l.h.Visible(ctx, nlqast.EntityRef{Type: entityType, ID: id})
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
	if !s.aiAssistantAllowed(claims) {
		writeError(w, http.StatusForbidden, errAITenantDisabled)
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
	c, err := s.nlqCompileQuestion(r, claims, req.Question, cx)
	if err != nil {
		logError("iris.nlquery", "compile failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the question could not be compiled"))
		return
	}
	tenant, _ := principalTenant(claims)
	logInfo("iris.nlquery", "compile", map[string]any{"tenant": tenant, "sub": claims.Sub, "intent": c.res.Intent,
		"unparsed": c.res.Unparsed, "declined": c.res.Decline != "", "question_chars": len(req.Question)})
	writeJSON(w, http.StatusOK, c.body())
}

// nlqCompiled is one question compiled and validated against the caller's scope.
type nlqCompiled struct {
	res     compile.Result
	checked *nlqast.AST      // the validated query; nil unless it is valid
	vr      *validate.Result // nil when nothing compiled
}

// nlqCompileQuestion runs the compiler and the validator for the caller.
func (s *server) nlqCompileQuestion(r *http.Request, claims jwtClaims, question string, cx compile.Context) (nlqCompiled, error) {
	res, err := compile.Compiler{Cat: s.nlqCatalog, R: s.nlqResolver(r, claims)}.Compile(r.Context(), question, cx)
	if err != nil {
		return nlqCompiled{}, err
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

// body is the compile answer: what was understood, and the query — the
// validated one, or the invalid one shown (never executed) so the operator
// sees what was understood.
func (c nlqCompiled) body() map[string]any {
	out := map[string]any{"intent": c.res.Intent, "entities": c.res.Entities, "clarify": c.res.Clarify,
		"decline": c.res.Decline, "unparsed": c.res.Unparsed, "not_understood": c.res.NotUnderstood}
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
	scope := s.nlqScopeFor(r, claims)
	checked, vr := validate.Validate(r.Context(), s.nlqCatalog, scope, q)
	if !vr.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"validation": vr})
		return
	}
	rs, err := s.nlqRun(r, claims, checked, vr)
	switch {
	case errors.Is(err, plan.ErrNotFound):
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	case err != nil:
		logError("iris.nlquery", "execute failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the query could not be run"))
		return
	}
	tenant, _ := principalTenant(claims)
	logInfo("iris.nlquery", "execute", map[string]any{"tenant": tenant, "sub": claims.Sub, "query_type": string(checked.Type),
		"ast_hash": rs.ASTHash, "catalog": rs.CatalogVersion, "rows": len(rs.Rows), "series": len(rs.Series),
		"truncated": rs.Truncated, "duration_ms": rs.Provenance.DurationMs})
	writeJSON(w, http.StatusOK, map[string]any{"result": rs, "validation": vr})
}

// ---- Iris NL: conversations (tracker 337 N-C7) --------------------------------
//
// POST /api/ai/conversations                 start one (owner + tenant scope from claims)
// GET  /api/ai/conversations/{id}            its turns — the owner's own only; otherwise 404
// POST /api/ai/conversations/{id}/messages   {question, tz?, incident_id?} → the compile
//      answer + the result, compiled against the SERVER-HELD state of earlier
//      turns ("that device", "what else did they change")
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
	if !irisconvo.ValidID(id) || (sub != "" && sub != "messages") {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if sub == "messages" {
		s.handleAIConversationMessage(w, r, id)
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
	if !ok {
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
	cx := compile.Context{Loc: loc, Now: time.Now(), IncidentID: incident, PriorAST: st.LastAST,
		Conv: &compile.Conversation{Entities: st.Entities, Actors: st.Actors, ChangeIDs: st.ChangeIDs}}
	c, err := s.nlqCompileQuestion(r, claims, req.Question, cx)
	if err != nil {
		logError("iris.nlquery", "compile failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the question could not be compiled"))
		return
	}
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
		rs, err := s.nlqRun(r, claims, c.checked, *c.vr)
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
			next = irisconvo.Next(s.nlqCatalog, st, c.checked, rs)
			out["result"] = rs
		}
	}
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
	logInfo("iris.convo", "turn", map[string]any{"tenant": tenant, "sub": claims.Sub, "intent": turn.Intent,
		"outcome": turn.Outcome, "turns": len(saved.Turns), "question_chars": len(req.Question)})
	writeJSON(w, status, out)
}
