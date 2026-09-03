package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/platformdb"
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

// aiProductKB is the Correlix PRODUCT knowledge (concepts + how-tos), parsed once
// from the same embedded doc that grounds the free-form copilot — so the grounded,
// key-free assistant answers "what is a seam / how do I set up SNMP" accurately.
var aiProductKB = ai.LoadProductKB(appKnowledge)

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

	ans, err := s.newOrchestrator(r, claims).Ask(r.Context(), s.aiPrincipal(claims), question, req.Context)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
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
	ds := aiDataSource{srv: s, ctx: r.Context(), scope: chTenantScope(r), claims: claims}
	tools := ai.Tools(ds)
	// IRIS Phase A: the read-only troubleshooting tools, wired to the seams this
	// deployment actually has. A nil seam means the tool is NOT registered, so
	// the assistant can never answer from a capability that is absent.
	deps := s.aiTroubleshootDeps(r, claims)
	tools.AddTroubleshootTools(ds, deps)
	return &ai.Orchestrator{
		DS:        ds,
		Tools:     tools,
		LLM:       aiLLM{srv: s, claims: claims},
		Flags:     envFlagLookup,
		Policy:    ai.NewPolicyEngine(ai.PolicyConfig{}, envFlagLookup), // safe default: read-only
		Redactor:  ai.Redact,                                            // outbound DLP: secrets + direct identifiers (LLM06)
		KB:        aiKB,                                                 // Network Expert KB (supporting knowledge)
		ProductKB: aiProductKB,                                          // Correlix product knowledge (concepts + how-tos)
		Docs:      aiDocsIndex,                                          // docs-portal retriever (real page citations)
		Skills:    aiSkills,                                             // troubleshooting methods (nil = layer disabled)

		Troubleshoot: deps,                  // tenant-scoped Phase-A reads
		ToolAudit:    s.aiToolAudit(claims), // one audit line per gather step (arg NAMES only)
		// IRIS Phase B: where a CONCLUDED investigation goes. It is held (in
		// memory, per principal) until an operator judges it on /api/ai/feedback;
		// only then is a tenant-scoped memory row written.
		RecordInvestigation: s.aiRecordInvestigation(claims),
	}
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
