package main

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
)

// ai_handlers.go — the Correlix AI HTTP surface. POST /api/ai/ask runs the
// orchestrator (classify → route → Policy Engine → tenant-scoped evidence →
// grounded answer). Read-only (v1); FEATURE_AI gates it (off by default).

// aiEnabled gates the Correlix AI endpoints. FEATURE_AI is the flag; the legacy
// FEATURE_COPILOT is honored for back-compat with existing deployments.
func aiEnabled() bool {
	return os.Getenv("FEATURE_AI") == "true" || os.Getenv("FEATURE_COPILOT") == "true"
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
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Correlix AI is disabled — set FEATURE_AI=true"))
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	// Per-principal rate limit — each ask may be a paid provider call (SR-021).
	if !s.copilotLimiter.allowN(claims.Tenant+"|"+claims.Sub, envInt("COPILOT_RATE_PER_MIN", 20)) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("Correlix AI rate limit exceeded — slow down"))
		return
	}
	// Bound the request before decoding (LLM10: no unbounded input).
	r.Body = http.MaxBytesReader(w, r.Body, maxCopilotBodyBytes)
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

	ds := aiDataSource{srv: s, ctx: r.Context(), scope: chTenantScope(r)}
	orch := &ai.Orchestrator{
		DS:        ds,
		Tools:     ai.Tools(ds),
		LLM:       aiLLM{srv: s},
		Flags:     envFlagLookup,
		Policy:    ai.NewPolicyEngine(ai.PolicyConfig{}, envFlagLookup), // safe default: read-only
		KB:        aiKB,                                                 // Network Expert KB (supporting knowledge)
		ProductKB: aiProductKB,                                          // Correlix product knowledge (concepts + how-tos)
	}
	ans, err := orch.Ask(r.Context(), s.aiPrincipal(claims), question, req.Context)
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
// UI can show what Correlix AI can answer. Read-only, any authenticated user.
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
		row := aiFeedbackRow{
			TenantID: tenant, ID: randID(), ConversationID: req.ConversationID,
			Sub: claims.Sub, Intent: req.Intent, Rating: rating, At: time.Now().UTC(),
		}
		if err := s.aiFeedback.Put(r.Context(), row); err != nil {
			log.Printf("ai feedback persist: %v", err) // best-effort; still audit below
		}
	}
	logInfo("ai", "feedback", map[string]any{
		"tenant": claims.Tenant, "sub": claims.Sub,
		"conversation_id": req.ConversationID, "intent": req.Intent, "rating": rating,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleAIFeedbackStats: GET /api/ai/feedback — the tenant-scoped feedback
// aggregate (up/down totals + per-intent breakdown) for the quality loop.
func (s *server) handleAIFeedbackStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "administration", LevelRead)
	if !ok {
		return
	}
	if s.aiFeedback == nil {
		writeJSON(w, http.StatusOK, aiFeedbackStats{ByIntent: map[string]*upDownCounts{}})
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
