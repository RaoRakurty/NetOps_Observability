package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

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

	ds := aiDataSource{srv: s, ctx: r.Context(), scope: chTenantScope(r)}
	orch := &ai.Orchestrator{
		DS:     ds,
		Tools:  ai.Tools(ds),
		LLM:    aiLLM{srv: s},
		Flags:  envFlagLookup,
		Policy: ai.NewPolicyEngine(ai.PolicyConfig{}, envFlagLookup), // safe default: read-only
	}
	ans, err := orch.Ask(r.Context(), s.aiPrincipal(claims), req.Question, req.Context)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// AI audit (best-effort): who asked, intent, modules, provider — never the
	// question text or any retrieved data (no PII/secret in the audit line).
	logInfo("ai", "ask", map[string]any{
		"tenant": claims.Tenant, "sub": claims.Sub,
		"intent": ans.Intent, "mode": ans.Mode, "modules": ans.Modules, "provider": ans.Provider,
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
