// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// copilot_config.go — main-side wiring for the assistant's runtime config
// custody (ai.CopilotConfigStore, extracted P2 RA.7). This file keeps the env
// resolution (COPILOT_PROVIDER/COPILOT_MODEL defaults, the out-of-band env-key
// vars) and the platform-admin handler; the store, the seal/unseal discipline
// (failed-unseal blanks, blank-key-preserves, provider-switch-clears) live in
// the package behind the SecretSealer seam.

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"

	"netops/backend/ai"
	"netops/backend/internal/vault"
)

type (
	copilotConfig      = ai.CopilotConfig
	copilotConfigStore = ai.CopilotConfigStore
)

func newCopilotConfigStore(path string, v *vault.Vault) *copilotConfigStore {
	var sealer ai.SecretSealer
	if v != nil {
		sealer = v
	}
	return ai.NewCopilotConfigStore(path, sealer, copilotEnvDefaults)
}

// copilotEnvDefaults is the provider/model the platform config falls back to
// when nothing is stored. The model is EMPTY unless COPILOT_MODEL is set (plan
// C1): an empty model makes the provider chain use that provider's own
// default (providerModel), where the old hard-coded "claude-sonnet-4-6" was
// handed to whichever provider was configured — a Claude model id asked of
// Gemini. The default provider is gemini (owner D6, matching the installer).
func copilotEnvDefaults() (provider, model string) {
	return envOr("COPILOT_PROVIDER", "gemini"), strings.TrimSpace(os.Getenv("COPILOT_MODEL"))
}

// handleCopilotConfig: GET/PUT /api/copilot/config (admin-gated).
//
// GET returns the effective provider/model/system plus runtime status flags
// (whether the feature is enabled and whether a key is present) WITHOUT ever
// exposing the key itself, so the UI can show "configured, waiting for key".
func (s *server) handleCopilotConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.copilotConfigView())
	case http.MethodPut:
		var req struct {
			copilotConfig
			// System is the retired persona override (N-F1). An older client
			// that round-trips it empty is fine; a non-empty one is refused, so
			// the text is not silently dropped.
			System string `json:"system"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if strings.TrimSpace(req.System) != "" {
			writeError(w, http.StatusBadRequest, errors.New("the assistant persona override was retired — write what Iris should know as Network context facts (Administration → Network context)"))
			return
		}
		s.copilotCfg.Set(req.copilotConfig)
		writeJSON(w, http.StatusOK, s.copilotConfigView())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// copilotConfigView is the platform-admin view of the assistant config, shared
// by GET and PUT. Never the key: key_present / key_source say whether one
// exists and where it comes from.
func (s *server) copilotConfigView() map[string]any {
	c := s.copilotCfg.Get()
	return map[string]any{
		"provider": c.Provider,
		"model":    c.Model,
		// §10 model router. Blank means "this tier uses model"; the UI must
		// show the blank, not the resolved value, or an operator cannot tell
		// a deliberate tier split from the single-model default.
		"model_fast":      c.ModelFast,
		"model_strong":    c.ModelStrong,
		"feature_enabled": aiEnabled(),
		"key_present":     s.copilotKeyPresent(),
		"key_source":      s.copilotKeySource(),
		"providers":       []string{"gemini", "anthropic", "openai"},
		// Suggested models per provider for the UI dropdown (free-text also allowed).
		"model_suggestions": ai.ModelSuggestions(),
		// C2: what the setup step fills in when a provider is picked.
		"recommended": ai.RecommendedModels(),
		// C3/C6: the latest connection test (in memory; nil until one runs).
		"last_test": s.copilotCfg.LastTest(),
		// D4: today's AI budget, so the admin banner can say when it is spent.
		"budget": s.aiBudgetView(""),
	}
}

// aiBudgetView is the daily-budget status for the admin banner (D4). For a
// workspace ("tenant" non-empty) it is that workspace's own spend; for the
// platform view ("") it is the platform default plus how many workspaces have
// spent theirs today — counts only, never another workspace's identity.
func (s *server) aiBudgetView(tenant string) map[string]any {
	out := map[string]any{"daily_tokens_default": aiToolsDailyTokens()}
	if s.aiToolBudget == nil {
		return out
	}
	used := s.aiToolBudget.UsedByTenant()
	if tenant != "" {
		limit := s.dailyTokensFor(tenant)
		out["daily_tokens"] = limit
		out["used_today"] = used[tenant]
		out["exhausted"] = limit > 0 && used[tenant] >= limit
		return out
	}
	spent := 0
	for t, n := range used {
		if limit := s.dailyTokensFor(t); limit > 0 && n >= limit {
			spent++
		}
	}
	out["workspaces_exhausted"] = spent
	return out
}

// copilotTestBody bounds a connection-test request body.
const copilotTestBody = 8 << 10

// handleCopilotConfigTest: POST /api/copilot/config/test (platform admin, C3).
// Body {provider, key?, model?}. A blank key tests the key the platform would
// use for that provider (env, else the stored one). The key is used for this
// one call only: never persisted, never logged, never echoed.
func (s *server) handleCopilotConfigTest(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := decodeProviderTest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cfg := s.copilotCfg.Get()
	name := req.provider
	if name == "" {
		name = ai.NormalizeProvider(cfg.Provider)
	}
	key := req.key
	if key == "" {
		key = providerKey(name)
		if key == "" && name == cfg.Provider {
			key = s.copilotCfg.APIKey()
		}
	}
	if key == "" {
		writeError(w, http.StatusBadRequest, errors.New("no API key to test — paste one first"))
		return
	}
	model := ai.ProbeModel(name, req.model, cfg.Models(), cfg.Provider)
	res := s.runProviderProbe(r, claims, name, key, model)
	s.copilotCfg.SetLastTest(res)
	writeJSON(w, http.StatusOK, res)
}

// providerTestRequest is a decoded, normalized connection-test body.
type providerTestRequest struct{ provider, key, model string }

// decodeProviderTest bounds and validates a connection-test body.
func decodeProviderTest(w http.ResponseWriter, r *http.Request) (providerTestRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, copilotTestBody)
	var raw struct {
		Provider string `json:"provider"`
		Key      string `json:"key"`
		Model    string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return providerTestRequest{}, errors.New("invalid request body")
	}
	out := providerTestRequest{key: strings.TrimSpace(raw.Key), model: strings.TrimSpace(raw.Model)}
	if p := strings.TrimSpace(raw.Provider); p != "" {
		if out.provider = ai.NormalizeProvider(p); out.provider == "" {
			return providerTestRequest{}, errors.New("unknown provider — use gemini, anthropic or openai")
		}
	}
	if out.model != "" && !probeModelName.MatchString(out.model) {
		return providerTestRequest{}, errors.New("invalid model name")
	}
	return out, nil
}

// probeModelName is the shape of a model id a connection test accepts.
var probeModelName = regexp.MustCompile(`^(models/)?[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

// runProviderProbe makes the one test call, charges its tokens to the caller's
// workspace budget (LLM04: a test is still a provider call), and audits the
// verdict — provider, model, outcome; never the key.
func (s *server) runProviderProbe(r *http.Request, claims jwtClaims, name, key, model string) ai.ProbeResult {
	tenant, _ := principalTenant(claims)
	res, c := ai.ProbeProvider(r.Context(), name, key, model)
	if s.aiToolBudget != nil && c.Usage.Reported {
		s.aiToolBudget.Charge(tenant, int(c.Usage.InputTokens+c.Usage.OutputTokens))
	}
	outcome := res.ErrorClass
	if res.OK {
		outcome = ai.ProvOK
	}
	s.aiProvCalls.ObserveCall(name, "test", outcome, float64(res.LatencyMS)/1000)
	fields := map[string]any{"tenant": tenant, "provider": name, "model": model, "ok": res.OK,
		"error_class": res.ErrorClass, "latency_ms": res.LatencyMS}
	if res.HTTPStatus != 0 {
		fields["http_status"] = res.HTTPStatus
	}
	if res.OK {
		logInfo("ai.provider", "model provider connection test passed", fields)
	} else {
		logWarn("ai.provider", "model provider connection test failed", fields)
	}
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Method: r.Method, Path: r.URL.Path,
		Status: http.StatusOK, Decision: "allow", Remote: auditClientIP(r),
		Detail: map[string]any{"action": "ai_provider_test", "provider": name, "model": model,
			"ok": res.OK, "error_class": res.ErrorClass},
	})
	return res
}

// copilotEnvKeyVars are the env vars that can carry a provider key out-of-band.
var copilotEnvKeyVars = []string{"COPILOT_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY"}

func copilotAnyEnvKey() bool {
	for _, k := range copilotEnvKeyVars {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return true
		}
	}
	return false
}

// copilotKeyPresent reports whether the assistant has any usable provider key —
// from the environment OR the UI-stored (encrypted) key.
func (s *server) copilotKeyPresent() bool {
	return copilotAnyEnvKey() || s.copilotCfg.APIKey() != ""
}

// copilotKeySource tells the UI where the active key comes from: "env", "stored"
// (pasted in settings), or "none". env wins (it's resolved first per provider).
func (s *server) copilotKeySource() string {
	if copilotAnyEnvKey() {
		return "env"
	}
	if s.copilotCfg.APIKey() != "" {
		return "stored"
	}
	return "none"
}
