package main

// copilot_config.go — main-side wiring for the assistant's runtime config
// custody (ai.CopilotConfigStore, extracted P2 RA.7). This file keeps the env
// resolution (COPILOT_PROVIDER/COPILOT_MODEL defaults, the out-of-band env-key
// vars) and the platform-admin handler; the store, the seal/unseal discipline
// (failed-unseal blanks, blank-key-preserves, provider-switch-clears) live in
// the package behind the SecretSealer seam.

import (
	"encoding/json"
	"net/http"
	"os"
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
	return ai.NewCopilotConfigStore(path, sealer, func() (string, string) {
		return envOr("COPILOT_PROVIDER", "anthropic"), envOr("COPILOT_MODEL", "claude-sonnet-4-6")
	})
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
		c := s.copilotCfg.Get()
		writeJSON(w, http.StatusOK, map[string]any{
			"provider":        c.Provider,
			"model":           c.Model,
			"system":          c.System,
			"feature_enabled": aiEnabled(),
			"key_present":     s.copilotKeyPresent(),
			"key_source":      s.copilotKeySource(),
			"providers":       []string{"anthropic", "openai", "gemini"},
			// Suggested models per provider for the UI dropdown (free-text also allowed).
			"model_suggestions": map[string][]string{
				"anthropic": {"claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"},
				"openai":    {"gpt-4o", "gpt-4o-mini", "gpt-4.1"},
				"gemini":    {"gemini-2.5-flash", "gemini-2.5-pro", "gemini-flash-latest"},
			},
		})
	case http.MethodPut:
		var c copilotConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out := s.copilotCfg.Set(c)
		writeJSON(w, http.StatusOK, map[string]any{
			"provider":        out.Provider,
			"model":           out.Model,
			"system":          out.System,
			"feature_enabled": aiEnabled(),
			"key_present":     s.copilotKeyPresent(),
			"key_source":      s.copilotKeySource(),
		})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
