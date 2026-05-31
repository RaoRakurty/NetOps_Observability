package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
)

// copilot_config.go — runtime configuration for the AI assistant ("Copilot").
//
// The assistant is Claude by default (Anthropic Messages API; see copilot.go),
// but the provider and model are now operator-configurable at runtime via the
// admin UI instead of being env-only — so you can switch Claude models, or to
// OpenAI, without editing .env and restarting. Persisted via the kv store (file
// or postgres) under one key, mirroring tenantStore/snmpCredStore.
//
// The API KEY is deliberately NOT part of this stored config and is never
// returned to the client: it stays in the COPILOT_API_KEY environment variable
// (a secret), so "wire everything but the key" works — provider/model are set,
// the feature flag can be on, and the assistant stays dormant until the key is
// supplied out-of-band.

// copilotConfig is the operator-tunable assistant settings (no secrets).
type copilotConfig struct {
	Provider string `json:"provider"` // "anthropic" | "openai"
	Model    string `json:"model"`    // e.g. claude-sonnet-4-6, claude-opus-4-8, gpt-4o
	System   string `json:"system"`   // optional system-prompt override ("" => default)
}

type copilotConfigStore struct {
	mu   sync.RWMutex
	cfg  copilotConfig
	path string
}

func newCopilotConfigStore(path string) *copilotConfigStore {
	s := &copilotConfigStore{path: path}
	s.load()
	return s
}

func (s *copilotConfigStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var c copilotConfig
	if json.Unmarshal(b, &c) == nil {
		s.cfg = c
	}
}

// get returns the effective config: stored values where set, else the env-var
// defaults (COPILOT_PROVIDER/COPILOT_MODEL) so behaviour matches copilot.go's
// historical env-driven resolution when nothing has been saved yet.
func (s *copilotConfigStore) get() copilotConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	if c.Provider == "" {
		c.Provider = strings.ToLower(envOr("COPILOT_PROVIDER", "anthropic"))
	}
	if c.Model == "" {
		c.Model = envOr("COPILOT_MODEL", "claude-sonnet-4-6")
	}
	return c
}

func (s *copilotConfigStore) set(c copilotConfig) copilotConfig {
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	if c.Provider != "openai" {
		c.Provider = "anthropic" // default + only other supported value
	}
	c.Model = strings.TrimSpace(c.Model)
	c.System = strings.TrimSpace(c.System)
	s.mu.Lock()
	s.cfg = c
	b, err := json.MarshalIndent(c, "", "  ")
	if err == nil {
		_ = kvSave(s.path, b)
	}
	s.mu.Unlock()
	return s.get()
}

// handleCopilotConfig: GET/PUT /api/copilot/config (admin-gated).
//
// GET returns the effective provider/model/system plus runtime status flags
// (whether the feature is enabled and whether a key is present) WITHOUT ever
// exposing the key itself, so the UI can show "configured, waiting for key".
func (s *server) handleCopilotConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		c := s.copilotCfg.get()
		writeJSON(w, http.StatusOK, map[string]any{
			"provider":      c.Provider,
			"model":         c.Model,
			"system":        c.System,
			"feature_enabled": os.Getenv("FEATURE_COPILOT") == "true",
			"key_present":   os.Getenv("COPILOT_API_KEY") != "",
			"providers":     []string{"anthropic", "openai"},
			// Suggested models per provider for the UI dropdown (free-text also allowed).
			"model_suggestions": map[string][]string{
				"anthropic": {"claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"},
				"openai":    {"gpt-4o", "gpt-4o-mini", "gpt-4.1"},
			},
		})
	case http.MethodPut:
		var c copilotConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out := s.copilotCfg.set(c)
		writeJSON(w, http.StatusOK, map[string]any{
			"provider":        out.Provider,
			"model":           out.Model,
			"system":          out.System,
			"feature_enabled": os.Getenv("FEATURE_COPILOT") == "true",
			"key_present":     os.Getenv("COPILOT_API_KEY") != "",
		})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
