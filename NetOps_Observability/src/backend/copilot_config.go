package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
// The API KEY may be supplied two ways: out-of-band via the COPILOT_API_KEY /
// per-provider env vars (a secret never persisted by us), OR pasted in the
// assistant settings UI — in which case it is stored encrypted at rest (platform
// DEK, like every other config secret; see mapCopilot) and NEVER returned to the
// client. Either path lets the platform owner turn the assistant on without
// editing .env. get() returns the decrypted key for server-side use only; the
// HTTP handler builds its response field-by-field and omits it.

// copilotConfig is the operator-tunable assistant settings. Key is a reversible
// secret (in-memory plaintext, sealed at rest); the rest are non-secret.
type copilotConfig struct {
	Provider string `json:"provider"`      // "anthropic" | "openai" | "gemini"
	Model    string `json:"model"`         // e.g. claude-sonnet-4-6, claude-opus-4-8, gpt-4o
	System   string `json:"system"`        // optional system-prompt override ("" => default)
	Key      string `json:"key,omitempty"` // provider API key — sealed at rest, never sent to clients
}

type copilotConfigStore struct {
	mu    sync.RWMutex
	cfg   copilotConfig
	path  string
	vault *Vault
}

func newCopilotConfigStore(path string, v *Vault) *copilotConfigStore {
	s := &copilotConfigStore{path: path, vault: v}
	if err := s.load(); err != nil {
		logError("copilot.config", "stored assistant config unreadable — the assistant falls back to env defaults", errf(err))
	}
	return s
}

// load reads the stored assistant config. THREE states, never two (the
// cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob — env defaults apply) / loaded.
func (s *copilotConfigStore) load() error {
	b, err := kvLoad(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = never configured; env defaults apply
	}
	if err != nil {
		return fmt.Errorf("read copilot config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = never configured
	}
	var c copilotConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("decode copilot config: %w", err)
	}
	// Decrypt the key (no-op when the Vault is dormant / nil). A failed unseal
	// must NOT leave the sealed bytes in place as the API key: every provider
	// call would then fail authentication and read as "the provider rejected
	// us" rather than "we never opened the envelope".
	out, derr := mapCopilot(c, openFn(s.vault))
	if derr != nil {
		c.Key = ""
		s.cfg = c
		return fmt.Errorf("unseal copilot API key: %w", derr)
	}
	s.cfg = out
	return nil
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
	if c.Provider != "openai" && c.Provider != "gemini" {
		c.Provider = "anthropic" // default; supported: anthropic | openai | gemini
	}
	c.Model = strings.TrimSpace(c.Model)
	c.System = strings.TrimSpace(c.System)
	c.Key = strings.TrimSpace(c.Key)
	s.mu.Lock()
	// A blank key on save preserves the stored one — the GET form is redacted and
	// never round-trips the secret, so "save settings" mustn't wipe the key.
	// EXCEPT when the PROVIDER changes: an API key is provider-specific, and
	// silently re-using the old provider's key against the new provider produces
	// baffling 401s (live incident 2026-07-02: the Gemini key rode along to
	// OpenAI). Provider switch without a new key ⇒ key cleared, UI shows "not set".
	if c.Key == "" {
		if s.cfg.Provider == "" || c.Provider == s.cfg.Provider {
			c.Key = s.cfg.Key
		}
	}
	s.cfg = c                                                      // in-memory stays plaintext
	if sealed, err := mapCopilot(c, sealFn(s.vault)); err == nil { // encrypt at rest
		if b, err := json.MarshalIndent(sealed, "", "  "); err == nil {
			_ = kvSave(s.path, b)
		}
	}
	s.mu.Unlock()
	return s.get()
}

// apiKey returns the UI-configured provider key (decrypted), or "" if none was
// stored. Used to resolve the assistant key for the configured provider when no
// env key is set.
func (s *copilotConfigStore) apiKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.cfg.Key)
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
		c := s.copilotCfg.get()
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
		out := s.copilotCfg.set(c)
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
	return copilotAnyEnvKey() || s.copilotCfg.apiKey() != ""
}

// copilotKeySource tells the UI where the active key comes from: "env", "stored"
// (pasted in settings), or "none". env wins (it's resolved first per provider).
func (s *server) copilotKeySource() string {
	if copilotAnyEnvKey() {
		return "env"
	}
	if s.copilotCfg.apiKey() != "" {
		return "stored"
	}
	return "none"
}
