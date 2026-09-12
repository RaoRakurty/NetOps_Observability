// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// copilot_config.go — the platform assistant's runtime configuration custody
// (extracted P2 RA.7). The provider/model/system are operator-configurable at
// runtime; the provider API KEY is a reversible secret held plaintext
// in-memory and SEALED at rest through the injected SecretSealer (platform
// DEK), never returned to clients. Env defaults (COPILOT_PROVIDER /
// COPILOT_MODEL) stay with the entrypoint and arrive as an injected defaults
// func, mirroring tenant_config.go's defaultModel seam.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// FieldCopilotKey is the Vault AAD field-id the platform assistant key is
// sealed under. PINNED: existing sealed blobs decrypt only under this label.
const FieldCopilotKey = "copilot.apikey" // #nosec G101 -- AAD field-id (a config key name), not a credential value

// CopilotConfig is the operator-tunable assistant settings. Key is a
// reversible secret (in-memory plaintext, sealed at rest); the rest are
// non-secret.
type CopilotConfig struct {
	Provider string `json:"provider"`      // "anthropic" | "openai" | "gemini"
	Model    string `json:"model"`         // e.g. claude-sonnet-4-6, claude-opus-4-8, gpt-4o
	System   string `json:"system"`        // optional system-prompt override ("" => default)
	Key      string `json:"key,omitempty"` // provider API key — sealed at rest, never sent to clients
}

// CopilotConfigStore holds the platform assistant config (one row, kv-backed).
type CopilotConfigStore struct {
	mu       sync.RWMutex
	cfg      CopilotConfig
	path     string
	sealer   SecretSealer
	defaults func() (provider, model string) // env resolution stays with the caller
}

// NewCopilotConfigStore opens the store; sealer nil = passthrough (dormant
// vault), defaults nil = empty defaults.
func NewCopilotConfigStore(path string, sealer SecretSealer, defaults func() (provider, model string)) *CopilotConfigStore {
	if defaults == nil {
		defaults = func() (string, string) { return "", "" }
	}
	s := &CopilotConfigStore{path: path, sealer: sealer, defaults: defaults}
	if err := s.load(); err != nil {
		applog.Error("copilot.config", "stored assistant config unreadable — the assistant falls back to env defaults", map[string]any{"error": err.Error()})
	}
	return s
}

func (s *CopilotConfigStore) seal(val string) (string, error) {
	if s.sealer == nil || val == "" {
		return val, nil
	}
	return s.sealer.Encrypt("", FieldCopilotKey, val)
}

func (s *CopilotConfigStore) open(val string) (string, error) {
	if s.sealer == nil || val == "" {
		return val, nil
	}
	return s.sealer.Decrypt("", FieldCopilotKey, val)
}

// load reads the stored assistant config. THREE states, never two: the store
// did not answer (error) / it answered with nothing (absent key or empty blob
// — env defaults apply) / loaded.
func (s *CopilotConfigStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = never configured; env defaults apply
	}
	if err != nil {
		return fmt.Errorf("read copilot config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = never configured
	}
	var c CopilotConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("decode copilot config: %w", err)
	}
	// Decrypt the key (no-op when the sealer is dormant / nil). A failed unseal
	// must NOT leave the sealed bytes in place as the API key: every provider
	// call would then fail authentication and read as "the provider rejected
	// us" rather than "we never opened the envelope".
	key, derr := s.open(c.Key)
	if derr != nil {
		c.Key = ""
		s.cfg = c
		return fmt.Errorf("unseal copilot API key: %w", derr)
	}
	c.Key = key
	s.cfg = c
	return nil
}

// Get returns the effective config: stored values where set, else the injected
// env-var defaults so behaviour matches the historical env-driven resolution
// when nothing has been saved yet.
func (s *CopilotConfigStore) Get() CopilotConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	defProvider, defModel := s.defaults()
	if c.Provider == "" {
		c.Provider = strings.ToLower(defProvider)
	}
	if c.Model == "" {
		c.Model = defModel
	}
	return c
}

// Set normalizes and persists the assistant config (key sealed at rest).
func (s *CopilotConfigStore) Set(c CopilotConfig) CopilotConfig {
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
	s.cfg = c                                        // in-memory stays plaintext
	if sealedKey, err := s.seal(c.Key); err == nil { // encrypt at rest
		sealed := c
		sealed.Key = sealedKey
		if b, err := json.MarshalIndent(sealed, "", "  "); err == nil {
			if serr := platformdb.Save(s.path, b); serr != nil {
				applog.Error("copilot.config", "assistant config not persisted — settings revert on restart", map[string]any{"error": serr.Error()})
			}
		}
	}
	s.mu.Unlock()
	return s.Get()
}

// APIKey returns the UI-configured provider key (decrypted), or "" if none was
// stored. Used to resolve the assistant key for the configured provider when no
// env key is set.
func (s *CopilotConfigStore) APIKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.cfg.Key)
}
