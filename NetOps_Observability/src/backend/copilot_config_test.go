package main

import (
	"encoding/json"
	"netops/backend/internal/platformdb"
	"path/filepath"
	"strings"
	"testing"
)

// copilotTempStore returns a copilotConfigStore backed by a fresh temp kv path.
// The global `backend` defaults to platformdb.FileKV{}, whose Load/Save operate on the raw
// path, so a tempdir file works as the kv key without any backend swap.
func copilotTempStore(t *testing.T) *copilotConfigStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "copilot_config.json")
	return newCopilotConfigStore(path, nil)
}

// Defaults come from env (COPILOT_PROVIDER/COPILOT_MODEL) when nothing is stored.
func TestCopilotConfigEnvFallbackDefaults(t *testing.T) {
	t.Setenv("COPILOT_PROVIDER", "")
	t.Setenv("COPILOT_MODEL", "")
	s := copilotTempStore(t)
	got := s.get()
	if got.Provider != "anthropic" {
		t.Fatalf("default provider = %q, want anthropic", got.Provider)
	}
	if got.Model != "claude-sonnet-4-6" {
		t.Fatalf("default model = %q, want claude-sonnet-4-6", got.Model)
	}

	t.Setenv("COPILOT_PROVIDER", "OpenAI")
	t.Setenv("COPILOT_MODEL", "gpt-4o")
	got = s.get()
	if got.Provider != "openai" { // env provider is lower-cased on read
		t.Fatalf("env provider = %q, want openai", got.Provider)
	}
	if got.Model != "gpt-4o" {
		t.Fatalf("env model = %q, want gpt-4o", got.Model)
	}
}

// set() normalizes the provider: only the supported set (openai/gemini/
// anthropic) survives; junk and casing variants collapse to the default
// "anthropic".
func TestCopilotConfigProviderNormalization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"openai", "openai"},
		{"OpenAI", "openai"},
		{"  OPENAI  ", "openai"},
		{"anthropic", "anthropic"},
		{"Anthropic", "anthropic"},
		{"", "anthropic"},
		{"gemini", "gemini"},
		{"Gemini", "gemini"},
		{"grok", "anthropic"},
		{"  ", "anthropic"},
	}
	for _, c := range cases {
		s := copilotTempStore(t)
		out := s.set(copilotConfig{Provider: c.in, Model: "m"})
		if out.Provider != c.want {
			t.Errorf("set(provider=%q).Provider = %q, want %q", c.in, out.Provider, c.want)
		}
	}
}

// set() trims model/system and persists; get() returns stored values, and a
// fresh store loading the same path reproduces them.
func TestCopilotConfigSetGetPersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copilot_config.json")
	s := newCopilotConfigStore(path, nil)

	out := s.set(copilotConfig{Provider: "openai", Model: "  gpt-4o  ", System: "  be terse  "})
	if out.Model != "gpt-4o" {
		t.Fatalf("model not trimmed: %q", out.Model)
	}
	if out.System != "be terse" {
		t.Fatalf("system not trimmed: %q", out.System)
	}

	got := s.get()
	if got != out {
		t.Fatalf("get() = %+v, want %+v", got, out)
	}

	reloaded := newCopilotConfigStore(path, nil)
	if r := reloaded.get(); r != out {
		t.Fatalf("reloaded get() = %+v, want %+v", r, out)
	}
}

// The API key must NEVER be part of the persisted config. Even if the caller
// stuffs a key-like value somewhere, the stored JSON only has provider/model/
// system and no secret-bearing fields.
func TestCopilotConfigNeverPersistsAPIKey(t *testing.T) {
	t.Setenv("COPILOT_API_KEY", "sk-super-secret-should-not-be-stored")
	path := filepath.Join(t.TempDir(), "copilot_config.json")
	s := newCopilotConfigStore(path, nil)
	s.set(copilotConfig{Provider: "anthropic", Model: "claude-opus-4-8", System: "hi"})

	raw, err := platformdb.Load(path)
	if err != nil {
		t.Fatalf("kvLoad: %v", err)
	}
	if strings.Contains(string(raw), "sk-super-secret-should-not-be-stored") {
		t.Fatalf("API key leaked into stored config: %s", raw)
	}
	// Confirm the persisted shape carries only the three non-secret keys.
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("stored config not valid JSON: %v", err)
	}
	for k := range m {
		switch k {
		case "provider", "model", "system":
		default:
			t.Errorf("unexpected key %q in stored config — possible secret leak", k)
		}
	}
}

// A UI-supplied key is stored and returned by apiKey(); saving again with a
// blank key preserves it (the redacted form never round-trips the secret).
func TestCopilotConfigKeyStoreAndPreserve(t *testing.T) {
	s := copilotTempStore(t)
	if s.apiKey() != "" {
		t.Fatalf("fresh store apiKey = %q, want empty", s.apiKey())
	}
	s.set(copilotConfig{Provider: "anthropic", Model: "claude-opus-4-8", Key: "sk-ui-key"})
	if got := s.apiKey(); got != "sk-ui-key" {
		t.Fatalf("apiKey after set = %q, want sk-ui-key", got)
	}
	// Save settings again WITHOUT a key (blank) — must keep the stored key.
	s.set(copilotConfig{Provider: "anthropic", Model: "claude-sonnet-4-6"})
	if got := s.apiKey(); got != "sk-ui-key" {
		t.Fatalf("apiKey after blank re-save = %q, want preserved sk-ui-key", got)
	}
}

// A store pointed at a non-existent / empty path loads cleanly (no panic) and
// falls through to env defaults.
func TestCopilotConfigLoadMissingFileIsClean(t *testing.T) {
	t.Setenv("COPILOT_PROVIDER", "")
	t.Setenv("COPILOT_MODEL", "")
	s := newCopilotConfigStore(filepath.Join(t.TempDir(), "does-not-exist.json"), nil)
	got := s.get()
	if got.Provider != "anthropic" || got.Model != "claude-sonnet-4-6" {
		t.Fatalf("missing-file load did not fall back to defaults: %+v", got)
	}
}
