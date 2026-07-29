package main

import (
	"reflect"
	"strings"
	"testing"

	"netops/backend/ai"
)

func TestNormalizeProvider(t *testing.T) {
	cases := map[string]string{
		"chatgpt": "openai", "GPT": "openai", "openai": "openai",
		"gemini": "gemini", "Google": "gemini",
		"claude": "anthropic", "copilot": "anthropic", "anthropic": "anthropic",
		"": "", "bogus": "",
	}
	for in, want := range cases {
		if got := ai.NormalizeProvider(in); got != want {
			t.Errorf("ai.NormalizeProvider(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCopilotProviderChain(t *testing.T) {
	t.Run("default order", func(t *testing.T) {
		t.Setenv("COPILOT_PROVIDER_CHAIN", "")
		t.Setenv("COPILOT_PROVIDER", "")
		if got := copilotProviderChain(); !reflect.DeepEqual(got, []string{"openai", "gemini", "anthropic"}) {
			t.Errorf("default chain = %v", got)
		}
	})
	t.Run("legacy COPILOT_PROVIDER promoted to front", func(t *testing.T) {
		t.Setenv("COPILOT_PROVIDER_CHAIN", "")
		t.Setenv("COPILOT_PROVIDER", "anthropic")
		if got := copilotProviderChain(); !reflect.DeepEqual(got, []string{"anthropic", "openai", "gemini"}) {
			t.Errorf("promoted chain = %v", got)
		}
	})
	t.Run("explicit chain with aliases + dedup", func(t *testing.T) {
		t.Setenv("COPILOT_PROVIDER_CHAIN", "chatgpt, copilot, gpt, gemini")
		if got := copilotProviderChain(); !reflect.DeepEqual(got, []string{"openai", "anthropic", "gemini"}) {
			t.Errorf("explicit chain = %v", got)
		}
	})
}

func TestProviderKeyResolution(t *testing.T) {
	// Per-provider keys win.
	t.Setenv("OPENAI_API_KEY", "sk-openai")
	t.Setenv("GEMINI_API_KEY", "g-key")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("COPILOT_API_KEY", "legacy")
	t.Setenv("COPILOT_PROVIDER", "anthropic")
	if k := providerKey("openai"); k != "sk-openai" {
		t.Errorf("openai key = %q", k)
	}
	if k := providerKey("gemini"); k != "g-key" {
		t.Errorf("gemini key = %q", k)
	}
	// anthropic has no own key but is the configured COPILOT_PROVIDER → legacy key.
	if k := providerKey("anthropic"); k != "legacy" {
		t.Errorf("anthropic should fall back to COPILOT_API_KEY, got %q", k)
	}
}

func TestProviderModelDefaults(t *testing.T) {
	t.Setenv("OPENAI_MODEL", "")
	t.Setenv("GEMINI_MODEL", "")
	t.Setenv("ANTHROPIC_MODEL", "")
	t.Setenv("COPILOT_MODEL", "")
	t.Setenv("COPILOT_PROVIDER", "")
	if m := providerModel("openai"); m != "gpt-4o-mini" {
		t.Errorf("openai default model = %q", m)
	}
	if m := providerModel("gemini"); m != "gemini-flash-latest" {
		t.Errorf("gemini default model = %q", m)
	}
	t.Setenv("GEMINI_MODEL", "gemini-2.0-pro")
	if m := providerModel("gemini"); m != "gemini-2.0-pro" {
		t.Errorf("gemini override model = %q", m)
	}
}

// The embedded knowledge must be compiled in and injected into the system prompt.
func TestKnowledgeEmbeddedInSystemPrompt(t *testing.T) {
	if len(appKnowledge) < 500 {
		t.Fatalf("appKnowledge looks unembedded (len=%d)", len(appKnowledge))
	}
	s := &server{}
	sp := s.copilotSystemPrompt()
	if !strings.Contains(sp, "NetOps Observability") || !strings.Contains(sp, "Source of Truth") {
		t.Error("system prompt should contain the embedded application knowledge")
	}
}
