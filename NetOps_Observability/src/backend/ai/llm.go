// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import "context"

// LLMMessage is one turn handed to the provider. Role is "user" or "assistant"
// (the system prompt is passed separately and is always server-owned — LLM01).
type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// LLMClient is the egress seam. The server wires this to the existing
// provider-agnostic proxy (copilot.go's provider chain — bounds, key custody,
// redaction, audit all live there); tests pass a MockLLM. The ai package never
// holds a provider key or makes a raw HTTP call itself.
type LLMClient interface {
	// Complete returns the model's text, the provider that answered, or an error.
	Complete(ctx context.Context, system string, msgs []LLMMessage) (text string, provider string, err error)
}

// MockLLM is a deterministic LLMClient for tests + offline/dev (HLD P0 mock
// provider). It returns a fixed reply (or echoes the last user message) so the
// orchestrator and tools can be tested without a real provider.
type MockLLM struct {
	Reply string // fixed reply; if empty, echoes the last user message
	Err   error  // set to simulate a provider failure
}

func (m MockLLM) Complete(_ context.Context, _ string, msgs []LLMMessage) (string, string, error) {
	if m.Err != nil {
		return "", "mock", m.Err
	}
	if m.Reply != "" {
		return m.Reply, "mock", nil
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return "MOCK: " + msgs[i].Content, "mock", nil
		}
	}
	return "MOCK: (no input)", "mock", nil
}
