package main

import (
	"context"
	"errors"

	"netops/backend/ai"
)

// ai_llm.go — adapts the existing provider-agnostic proxy (copilot.go's chain:
// bounds, key custody, redaction, audit all live there) to the ai.LLMClient
// seam. The ai package never holds a key or makes a raw HTTP call; it asks this
// adapter to complete with a SERVER-OWNED system prompt (LLM01).
type aiLLM struct{ srv *server }

func (l aiLLM) Complete(ctx context.Context, system string, msgs []ai.LLMMessage) (string, string, error) {
	cmsgs := make([]copilotMessage, 0, len(msgs))
	for _, m := range msgs {
		// Only user/assistant turns cross the boundary; the system prompt is the
		// orchestrator's server-owned string passed separately (never client-set).
		role := m.Role
		if role != "assistant" {
			role = "user"
		}
		cmsgs = append(cmsgs, copilotMessage{Role: role, Content: m.Content})
	}
	storedKey := l.srv.copilotCfg.apiKey()
	cfgProvider := l.srv.copilotCfg.get().Provider
	cfgModel := l.srv.copilotCfg.get().Model
	for _, name := range copilotProviderChain() {
		key := providerKey(name)
		if key == "" && storedKey != "" && name == cfgProvider {
			key = storedKey
		}
		if key == "" {
			continue // provider not configured — skip
		}
		model := providerModel(name)
		if name == cfgProvider && cfgModel != "" {
			model = cfgModel
		}
		text, err := callProvider(ctx, name, key, model, system, cmsgs)
		if err == nil {
			return text, name, nil
		}
		// Raw provider error stays server-side (SR-022); fall through to the next.
	}
	return "", "", errors.New("no AI provider configured")
}
