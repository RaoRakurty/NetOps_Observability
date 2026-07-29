package main

import (
	"context"
	"errors"

	"netops/backend/ai"
)

// ai_llm.go — adapts the existing provider-agnostic proxy (copilot.go's chain:
// bounds, key custody, redaction, audit all live there) to the ai.LLMClient
// seam. The ai package never holds a key or makes a raw HTTP call; it asks this
// adapter to complete with a SERVER-OWNED system prompt (LLM01). The provider
// chain resolves PER PRINCIPAL (ai_tenant_config.go): a tenant's BYO key wins,
// a strict tenant never rides the platform key.
type aiLLM struct {
	srv    *server
	claims jwtClaims
}

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
	for _, cand := range l.srv.providerCandidates(l.claims) {
		text, err := ai.CallProvider(ctx, cand.name, cand.key, cand.model, system, cmsgs)
		if err == nil {
			return text, cand.name, nil
		}
		// Raw provider error stays server-side (SR-022); fall through to the next.
	}
	return "", "", errors.New("no AI provider configured")
}
