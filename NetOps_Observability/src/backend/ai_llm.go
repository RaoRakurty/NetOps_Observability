// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
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

// Complete is the tier-less completion: the pre-router behaviour, and what any
// caller that has not routed a tier gets.
func (l aiLLM) Complete(ctx context.Context, system string, msgs []ai.LLMMessage) (string, string, error) {
	return l.CompleteTier(ctx, "", system, msgs)
}

// CompleteTier satisfies ai.TieredLLMClient: the orchestrator hands over the
// tier the §10 router chose for this answer, and the per-principal provider
// chain resolves that tier to a model name. The tier NEVER changes which
// provider or which key is used — only which of that configuration's model
// names is called — so the BYO-key rules (a tenant's own key wins; a strict
// tenant rides nothing) are structurally untouched by it.
func (l aiLLM) CompleteTier(ctx context.Context, tier ai.ModelTier, system string, msgs []ai.LLMMessage) (string, string, error) {
	text, provider, _, err := l.CompleteTierWithUsage(ctx, tier, system, msgs)
	return text, provider, err
}

// CompleteTierWithUsage satisfies ai.LLMUsageClient: the same chain, plus the
// provider's OWN token accounting for the call that answered (tracker 337
// N-A4). Every completion — not only the agent loop's — is charged against the
// tenant's daily budget (LLM04): the provider-reported total when there is
// one, else the coarse chars/4 estimate the budget has always used.
func (l aiLLM) CompleteTierWithUsage(ctx context.Context, tier ai.ModelTier, system string, msgs []ai.LLMMessage) (string, string, ai.TokenUsage, error) {
	cmsgs := make([]copilotMessage, 0, len(msgs))
	chars := len(system)
	for _, m := range msgs {
		// Only user/assistant turns cross the boundary; the system prompt is the
		// orchestrator's server-owned string passed separately (never client-set).
		role := m.Role
		if role != "assistant" {
			role = "user"
		}
		cmsgs = append(cmsgs, copilotMessage{Role: role, Content: m.Content})
		chars += len(m.Content)
	}
	// LLM04: a tenant that has spent its daily budget gets no further provider
	// call. The error makes every call site take its existing deterministic,
	// evidence-only path — the product keeps answering, key-free.
	tenant, _ := principalTenant(l.claims)
	if l.srv.aiToolBudget != nil && !l.srv.aiToolBudget.Allow(tenant, l.srv.dailyTokensFor(tenant)) {
		return "", "", ai.TokenUsage{}, errAIBudgetExhausted
	}
	for _, cand := range l.srv.providerCandidatesForTier(l.claims, tier) {
		c, err := ai.CallProviderUsage(ctx, cand.name, cand.key, cand.model, system, cmsgs)
		if err == nil {
			l.charge(c, chars)
			// The decision ledger names the model that answered (N-A6); a
			// no-op outside a ledgered request.
			aidecision.FromContext(ctx).NoteModel(aidecision.ModelUse{Provider: cand.name, Name: cand.model, Tier: string(tier)})
			return c.Text, cand.name, c.Usage, nil
		}
		// Raw provider error stays server-side (SR-022); fall through to the next.
	}
	return "", "", ai.TokenUsage{}, errors.New("no AI provider configured")
}

// errAIBudgetExhausted is the refusal once a tenant's daily token budget is spent.
var errAIBudgetExhausted = errors.New("daily AI token budget exhausted for this workspace")

// charge meters one successful completion against the caller's tenant budget.
func (l aiLLM) charge(c ai.Completion, promptChars int) {
	if l.srv == nil || l.srv.aiToolBudget == nil {
		return
	}
	tenant, _ := principalTenant(l.claims)
	tokens := int(c.Usage.InputTokens + c.Usage.OutputTokens)
	if !c.Usage.Reported {
		tokens = (promptChars + len(c.Text)) / 4
	}
	l.srv.aiToolBudget.Charge(tenant, tokens)
}
