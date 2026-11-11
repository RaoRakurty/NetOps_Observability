// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/aiprovider"
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
	cands := l.srv.providerCandidatesForTier(l.claims, tier)
	if len(cands) == 0 {
		return "", "", ai.TokenUsage{}, errNoAIProvider
	}
	var lastErr error
	skipped := 0
	ctx = l.srv.egressCtx(ctx, l.claims)
	for _, cand := range cands {
		c, err := l.srv.callProviderGuarded(ctx, tenant, tier, cand, system, cmsgs)
		if err == nil {
			l.charge(c, chars)
			// The decision ledger names the model that answered (N-A6); a
			// no-op outside a ledgered request. The answer's own note feeds
			// the per-answer footnote (C6).
			aidecision.FromContext(ctx).NoteModel(aidecision.ModelUse{Provider: cand.name, Name: cand.model, Tier: string(tier)})
			ai.NoteModelUsed(ctx, cand.name, cand.model)
			return c.Text, cand.name, c.Usage, nil
		}
		if errors.Is(err, ai.ErrProviderBreakerOpen) {
			skipped++
		}
		lastErr = err
		// Raw provider error stays server-side (SR-022); fall through to the next.
	}
	if skipped == len(cands) {
		return "", "", ai.TokenUsage{}, ai.ErrProviderBreakerOpen
	}
	// Wrapped, not replaced: the caller's honest footer ("timed out", "paused")
	// is decided from the class of the last failure.
	return "", "", ai.TokenUsage{}, fmt.Errorf("no AI provider answered: %w", lastErr)
}

// egressCtx attaches the CALLER's community mask to a provider call's context
// (ai.WithEgressScrub): its own tenant's values plus the platform's, every
// tenant's only for a cross-tenant caller (internal/credscrub). It replaces the
// process default (the union, kept for callers with no request) because the
// model's answer comes back to this caller: an answer that echoed "***" where
// the caller's own log held another tenant's community would tell the caller
// the string is one. Every request path that reaches ai.ProviderDo goes through
// here: aiLLM (the grounded engine, Iris NL), the copilot's plain chat and its
// agent loop.
func (s *server) egressCtx(ctx context.Context, claims jwtClaims) context.Context {
	if s == nil || s.credScrub == nil {
		return ctx
	}
	cs := s.credScrub
	tenant, cross := principalTenant(claims)
	return ai.WithEgressScrub(ctx, func(body []byte) []byte { return cs.For(tenant, cross).MaskJSON(body) })
}

// errAIBudgetExhausted is the refusal once a tenant's daily token budget is spent.
var errAIBudgetExhausted = ai.ErrBudgetExhausted

// errNoAIProvider: no provider this caller may use is configured.
var errNoAIProvider = fmt.Errorf("no AI provider configured: %w", ai.ErrNoProvider)

// callProviderGuarded is ONE provider attempt behind the guards every model
// call shares (Iris latency batch 2026-11-10, CLAUDE.md §9/§10):
//   - the (tenant, provider) circuit breaker — an open breaker skips the call
//     (ErrProviderBreakerOpen) instead of paying another full timeout;
//   - one structured log line for EVERY failure (provider, model, tier, http
//     status, provider reason, error class, latency — never the key, the
//     prompt or the provider's message text);
//   - netops_ai_provider_call_seconds{provider,tier,outcome}.
//
// A call the caller abandoned (context canceled) or that never left (budget)
// is not the provider's failure and does not move the breaker.
func (s *server) callProviderGuarded(ctx context.Context, tenant string, tier ai.ModelTier, cand providerCandidate, system string, msgs []copilotMessage) (ai.Completion, error) {
	tierLabel := string(tier)
	if !s.aiBreaker.Allow(tenant, cand.name) {
		s.aiProvCalls.ObserveCall(cand.name, tierLabel, ai.ProvBreakerOpen, 0)
		return ai.Completion{}, ai.ErrProviderBreakerOpen
	}
	start := time.Now()
	c, err := ai.CallProviderUsage(ctx, cand.name, cand.key, cand.model, system, msgs)
	took := time.Since(start)
	outcome := ai.ClassifyProviderError(err)
	// A deadline that expired because the CALLER'S context ended (client gone)
	// is a cancellation, not a provider timeout.
	if outcome == ai.ProvTimeout && errors.Is(ctx.Err(), context.Canceled) {
		outcome = ai.ProvCanceled
	}
	s.aiProvCalls.ObserveCall(cand.name, tierLabel, outcome, took.Seconds())
	switch {
	case err == nil:
		s.aiBreaker.Record(tenant, cand.name, false)
	case ai.CountsAgainstProvider(outcome):
		s.aiBreaker.Record(tenant, cand.name, true)
	default:
		s.aiBreaker.Release(tenant, cand.name)
	}
	if err != nil {
		fields := map[string]any{
			"tenant": tenant, "provider": cand.name, "model": cand.model, "tier": tierLabel,
			"key_source": cand.source, "error_class": outcome, "latency_ms": took.Milliseconds(),
			"breaker": s.aiBreaker.State(tenant, cand.name).String(),
		}
		if st := ai.ProviderStatusOf(err); st != 0 {
			fields["http_status"] = st
		}
		var se *ai.ProviderStatusError
		if errors.As(err, &se) && se.Reason != "" {
			fields["provider_reason"] = se.Reason
		}
		var ee *ai.ProviderEmptyError
		if errors.As(err, &ee) {
			fields["finish_reason"], fields["block_reason"], fields["thought_tokens"] = ee.FinishReason, ee.BlockReason, ee.ThoughtTok
		}
		logWarn("ai.provider", "model provider call failed", fields)
	}
	return c, err
}

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

// aiModelBudgets is the per-stage model budget (never block a ready answer on a
// model): AI_MODEL_BUDGET_FAST / AI_MODEL_BUDGET_STRONG as Go durations
// ("8s", "15s"); unset or invalid → the ai package defaults. Clamped by
// ai.StageBudgets.For to the transport ceiling.
func aiModelBudgets() ai.StageBudgets {
	return ai.StageBudgets{
		Fast:   envDuration("AI_MODEL_BUDGET_FAST", ai.DefaultFastBudget),
		Strong: envDuration("AI_MODEL_BUDGET_STRONG", ai.DefaultStrongBudget),
	}
}

// aiBreakerConfig: AI_PROVIDER_BREAKER_FAILURES consecutive failures open a
// (tenant, provider) breaker for AI_PROVIDER_BREAKER_COOLDOWN (a Go duration).
func aiBreakerConfig() aiprovider.Config {
	return aiprovider.Config{
		Threshold: envInt("AI_PROVIDER_BREAKER_FAILURES", aiprovider.DefaultThreshold),
		Cooldown:  envDuration("AI_PROVIDER_BREAKER_COOLDOWN", aiprovider.DefaultCooldown),
	}
}

// usableProviderCandidates is the caller's provider chain minus the providers
// whose (tenant, provider) breaker would refuse a call right now. It PEEKS —
// it never claims a half-open probe — so a "should we try at all" check cannot
// starve the call that follows it.
func (s *server) usableProviderCandidates(claims jwtClaims, tier ai.ModelTier) []providerCandidate {
	tenant, _ := principalTenant(claims)
	var out []providerCandidate
	for _, c := range s.providerCandidatesForTier(claims, tier) {
		if s.aiBreaker.Peek(tenant, c.name) {
			out = append(out, c)
		}
	}
	return out
}
