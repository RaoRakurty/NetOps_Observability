// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"strings"
)

// router.go — the Model Router (HLD §10). Two halves, both here on purpose:
//
//	POLICY     — RouteFor classifies each answer by the model tier it needs,
//	             whether the unsupported-claim verifier applies, and (implicitly)
//	             the safe evidence-only fallback. Many Correlix answers are
//	             DETERMINISTIC (navigation, KB, shift/time-range/incident-list)
//	             and never call a model; the ones that do (RCA, current-state,
//	             module health) are grounded + verified.
//	MECHANISM  — TierModels resolves a tier to the model name actually called,
//	             and the orchestrator asks for a completion BY TIER through
//	             TieredLLMClient. Before this, every tier resolved through the
//	             single provider chain, so a /status headline and a multi-round
//	             RCA narrative hit the same model at the same price.
//
// The router stays provider-neutral: it names tiers, never providers or keys.
// Key custody, the per-principal provider chain and the BYO-key rules stay in
// the server (ai_tenant_config.go), which is also where a tier becomes a model.

// ModelTier is the class of model an answer needs.
type ModelTier string

const (
	TierDeterministic ModelTier = "deterministic" // no model call — built from tools/KB/registry
	TierFast          ModelTier = "fast"          // a short grounded headline
	TierStrong        ModelTier = "strong"        // multi-fact reasoning narrative
)

// ModelRoute is the routing decision for one answer mode.
type ModelRoute struct {
	Tier   ModelTier `json:"tier"`
	UseLLM bool      `json:"use_llm"` // false → fully deterministic (no provider call)
	Verify bool      `json:"verify"`  // run the unsupported-claim verifier on model output
}

// RouteFor maps an answer mode to its model route. Kept in one place so the
// tier policy is inspectable and testable, and matches the orchestrator's actual
// behavior (deterministic modes skip the provider entirely).
func RouteFor(mode AnswerMode) ModelRoute {
	switch mode {
	case ModeProblemExplanation, ModeTroubleshootFinding:
		// A skill answer reasons over several tool results at once and MUST be
		// verified — it is the most fabrication-prone surface we have.
		return ModelRoute{Tier: TierStrong, UseLLM: true, Verify: true}
	case ModeCurrentStateSummary, ModeModuleHealthSummary:
		return ModelRoute{Tier: TierFast, UseLLM: true, Verify: true}
	default:
		// Navigation, KB (investigation_plan), shift-handoff, time-range,
		// incident-list, unavailable — all built deterministically from
		// tools/registry/KB, no provider call.
		return ModelRoute{Tier: TierDeterministic, UseLLM: false, Verify: false}
	}
}

// ── the MECHANISM half: which model a tier resolves to ──────────────────────

// TierModels is one provider configuration's model selection: a single default
// plus OPTIONAL per-tier overrides.
//
// BACK-COMPATIBILITY IS THE DEFAULT, not a special case: an unset override falls
// back to Default, so a deployment that only ever configured one model calls
// exactly the model it called before, for every tier, at the same price. A tier
// only diverges once an operator (or a tenant, with their own key) deliberately
// names a model for it.
type TierModels struct {
	Default string // the single model — every tier with no override resolves here
	Fast    string // optional: the cheap/fast model (grounded headlines, routing)
	Strong  string // optional: the reasoning model (multi-fact RCA narratives)
}

// For returns the model name to call for a tier.
//
// TierDeterministic never reaches a provider (RouteFor says UseLLM=false); it
// resolves to Default anyway so a caller that asks cannot end up holding an
// empty model string. The zero tier "" means "no tier was routed" — the
// free-form assistant proxy, which is not an answer mode — and resolves the
// same way, which is what keeps that surface byte-for-byte unchanged.
func (t TierModels) For(tier ModelTier) string {
	switch tier {
	case TierFast:
		if m := strings.TrimSpace(t.Fast); m != "" {
			return m
		}
	case TierStrong:
		if m := strings.TrimSpace(t.Strong); m != "" {
			return m
		}
	case TierDeterministic:
		// Falls through to Default — see the doc comment.
	}
	return t.Default
}

// ErrNoProvider is the honest "nothing to call" answer: the orchestrator was
// built without an LLM seam. Every model call site already degrades to its
// deterministic, evidence-only answer on an error, so this reaches the operator
// as the evidence-only card rather than as a panic.
var ErrNoProvider = errors.New("no AI provider is configured")

// completeTier is the ONE place the orchestrator talks to a provider. It carries
// the ROUTER'S tier to the client, so the mechanism cannot drift from the policy:
// a call site names its answer mode's tier and nothing else decides the model.
//
// A client that does not implement TieredLLMClient is called exactly as before —
// that assertion, not a config flag, is what makes this change invisible to an
// existing deployment.
func (o *Orchestrator) completeTier(ctx context.Context, tier ModelTier, system string, msgs []LLMMessage) (string, string, error) {
	if o == nil || o.LLM == nil {
		return "", "", ErrNoProvider
	}
	if tc, ok := o.LLM.(TieredLLMClient); ok {
		return tc.CompleteTier(ctx, tier, system, msgs)
	}
	return o.LLM.Complete(ctx, system, msgs)
}
