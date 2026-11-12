// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// thinking.go — how much hidden reasoning a provider call asks for, and which
// stage of Iris made the call (Iris latency, owner report 2026-11-11: "Iris
// takes a long time even with Gemini connected").
//
// The recommended Gemini models are THINKING models: unless told otherwise
// they reason before they answer, the reasoning is billed as output, it counts
// against maxOutputTokens, and it adds seconds to every call. The FAST tier
// (a headline, a route tie-break, a chain classification, the NL rephrase) is
// a short, bounded job, so a fast-tier call asks the provider for the least
// thinking the model offers:
//
//   - Gemini 2.5 Flash: generationConfig.thinkingConfig.thinkingBudget = 0
//     (thinking off; Gemini API "thinking" guide, 2.5 series);
//   - later Gemini models and the "-latest" aliases (which Google hot-swaps to
//     new releases): thinkingConfig.thinkingLevel = "low" — the one level every
//     model in Google's current thinking table supports (gemini-2.5-* through
//     gemini-4-*; "minimal" is not offered by all of them);
//
// Doc basis (2026-11-11): Google's current thinking page documents the level
// table and the snake_case Interactions-API field (generation_config.
// thinking_level), and states that thinking counts against the output cap and
// is billed as output. The generateContent spelling used here
// (generationConfig.thinkingConfig.{thinkingBudget,thinkingLevel}) is the
// ThinkingConfig of the v1beta generateContent API as previously documented;
// it could not be re-read offline. TODO(337, verify-live): one fast-tier call
// with the lab key — expect thoughtsTokenCount 0 (2.5 Flash) or small, and no
// "thinking setting refused" retry in the api log. Whatever the answer, the
// retry below keeps a wrong guess from breaking a call.
//   - "-lite" models: nothing is sent — their default is already off (2.5) or
//     minimal (3.x), and "low" would RAISE it;
//   - 1.x / 2.0 models and anything not named gemini-*: nothing is sent.
//
// Model names behind an alias change without notice, so the request is
// self-healing: when Gemini refuses a call that carried a thinking setting
// with 400 INVALID_ARGUMENT, the call is repeated once without it, and — only
// when that retry succeeds, proving the setting was the cause — the model is
// remembered so later calls skip the setting. The worst case is one extra
// fast 400 per model per process.
//
// Anthropic: extended thinking is opt-in (a "thinking" request object) and
// Correlix never sends one, so no Claude call thinks. OpenAI: the recommended
// models (gpt-4o-mini, gpt-4.1) are not reasoning models; reasoning_effort is
// a reasoning-model parameter and is not sent. TODO(337, verify-live): if an
// operator configures an OpenAI reasoning model (o-series / gpt-5) as the fast
// tier, a reasoning_effort setting would belong here — not built, because the
// OpenAI reference could not be read to confirm the accepted values per model.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
)

type fastThinkingKey struct{}

// WithTierThinking marks ctx so the provider call made under it asks for the
// least thinking the model offers — for the fast tier only. Any other tier
// returns ctx unchanged (the provider's default stands).
func WithTierThinking(ctx context.Context, tier ModelTier) context.Context {
	if tier != TierFast {
		return ctx
	}
	return context.WithValue(ctx, fastThinkingKey{}, true)
}

func fastThinking(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(fastThinkingKey{}).(bool)
	return v
}

// Stages of Iris that call a model (a closed set: a metric label).
const (
	StageAnswer  = "answer"      // the grounded answer path (the default)
	StageRewrite = "nlq_rewrite" // the NL rephrase stage (hybrid NLU plan B1)
	StageCompile = "nlq_compile" // the NL structured-output fallback (B3)
)

type stageKey struct{}

// WithStage names the Iris stage making the calls under ctx. An unknown
// stage is ignored.
func WithStage(ctx context.Context, stage string) context.Context {
	switch stage {
	case StageAnswer, StageRewrite, StageCompile:
		return context.WithValue(ctx, stageKey{}, stage)
	}
	return ctx
}

// StageOf is the stage ctx carries; StageAnswer when none.
func StageOf(ctx context.Context) string {
	if ctx != nil {
		if s, _ := ctx.Value(stageKey{}).(string); s != "" {
			return s
		}
	}
	return StageAnswer
}

// geminiModelKey folds a configured Gemini model name to the bare id.
func geminiModelKey(model string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(model), "models/"))
}

// geminiFastThinking is the thinkingConfig a fast-tier call on model sends,
// or nil (see the file comment for the per-family choice).
func geminiFastThinking(model string) map[string]any {
	m := geminiModelKey(model)
	switch {
	case !strings.HasPrefix(m, "gemini-"):
		return nil
	case strings.Contains(m, "lite"):
		return nil
	case strings.HasPrefix(m, "gemini-1.") || strings.HasPrefix(m, "gemini-2.0"):
		return nil
	case strings.HasPrefix(m, "gemini-2.5-flash"):
		return map[string]any{"thinkingBudget": 0}
	case strings.HasPrefix(m, "gemini-2.5-pro"):
		// 2.5 Pro cannot turn thinking off (its budget has a floor), so the
		// provider default stands.
		return nil
	}
	return map[string]any{"thinkingLevel": "low"}
}

// maxThinkingRejects bounds the remembered models (configured names are few;
// this is a backstop against an unbounded map).
const maxThinkingRejects = 64

// thinkingRejects remembers the Gemini models that refused a thinking setting.
type thinkingRejects struct {
	mu sync.Mutex
	m  map[string]bool
}

func (t *thinkingRejects) has(model string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[geminiModelKey(model)]
}

func (t *thinkingRejects) add(model string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) < maxThinkingRejects {
		t.m[geminiModelKey(model)] = true
	}
}

// geminiThinkingRejected is process state by design (like the provider HTTP
// client): it is a cache of what the provider told us, never a decision input
// beyond "skip the setting that was refused".
var geminiThinkingRejected = &thinkingRejects{m: map[string]bool{}}

// geminiThinkingFor is the thinkingConfig for this call: the fast-tier choice,
// unless the model is known to refuse it.
func geminiThinkingFor(ctx context.Context, model string) map[string]any {
	if !fastThinking(ctx) || geminiThinkingRejected.has(model) {
		return nil
	}
	return geminiFastThinking(model)
}

// refusedArgument reports a Gemini 400 that a thinking setting could have
// caused. ANY 400 qualifies (review fix 2026-11-11): providerErrorReason
// prefers the specific google.rpc.ErrorInfo reason over the generic
// INVALID_ARGUMENT status, so a refused field may surface under a reason we
// do not know. The one exception is a key problem — no request field can
// cause or cure it, and retrying would only send a bad key twice.
func refusedArgument(err error) bool {
	var se *ProviderStatusError
	if !errors.As(err, &se) || se.Status != http.StatusBadRequest {
		return false
	}
	return !strings.Contains(se.Reason, "API_KEY") && se.Reason != "PERMISSION_DENIED" && se.Reason != "UNAUTHENTICATED"
}
