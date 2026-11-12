// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// provider_probe.go — "Test connection" for a model provider (tracker 337 plan
// C3) and the recommended models per provider (C2).
//
// The probe makes ONE tiny completion through the same transport every answer
// uses (CallProviderUsage: bounded body, redaction backstop, retry policy,
// key in a header) under a hard ProbeTimeout. What comes back to the client is
// a closed verdict — ok, latency, the model asked for and an error CLASS — never
// the provider's text or error message (SR-022), and never the key: the probe
// neither stores nor logs it.

import (
	"context"
	"strings"
	"sync"
	"time"
)

// ProbeTimeout bounds one connection test end to end.
const ProbeTimeout = 10 * time.Second

// probeSystem / probeUser are the constant probe prompt (LLM01: server-owned;
// nothing from the request reaches the prompt).
const (
	probeSystem = "You are a connectivity check. Reply with the single word OK."
	probeUser   = "Connection test. Reply OK."
)

// ProbeResult is the client-visible verdict of a connection test.
type ProbeResult struct {
	OK         bool   `json:"ok"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	LatencyMS  int64  `json:"latency_ms"`
	ErrorClass string `json:"error_class,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	TestedAt   string `json:"tested_at"`
}

// ProbeProvider runs one connection test. The returned Completion carries the
// provider's usage so the caller can charge it; its text is never shown.
func ProbeProvider(ctx context.Context, provider, key, model string) (ProbeResult, Completion) {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	start := time.Now()
	c, err := CallProviderUsage(ctx, provider, key, model, probeSystem, []ChatMessage{{Role: "user", Content: probeUser}})
	res := ProbeResult{
		OK: err == nil, Provider: provider, Model: model,
		LatencyMS: time.Since(start).Milliseconds(),
		TestedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err != nil {
		res.ErrorClass = ClassifyProviderError(err)
		res.HTTPStatus = ProviderStatusOf(err)
		return res, Completion{Usage: c.Usage}
	}
	return res, c
}

// RecommendedSet is one provider's recommended models: the single default and
// the fast/strong tier choices the setup step fills in for the operator.
type RecommendedSet struct {
	Default string `json:"default"`
	Fast    string `json:"fast"`
	Strong  string `json:"strong"`
}

// RecommendedModels is the per-provider recommendation the settings UI
// auto-fills (C2). Chosen for the transport as it is: no provider-specific
// thinking parameter is sent and output is capped at MaxOutputTokens, so each
// pick answers a short request without spending that cap on hidden reasoning
// (Gemini's flash-lite and Anthropic's 4.x models do not think unless asked).
// Defaults match the code-side provider defaults (providerModel in the root),
// so "recommended" and "what runs when nothing is set" are the same model. A
// blank tier field resolves to its recommended model (TierModels.ForProvider).
//
// Gemini (2026-11-12): the default and strong pick moved from the moving alias
// gemini-flash-latest — which timed out on a 10 s probe in the lab that day
// while the dated gemini-2.5-flash answered in 0.59 s and the fast pick
// gemini-flash-lite-latest in 0.67 s — to gemini-2.5-flash. A dated id can be
// retired (gemini-1.5-flash now 404s), and that is the trade: an alias can
// change under a deployment without notice, a dated id fails loudly as "model
// not found" in the settings Test (which now probes every tier model) and is
// replaced deliberately. Review this pick when Google announces 2.5 retirement.
func RecommendedModels() map[string]RecommendedSet {
	return map[string]RecommendedSet{
		"gemini":    {Default: "gemini-2.5-flash", Fast: "gemini-flash-lite-latest", Strong: "gemini-2.5-flash"},
		"openai":    {Default: "gpt-4o-mini", Fast: "gpt-4o-mini", Strong: "gpt-4.1"},
		"anthropic": {Default: "claude-sonnet-4-6", Fast: "claude-haiku-4-5", Strong: "claude-opus-4-8"},
	}
}

// FallbackModel is the ONE other model of the same provider a call falls back
// to when model fails: the provider's recommended default model, or — when
// model already is that — its recommended fast model; "" when there is none
// (unknown provider, or model is both). Same provider, same key: a fallback
// never changes whose account pays or where the prompt goes, only which of
// that provider's models answers, and it is never dearer than the
// recommended default (owner rule: the recommended picks are the cheap,
// short-answer models; the fallback must not escalate cost).
//
// Why (2026-11-12, lab): Google answered 503 "high demand" for the alias
// gemini-flash-latest, and gemini-flash-lite-latest stopped answering inside
// 10 s, while the dated gemini-2.5-flash answered the same key in 0.5–0.9 s.
// With only a Gemini key there was no other provider to fall through to, so
// Iris lost the model although a working one was one name away.
func FallbackModel(provider, model string) string {
	rec, ok := RecommendedModels()[NormalizeProvider(provider)]
	if !ok {
		return ""
	}
	model = strings.TrimSpace(model)
	if rec.Default != "" && rec.Default != model {
		return rec.Default
	}
	if rec.Fast != "" && rec.Fast != model {
		return rec.Fast
	}
	return ""
}

// ModelSuggestions is the per-provider dropdown list (free text stays allowed):
// the recommended models first, then other common choices.
func ModelSuggestions() map[string][]string {
	return map[string][]string{
		"anthropic": {"claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-8", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5"},
		"openai":    {"gpt-4o-mini", "gpt-4.1", "gpt-4o"},
		"gemini":    {"gemini-2.5-flash", "gemini-flash-lite-latest", "gemini-flash-latest", "gemini-2.5-pro"},
	}
}

// TierProbe is one tier model's connection-test verdict: the settings page
// shows each tier's model with its latency, and warns before saving a model
// that failed.
type TierProbe struct {
	Tier       string `json:"tier"` // "default" | "fast" | "strong"
	Model      string `json:"model"`
	OK         bool   `json:"ok"`
	LatencyMS  int64  `json:"latency_ms"`
	ErrorClass string `json:"error_class,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

// TierProbeModels is the model each tier resolves to for a test (ForProvider:
// a blank tier is its recommended model), in the order default, fast, strong.
func TierProbeModels(provider string, models TierModels) [][2]string {
	return [][2]string{
		{"default", models.ForProvider(TierDeterministic, provider)},
		{"fast", models.ForProvider(TierFast, provider)},
		{"strong", models.ForProvider(TierStrong, provider)},
	}
}

// ProbeTiers tests every distinct tier model once, concurrently (so the
// whole test stays within one ProbeTimeout), and reports a verdict per tier.
// probe makes one test call; the caller charges and audits it.
func ProbeTiers(provider string, models TierModels, probe func(model string) ProbeResult) []TierProbe {
	tiers := TierProbeModels(provider, models)
	results := map[string]ProbeResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, tm := range tiers {
		m := tm[1]
		mu.Lock()
		_, seen := results[m]
		if !seen {
			results[m] = ProbeResult{}
		}
		mu.Unlock()
		if seen || m == "" {
			continue
		}
		wg.Add(1)
		go func(model string) {
			defer wg.Done()
			r := probe(model)
			mu.Lock()
			results[model] = r
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	out := make([]TierProbe, 0, len(tiers))
	for _, tm := range tiers {
		r := results[tm[1]]
		out = append(out, TierProbe{Tier: tm[0], Model: tm[1], OK: r.OK, LatencyMS: r.LatencyMS, ErrorClass: r.ErrorClass, HTTPStatus: r.HTTPStatus})
	}
	return out
}

// ProbeModel picks the model a connection test asks for: the operator's draft
// when given, else the configured fast-tier model when the configuration is for
// this provider, else the provider's recommended fast model.
func ProbeModel(provider, draft string, configured TierModels, configuredFor string) string {
	if m := strings.TrimSpace(draft); m != "" {
		return m
	}
	if provider == configuredFor {
		if m := strings.TrimSpace(configured.ForProvider(TierFast, provider)); m != "" {
			return m
		}
	}
	return RecommendedModels()[provider].Fast
}
