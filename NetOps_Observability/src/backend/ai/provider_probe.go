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
// so "recommended" and "what runs when nothing is set" are the same model.
func RecommendedModels() map[string]RecommendedSet {
	return map[string]RecommendedSet{
		"gemini":    {Default: "gemini-flash-latest", Fast: "gemini-flash-lite-latest", Strong: "gemini-flash-latest"},
		"openai":    {Default: "gpt-4o-mini", Fast: "gpt-4o-mini", Strong: "gpt-4.1"},
		"anthropic": {Default: "claude-sonnet-4-6", Fast: "claude-haiku-4-5", Strong: "claude-opus-4-8"},
	}
}

// ModelSuggestions is the per-provider dropdown list (free text stays allowed):
// the recommended models first, then other common choices.
func ModelSuggestions() map[string][]string {
	return map[string][]string{
		"anthropic": {"claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-8", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5"},
		"openai":    {"gpt-4o-mini", "gpt-4.1", "gpt-4o"},
		"gemini":    {"gemini-flash-latest", "gemini-flash-lite-latest", "gemini-2.5-flash", "gemini-2.5-pro"},
	}
}

// ProbeModel picks the model a connection test asks for: the operator's draft
// when given, else the configured fast-tier model when the configuration is for
// this provider, else the provider's recommended fast model.
func ProbeModel(provider, draft string, configured TierModels, configuredFor string) string {
	if m := strings.TrimSpace(draft); m != "" {
		return m
	}
	if provider == configuredFor {
		if m := strings.TrimSpace(configured.For(TierFast)); m != "" {
			return m
		}
	}
	return RecommendedModels()[provider].Fast
}
