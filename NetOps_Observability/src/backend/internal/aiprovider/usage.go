// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiprovider

// usage.go — what one ANSWERED provider call cost and took (Iris latency, owner
// report 2026-11-11: "Iris takes a long time even with Gemini connected").
// Failures were already logged with their latency (callProviderGuarded); a
// slow SUCCESS left no trace beyond a histogram bucket, so nobody could say
// which model, which tier, which Iris stage, or how much hidden reasoning
// ("thinking") the provider spent on it. Every answered call now leaves:
//
//   - one structured log line: tenant, provider, model, tier, stage, key
//     source, latency, input / output / thinking tokens and whether the
//     provider reported usage at all — never the key, the prompt or the reply;
//   - netops_ai_provider_tokens_total{provider,tier,stage,kind}, kind ∈
//     input | output | thinking (thinking is the reasoning SHARE of output).
//
// Stage and tier are closed sets in the caller; the model name is free text
// an admin typed, so it is a log field, never a metric label.

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
)

// Call is one answered provider call.
type Call struct {
	Tenant, Provider, Model, Tier, Stage, KeySource string
	Latency                                         time.Duration
	InputTokens, OutputTokens, ThinkingTokens       int64
	// UsageReported is false when the provider sent no usage block: the
	// token fields are then unknown (zero), not measured.
	UsageReported bool
}

// maxTokenSeries bounds the {provider,tier,stage,kind} label space (a
// backstop; every label is a closed set in the caller).
const maxTokenSeries = 512

type tokenKey struct{ provider, tier, stage, kind string }

// tokenCounters is netops_ai_provider_tokens_total.
type tokenCounters struct {
	mu      sync.Mutex
	n       map[tokenKey]int64
	dropped int64
}

func (t *tokenCounters) add(k tokenKey, v int64) {
	if v <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.n[k]; !ok && len(t.n) >= maxTokenSeries {
		t.dropped++
		return
	}
	t.n[k] += v
}

// RecordSuccess records one answered call: the log line and, when the
// provider reported usage, the token counters. Nil-safe.
func (m *Metrics) RecordSuccess(c Call) {
	if m == nil {
		return
	}
	tier, stage := c.Tier, c.Stage
	if tier == "" {
		tier = "default"
	}
	if stage == "" {
		stage = "answer"
	}
	applog.Info("ai.provider", "model provider call answered", map[string]any{
		"tenant": c.Tenant, "provider": c.Provider, "model": c.Model, "tier": tier, "stage": stage,
		"key_source": c.KeySource, "latency_ms": c.Latency.Milliseconds(),
		"usage_reported": c.UsageReported, "input_tokens": c.InputTokens,
		"output_tokens": c.OutputTokens, "thinking_tokens": c.ThinkingTokens,
	})
	if !c.UsageReported || m.tokens == nil {
		return
	}
	m.tokens.add(tokenKey{c.Provider, tier, stage, "input"}, c.InputTokens)
	m.tokens.add(tokenKey{c.Provider, tier, stage, "output"}, c.OutputTokens)
	m.tokens.add(tokenKey{c.Provider, tier, stage, "thinking"}, c.ThinkingTokens)
}

// writeTokens renders netops_ai_provider_tokens_total.
func (m *Metrics) writeTokens(w io.Writer) error {
	var b strings.Builder
	b.WriteString("# HELP netops_ai_provider_tokens_total Provider-reported tokens of answered model calls, by provider, model tier, Iris stage and kind (input, output, thinking — thinking is the hidden-reasoning share of output).\n")
	b.WriteString("# TYPE netops_ai_provider_tokens_total counter\n")
	var dropped int64
	if t := m.tokens; t != nil {
		t.mu.Lock()
		keys := make([]tokenKey, 0, len(t.n))
		for k := range t.n {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, c := keys[i], keys[j]
			return a.provider+"\x00"+a.tier+"\x00"+a.stage+"\x00"+a.kind < c.provider+"\x00"+c.tier+"\x00"+c.stage+"\x00"+c.kind
		})
		for _, k := range keys {
			fmt.Fprintf(&b, "netops_ai_provider_tokens_total{provider=%q,tier=%q,stage=%q,kind=%q} %d\n", k.provider, k.tier, k.stage, k.kind, t.n[k])
		}
		dropped = t.dropped
		t.mu.Unlock()
	}
	b.WriteString("# HELP netops_ai_provider_token_series_dropped_total Provider token observations dropped because the label space was full.\n")
	b.WriteString("# TYPE netops_ai_provider_token_series_dropped_total counter\n")
	fmt.Fprintf(&b, "netops_ai_provider_token_series_dropped_total %d\n", dropped)
	_, err := io.WriteString(w, b.String())
	return err
}
