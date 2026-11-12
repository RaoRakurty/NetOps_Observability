// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiprovider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/applog"
)

// captureLog points applog's observer at a buffer for one test.
func captureLog(t *testing.T) *[]map[string]any {
	t.Helper()
	var lines []map[string]any
	restore := applog.SetObserver(func(level, component, msg string, fields map[string]any) {
		if component == "ai.provider" {
			cp := map[string]any{"_level": level, "_msg": msg}
			for k, v := range fields {
				cp[k] = v
			}
			lines = append(lines, cp)
		}
	})
	t.Cleanup(restore)
	return &lines
}

func TestRecordSuccessLogsEveryMeasureAndCountsTokens(t *testing.T) {
	lines := captureLog(t)
	m := NewMetrics(nil)
	m.RecordSuccess(Call{Tenant: "t-a", Provider: "gemini", Model: "gemini-flash-latest", Tier: "fast", Stage: "nlq_rewrite",
		KeySource: "platform", Latency: 1830 * time.Millisecond, InputTokens: 2100, OutputTokens: 900, ThinkingTokens: 860, UsageReported: true})
	m.RecordSuccess(Call{Tenant: "t-a", Provider: "gemini", Model: "gemini-flash-latest", Tier: "fast", Stage: "nlq_rewrite",
		Latency: time.Second, InputTokens: 100, OutputTokens: 10, UsageReported: true})
	m.RecordSuccess(Call{Tenant: "t-a", Provider: "openai", Model: "gpt-4o-mini", Latency: time.Second, UsageReported: false})

	if len(*lines) != 3 {
		t.Fatalf("log lines = %d, want one per answered call", len(*lines))
	}
	l := (*lines)[0]
	for k, want := range map[string]any{"_level": "info", "provider": "gemini", "model": "gemini-flash-latest", "tier": "fast",
		"stage": "nlq_rewrite", "latency_ms": int64(1830), "input_tokens": int64(2100), "output_tokens": int64(900),
		"thinking_tokens": int64(860), "usage_reported": true, "tenant": "t-a", "key_source": "platform"} {
		if l[k] != want {
			t.Errorf("log field %s = %v (%T), want %v", k, l[k], l[k], want)
		}
	}
	if (*lines)[2]["tier"] != "default" || (*lines)[2]["stage"] != "answer" {
		t.Errorf("blank tier/stage must read default/answer: %v", (*lines)[2])
	}
	// The log line never carries text: no prompt, no reply, no key.
	b, _ := json.Marshal(*lines)
	for _, banned := range []string{"prompt", "reply", "text", "key\""} {
		if bytes.Contains(b, []byte(banned)) {
			t.Errorf("log carries %q: %s", banned, b)
		}
	}

	var sb strings.Builder
	if err := m.Write(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"# TYPE netops_ai_provider_tokens_total counter",
		`netops_ai_provider_tokens_total{provider="gemini",tier="fast",stage="nlq_rewrite",kind="input"} 2200`,
		`netops_ai_provider_tokens_total{provider="gemini",tier="fast",stage="nlq_rewrite",kind="output"} 910`,
		`netops_ai_provider_tokens_total{provider="gemini",tier="fast",stage="nlq_rewrite",kind="thinking"} 860`,
		"netops_ai_provider_token_series_dropped_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `provider="openai"`) && strings.Contains(out, "tokens_total{provider=\"openai\"") {
		t.Errorf("an unreported call must not invent tokens:\n%s", out)
	}
	var nm *Metrics
	nm.RecordSuccess(Call{Provider: "x"}) // nil-safe
}

func TestTokenLabelSpaceIsBounded(t *testing.T) {
	m := NewMetrics(nil)
	for i := 0; i < maxTokenSeries+5; i++ {
		m.tokens.add(tokenKey{fmt.Sprintf("p%d", i), "fast", "answer", "input"}, 1)
	}
	if len(m.tokens.n) != maxTokenSeries || m.tokens.dropped != 5 {
		t.Fatalf("series=%d dropped=%d", len(m.tokens.n), m.tokens.dropped)
	}
}
