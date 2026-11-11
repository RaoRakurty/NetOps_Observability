// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_provider_usage_test.go — Iris latency measurement (owner report
// 2026-11-11: "Iris takes a long time even with Gemini connected"), at the root
// seam every provider call goes through (callProviderGuarded):
//
//   - an ANSWERED call leaves one log line naming provider, model, tier, Iris
//     stage, latency and the provider's input / output / thinking tokens, and
//     feeds netops_ai_provider_tokens_total — never the key or the text;
//   - a fast-tier call asks Gemini for the least thinking; a strong-tier call
//     leaves the provider default.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/aiprovider"
)

const geminiThinkingOK = `{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":3,"thoughtsTokenCount":250,"totalTokenCount":293}}`

func TestAnsweredProviderCallsAreMeasured(t *testing.T) {
	s := platformGeminiServer(t)
	s.aiProvCalls = aiprovider.NewMetrics(nil)
	s.aiToolBudget = ai.NewDailyBudget()
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body) // best-effort: asserted below
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, geminiThinkingOK)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(ai.SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	logs := captureProviderLogs(t)
	l := aiLLM{srv: s, claims: aiPlatformOwn}

	ctx := ai.WithStage(context.Background(), ai.StageRewrite)
	if _, _, u, err := l.CompleteTierWithUsage(ctx, ai.TierFast, "sys", []ai.LLMMessage{{Role: "user", Content: "q"}}); err != nil ||
		u.OutputTokens != 253 || u.ThinkingTokens != 250 {
		t.Fatalf("fast call: usage %+v err %v", u, err)
	}
	if _, _, _, err := l.CompleteTierWithUsage(context.Background(), ai.TierStrong, "sys", []ai.LLMMessage{{Role: "user", Content: "q"}}); err != nil {
		t.Fatal(err)
	}

	got := logs.find("model provider call answered")
	if len(got) != 2 {
		t.Fatalf("want one line per answered call, got %d", len(got))
	}
	f := got[0]
	for k, want := range map[string]any{"provider": "gemini", "model": "gemini-flash-latest", "tier": "fast", "stage": ai.StageRewrite,
		"input_tokens": int64(40), "output_tokens": int64(253), "thinking_tokens": int64(250), "usage_reported": true} {
		if f[k] != want {
			t.Errorf("log field %s = %v (%T), want %v", k, f[k], f[k], want)
		}
	}
	if _, ok := f["latency_ms"]; !ok {
		t.Errorf("latency missing: %v", f)
	}
	if got[1]["tier"] != "strong" || got[1]["stage"] != ai.StageAnswer {
		t.Errorf("strong call line: %v", got[1])
	}
	logs.mustNotContain(t, platformKey)

	// The fast call asked for the least thinking; the strong call did not.
	mu.Lock()
	defer mu.Unlock()
	thinking := func(i int) any {
		gen, _ := bodies[i]["generationConfig"].(map[string]any)
		return gen["thinkingConfig"]
	}
	if tc, _ := thinking(0).(map[string]any); tc["thinkingLevel"] != "low" {
		t.Errorf("fast-tier thinkingConfig = %v, want thinkingLevel low for gemini-flash-latest", thinking(0))
	}
	if thinking(1) != nil {
		t.Errorf("strong-tier call carried thinkingConfig %v", thinking(1))
	}

	var sb strings.Builder
	if err := s.aiProvCalls.Write(&sb); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`netops_ai_provider_tokens_total{provider="gemini",tier="fast",stage="nlq_rewrite",kind="thinking"} 250`,
		`netops_ai_provider_tokens_total{provider="gemini",tier="strong",stage="answer",kind="output"} 253`,
	} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, sb.String())
		}
	}
	// Thinking is billed output: the tenant budget is charged for it too.
	if used := s.aiToolBudget.UsedByTenant()[TenantGlobal]; used != 2*(40+253) {
		t.Errorf("budget charged %d, want %d (input + output incl. thinking, two calls)", used, 2*(40+253))
	}
}
