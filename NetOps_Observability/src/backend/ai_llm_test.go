// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_llm_test.go — the grounded engine's provider adapter (tracker 337 N-A4):
// provider-reported usage flows out and is charged against the tenant's daily
// budget; an unreported call is charged the coarse estimate; an exhausted
// budget refuses BEFORE any provider is called, so the engine degrades to its
// deterministic answer instead of spending more.

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"netops/backend/ai"
)

type countingProvider struct {
	cannedProvider
	calls *atomic.Int32
}

func (c countingProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.cannedProvider.RoundTrip(r)
}

func llmFixture(t *testing.T, body string) (*server, aiLLM, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: countingProvider{cannedProvider{body: body}, &calls}})
	t.Cleanup(restore)
	s := groundingTestServer(t)
	if _, err := s.aiTenantCfg.SetTenantSettings("t-a", ai.TenantSettings{Provider: "openai", Model: "gpt-4o-mini", Key: "sk-test"}); err != nil {
		t.Fatal(err)
	}
	return s, aiLLM{srv: s, claims: jwtClaims{Tenant: "t-a", Sub: "u", Role: "viewer"}}, &calls
}

func TestAILLMReportsAndChargesProviderUsage(t *testing.T) {
	s, l, _ := llmFixture(t, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":700,"completion_tokens":300}}`)
	text, provider, usage, err := l.CompleteTierWithUsage(context.Background(), ai.TierFast, "sys", []ai.LLMMessage{{Role: "user", Content: "q"}})
	if err != nil || text != "ok" || provider != "openai" {
		t.Fatalf("got %q %q %v", text, provider, err)
	}
	if !usage.Reported || usage.InputTokens != 700 || usage.OutputTokens != 300 {
		t.Fatalf("usage = %+v", usage)
	}
	if got := s.aiToolBudget.UsedByTenant()["t-a"]; got != 1000 {
		t.Fatalf("budget charged %d, want the provider-reported 1000", got)
	}
}

func TestAILLMChargesAnEstimateWhenUsageIsUnreported(t *testing.T) {
	s, l, _ := llmFixture(t, `{"choices":[{"message":{"content":"12345678"}}]}`)
	_, _, usage, err := l.CompleteTierWithUsage(context.Background(), ai.TierFast, "", []ai.LLMMessage{{Role: "user", Content: "abcdefgh"}})
	if err != nil || usage.Reported {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}
	if got := s.aiToolBudget.UsedByTenant()["t-a"]; got != 4 { // (8 prompt + 8 reply) / 4
		t.Fatalf("budget charged %d, want the chars/4 estimate 4", got)
	}
}

func TestAILLMRefusesOnceTheBudgetIsSpent(t *testing.T) {
	t.Setenv("AI_TOOLS_DAILY_TOKENS", "100")
	s, l, calls := llmFixture(t, "")
	s.aiToolBudget.Charge("t-a", 100)
	_, _, _, err := l.CompleteTierWithUsage(context.Background(), ai.TierFast, "sys", []ai.LLMMessage{{Role: "user", Content: "q"}})
	if !errors.Is(err, errAIBudgetExhausted) {
		t.Fatalf("want errAIBudgetExhausted, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("an exhausted budget must refuse BEFORE the provider is called; calls=%d", calls.Load())
	}
	// Another tenant's budget is untouched (§3a: metering is per tenant).
	other := aiLLM{srv: s, claims: jwtClaims{Tenant: "t-b", Sub: "v", Role: "viewer"}}
	if _, _, _, err := other.CompleteTierWithUsage(context.Background(), ai.TierFast, "s", nil); errors.Is(err, errAIBudgetExhausted) {
		t.Fatal("tenant A's spent budget must not refuse tenant B")
	}
}
