// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// thinking_test.go — the fast tier's thinking setting on the wire, the
// self-healing retry when a model refuses it, and the thinking tokens each
// provider reports (Iris latency, owner report 2026-11-11).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const geminiOK = `{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":7,"totalTokenCount":19}}`

const geminiBadArg = `{"error":{"code":400,"message":"Thinking level is not supported for this model.","status":"INVALID_ARGUMENT"}}`

// seqGemini answers each request with the next (status, body) and records the
// decoded request bodies.
type seqGemini struct {
	mu      sync.Mutex
	answers [][2]any
	bodies  []map[string]any
}

func (g *seqGemini) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(b, &body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		g.mu.Lock()
		i := len(g.bodies)
		g.bodies = append(g.bodies, body)
		if i >= len(g.answers) {
			i = len(g.answers) - 1
		}
		st, out := g.answers[i][0].(int), g.answers[i][1].(string)
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	prev := providerSleep
	providerSleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { providerSleep = prev })
}

func (g *seqGemini) thinkingConfig(i int) (map[string]any, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	gen, _ := g.bodies[i]["generationConfig"].(map[string]any)
	if gen["maxOutputTokens"] != float64(MaxOutputTokens) {
		panic("maxOutputTokens must always be sent")
	}
	tc, ok := gen["thinkingConfig"].(map[string]any)
	return tc, ok
}

func callGeminiAt(t *testing.T, tier ModelTier, model string) (Completion, error) {
	t.Helper()
	ctx := WithTierThinking(context.Background(), tier)
	return CallProviderUsage(ctx, "gemini", geminiTestKey, model, "sys", []ChatMessage{{Role: "user", Content: "q"}})
}

func TestGeminiFastTierAsksForTheLeastThinking(t *testing.T) {
	for _, c := range []struct {
		name, model string
		tier        ModelTier
		want        map[string]any // nil ⇒ no thinkingConfig at all
	}{
		{"2.5 flash: thinking off", "gemini-2.5-flash", TierFast, map[string]any{"thinkingBudget": float64(0)}},
		{"models/ prefix tolerated", "models/gemini-2.5-flash", TierFast, map[string]any{"thinkingBudget": float64(0)}},
		{"alias: low level", "gemini-flash-latest", TierFast, map[string]any{"thinkingLevel": "low"}},
		{"3.x flash: low level", "gemini-3-flash-preview", TierFast, map[string]any{"thinkingLevel": "low"}},
		{"lite: default is already least", "gemini-flash-lite-latest", TierFast, nil},
		{"2.5 flash-lite: default off", "gemini-2.5-flash-lite", TierFast, nil},
		{"2.5 pro: cannot turn off", "gemini-2.5-pro", TierFast, nil},
		{"2.0: no thinking", "gemini-2.0-flash", TierFast, nil},
		{"strong tier: provider default", "gemini-2.5-flash", TierStrong, nil},
		{"no tier: provider default", "gemini-flash-latest", "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := &seqGemini{answers: [][2]any{{200, geminiOK}}}
			g.start(t)
			if _, err := callGeminiAt(t, c.tier, c.model); err != nil {
				t.Fatal(err)
			}
			tc, ok := g.thinkingConfig(0)
			if c.want == nil {
				if ok {
					t.Fatalf("thinkingConfig %v sent, want none", tc)
				}
				return
			}
			if !ok || len(tc) != len(c.want) {
				t.Fatalf("thinkingConfig = %v, want %v", tc, c.want)
			}
			for k, v := range c.want {
				if tc[k] != v {
					t.Fatalf("thinkingConfig[%s] = %v, want %v", k, tc[k], v)
				}
			}
		})
	}
}

func TestGeminiThinkingRefusedIsRetriedOnceWithoutIt(t *testing.T) {
	const model = "gemini-9-flash-test-retry" // unique: the remembered set is process state
	g := &seqGemini{answers: [][2]any{{400, geminiBadArg}, {200, geminiOK}, {200, geminiOK}}}
	g.start(t)
	c, err := callGeminiAt(t, TierFast, model)
	if err != nil || c.Text != "OK" {
		t.Fatalf("completion %+v err %v", c, err)
	}
	if len(g.bodies) != 2 {
		t.Fatalf("requests = %d, want the refused one and one retry", len(g.bodies))
	}
	if _, ok := g.thinkingConfig(0); !ok {
		t.Fatal("the first request must carry the thinking setting")
	}
	if tc, ok := g.thinkingConfig(1); ok {
		t.Fatalf("the retry still carried %v", tc)
	}
	// Remembered: the next fast call on the model does not try again.
	if _, err := callGeminiAt(t, TierFast, model); err != nil {
		t.Fatal(err)
	}
	if tc, ok := g.thinkingConfig(2); ok || len(g.bodies) != 3 {
		t.Fatalf("after a proven refusal the setting was sent again: %v (requests %d)", tc, len(g.bodies))
	}
}

func TestGeminiThinkingRetryIsNotRememberedWhenItAlsoFails(t *testing.T) {
	const model = "gemini-9-flash-test-both-fail"
	g := &seqGemini{answers: [][2]any{{400, geminiBadArg}, {400, geminiBadArg}, {200, geminiOK}}}
	g.start(t)
	if _, err := callGeminiAt(t, TierFast, model); ProviderStatusOf(err) != 400 {
		t.Fatalf("err = %v, want the provider's 400", err)
	}
	if geminiThinkingRejected.has(model) {
		t.Fatal("a refusal the retry did not cure must not be blamed on the thinking setting")
	}
	if _, err := callGeminiAt(t, TierFast, model); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.thinkingConfig(2); !ok {
		t.Fatal("the setting must still be tried on the next call")
	}
}

func TestGeminiOtherRefusalsAreNotRetried(t *testing.T) {
	g := &seqGemini{answers: [][2]any{{400, `{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}`}}}
	g.start(t)
	if _, err := callGeminiAt(t, TierFast, "gemini-9-flash-test-key"); err == nil {
		t.Fatal("want the key error")
	}
	if len(g.bodies) != 1 {
		t.Fatalf("requests = %d: a bad key is not a thinking refusal", len(g.bodies))
	}
}

func TestThinkingTokensAreReportedPerProvider(t *testing.T) {
	g := &seqGemini{answers: [][2]any{{200, geminiOK}}}
	g.start(t)
	c, err := callGeminiAt(t, TierFast, "gemini-2.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	// Gemini reports thoughts BESIDE candidates; both are billed output.
	if u := c.Usage; !u.Reported || u.InputTokens != 10 || u.OutputTokens != 9 || u.ThinkingTokens != 7 {
		t.Fatalf("gemini usage = %+v, want in 10 / out 9 (2 text + 7 thinking) / thinking 7", u)
	}

	oc, err := parseOpenAI([]byte(`{"choices":[{"message":{"content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":40,"completion_tokens_details":{"reasoning_tokens":32}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if u := oc.Usage; u.InputTokens != 11 || u.OutputTokens != 40 || u.ThinkingTokens != 32 {
		t.Fatalf("openai usage = %+v (reasoning tokens are already inside completion_tokens)", u)
	}
	plain, _ := parseOpenAI([]byte(`{"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":1,"completion_tokens":2}}`))
	if plain.Usage.ThinkingTokens != 0 || plain.Usage.OutputTokens != 2 {
		t.Fatalf("openai without details = %+v", plain.Usage)
	}

	ac, err := parseAnthropic([]byte(`{"content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":50,"output_tokens_details":{"thinking_tokens":45}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if u := ac.Usage; u.InputTokens != 12 || u.OutputTokens != 50 || u.ThinkingTokens != 45 {
		t.Fatalf("anthropic usage = %+v (thinking tokens are a share of output_tokens)", u)
	}
}

func TestStageIsAClosedSet(t *testing.T) {
	if StageOf(context.Background()) != StageAnswer {
		t.Fatal("no stage must read as the answer stage")
	}
	if got := StageOf(WithStage(context.Background(), StageRewrite)); got != StageRewrite {
		t.Fatalf("stage = %q", got)
	}
	if got := StageOf(WithStage(context.Background(), "attacker-chosen-label")); got != StageAnswer {
		t.Fatalf("an unknown stage became a label: %q", got)
	}
	if fastThinking(WithTierThinking(context.Background(), TierStrong)) || !fastThinking(WithTierThinking(context.Background(), TierFast)) {
		t.Fatal("only the fast tier asks for the least thinking")
	}
}
