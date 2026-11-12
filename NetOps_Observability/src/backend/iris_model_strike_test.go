// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_model_strike_test.go — one strike per request (§9, lab 2026-11-11:
// "which devices are down right now?" waited 28 s on a timing-out model while
// the tie-break, the rephrase and the strong compile each waited out their own
// budget in turn). After a provider fails a call of a request in a way that
// will not change within seconds, the rest of that request does not call it
// again: the deterministic answer ships after at most ONE model budget.
//
// The breaker is set far above the calls these tests make, so what stops the
// second call is the request's strike, not the cross-request breaker.

import (
	"context"
	"errors"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aiprovider"
)

const geminiUnauth = `{"error":{"code":401,"message":"bad key","status":"UNAUTHENTICATED"}}`

func strikeServer(t *testing.T) *server {
	t.Helper()
	s := platformGeminiServer(t)
	s.aiBreaker = aiprovider.NewBreaker(aiprovider.Config{Threshold: 1000, Cooldown: time.Hour})
	s.aiProvCalls = aiprovider.NewMetrics(s.aiBreaker)
	return s
}

func TestAProviderThatFailedIsNotCalledAgainInTheSameRequest(t *testing.T) {
	s := strikeServer(t)
	g := startFakeGemini(t, 401, geminiUnauth)
	logs := captureProviderLogs(t)
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	msgs := []ai.LLMMessage{{Role: "user", Content: "q"}}
	ctx, _ := ai.WithModelNote(context.Background())
	if _, _, _, err := l.CompleteTierWithUsage(ctx, ai.TierFast, "s", msgs); ai.ClassifyProviderError(err) != ai.ProvAuth {
		t.Fatalf("first call: %v", err)
	}
	start := time.Now()
	_, _, _, err := l.CompleteTierWithUsage(ctx, ai.TierStrong, "s", msgs)
	var skip *ai.ModelSkippedError
	if !errors.As(err, &skip) || ai.ClassifyProviderError(err) != ai.ProvAuth || g.hits() != 1 || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("the second call of the request must be skipped at once with the first failure's class: err=%v hits=%d after %v", err, g.hits(), time.Since(start))
	}
	if len(logs.find("model call skipped: the provider already failed in this request")) != 1 {
		t.Fatal("a skipped call is logged (§10: no silent failure)")
	}
	logs.mustNotContain(t, platformKey)
	// A new request starts clean: the strike is per request, not a breaker.
	fresh, _ := ai.WithModelNote(context.Background())
	if _, _, _, err := l.CompleteTierWithUsage(fresh, ai.TierFast, "s", msgs); ai.ClassifyProviderError(err) != ai.ProvAuth || g.hits() != 2 {
		t.Fatalf("a new request must call the provider again: err=%v hits=%d", err, g.hits())
	}
}

// A timeout strikes: the next stage of the same request does not wait again.
func TestATimeoutIsWaitedForOncePerRequest(t *testing.T) {
	s := strikeServer(t)
	g := startFakeGemini(t, 200, geminiOK)
	g.mu.Lock()
	g.hang = true
	g.mu.Unlock()
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	msgs := []ai.LLMMessage{{Role: "user", Content: "q"}}
	ctx, _ := ai.WithModelNote(context.Background())
	short, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	if _, _, _, err := l.CompleteTierWithUsage(short, ai.TierFast, "s", msgs); ai.ClassifyProviderError(err) != ai.ProvTimeout {
		t.Fatalf("first call: %v", err)
	}
	start := time.Now()
	_, _, _, err := l.CompleteTierWithUsage(ctx, ai.TierStrong, "s", msgs) // no deadline: without the strike it would hang
	if ai.ClassifyProviderError(err) != ai.ProvTimeout || ai.FallbackNoteFor(err) != ai.NoteModelTimedOut || time.Since(start) > 100*time.Millisecond || g.hits() != 1 {
		t.Fatalf("a timed-out provider must not be waited on twice: err=%v after %v hits=%d", err, time.Since(start), g.hits())
	}
}

// End to end through /api/ai/ask: a question the grammar cannot read and no
// method claims takes the rephrase and then the strong compile; with the
// provider failing, exactly ONE call is made and the deterministic answer
// still ships.
func TestAskCallsAFailingProviderOnce(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, _ := nlqAPIFixture(t)
	clearAIEnv(t)
	s.copilotCfg = newCopilotConfigStore(t.TempDir()+"/copilot_config.json", nil)
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey})
	if s.aiTenantCfg == nil {
		s.aiTenantCfg = newAITenantConfigStore(t.TempDir()+"/ai_tenant_config.json", nil)
	}
	s.aiBreaker = aiprovider.NewBreaker(aiprovider.Config{Threshold: 1000, Cooldown: time.Hour})
	s.aiProvCalls = aiprovider.NewMetrics(s.aiBreaker)
	g := startFakeGemini(t, 401, geminiUnauth)
	if !s.nlqModelUsable(a, ai.TierFast) {
		t.Fatal("fixture: the model path must be usable, or this test proves nothing")
	}
	start := time.Now()
	out := askIris(t, s, a, "how chatty is the frobnicator on edge-a")
	if g.hits() != 1 {
		t.Fatalf("a failing provider must be called once per request, got %d calls", g.hits())
	}
	if out["mode"] == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("the deterministic answer must still ship, promptly: %v after %v", out, time.Since(start))
	}
}
