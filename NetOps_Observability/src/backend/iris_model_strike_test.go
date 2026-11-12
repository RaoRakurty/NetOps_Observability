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
	"strings"
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

// A timeout strikes the MODEL that timed out: a later stage of the same request
// does not wait on it again, but may ask the provider's other model once
// (2026-11-12: an alias hung while the dated model answered the same key). A
// second model of the provider timing out strikes the provider, so a request
// waits at most twice on one provider, never once per stage.
func TestATimeoutIsWaitedForOncePerModelAndTwicePerProvider(t *testing.T) {
	s := strikeServer(t)
	g := startFakeGemini(t, 200, geminiOK)
	g.mu.Lock()
	g.hang = true
	g.mu.Unlock()
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	msgs := []ai.LLMMessage{{Role: "user", Content: "q"}}
	ctx, _ := ai.WithModelNote(context.Background())
	stage := func(tier ai.ModelTier) error {
		c, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
		defer cancel()
		_, _, _, err := l.CompleteTierWithUsage(c, tier, "s", msgs)
		return err
	}
	// Stage 1 (fast model) times out; its budget is spent, so its fallback is
	// not called in it.
	if err := stage(ai.TierFast); ai.ClassifyProviderError(err) != ai.ProvTimeout || g.hits() != 1 {
		t.Fatalf("stage 1: %v hits=%d", err, g.hits())
	}
	// Stage 2 (strong = the recommended default model) is a different model:
	// asked once, times out — now two models of the provider timed out.
	if err := stage(ai.TierStrong); ai.ClassifyProviderError(err) != ai.ProvTimeout || g.hits() != 2 {
		t.Fatalf("stage 2: %v hits=%d", err, g.hits())
	}
	// Stage 3 has NO deadline: without the provider strike it would hang.
	start := time.Now()
	_, _, _, err := l.CompleteTierWithUsage(ctx, ai.TierFast, "s", msgs)
	if ai.ClassifyProviderError(err) != ai.ProvTimeout || ai.FallbackNoteFor(err) != ai.NoteModelTimedOut || time.Since(start) > 100*time.Millisecond || g.hits() != 2 {
		t.Fatalf("a provider whose two models timed out must not be waited on again: err=%v after %v hits=%d", err, time.Since(start), g.hits())
	}
}

// The lab case end to end at the LLM seam: the configured model is overloaded
// (503) and the provider's recommended model answers — Iris answers, with the
// answering model named, instead of losing the model.
func TestAnOverloadedModelFallsBackToTheProvidersRecommendedModel(t *testing.T) {
	s := strikeServer(t)
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey, Model: "gemini-flash-latest"})
	g := startFakeGemini(t, 200, geminiOK)
	g.mu.Lock()
	g.statusFor = map[string]int{"gemini-flash-latest": 503}
	g.mu.Unlock()
	logs := captureProviderLogs(t)
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	ctx, note := ai.WithModelNote(context.Background())
	text, provider, _, err := l.CompleteTierWithUsage(ctx, "", "s", []ai.LLMMessage{{Role: "user", Content: "q"}})
	if err != nil || text == "" || provider != "gemini" {
		t.Fatalf("the fallback model must answer: text=%q provider=%q err=%v", text, provider, err)
	}
	if got := note.Model("gemini"); got != "gemini-2.5-flash" {
		t.Fatalf("the answer must name the model that answered, got %q", got)
	}
	if len(logs.find("fallback model answered")) != 1 {
		t.Fatal("a fallback answer is logged")
	}
	if g.keys[len(g.keys)-1] != platformKey {
		t.Fatal("the fallback rides the same key")
	}
	logs.mustNotContain(t, platformKey)
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

// The agent loop (AI investigations) runs on one model; when the configured
// model is overloaded it runs once more on the provider's fallback model,
// same key, inside the same budget — never "model unavailable" while another
// model of the provider answers (lab 2026-11-12: gemini-flash-latest 503).
func TestAgentLoopMovesToTheFallbackModelWhenTheConfiguredOneIsOverloaded(t *testing.T) {
	s := oneRegistryServer(t)
	clearAIEnv(t)
	t.Setenv("FEATURE_AI_TOOLS", "true")
	s.aiBreaker = aiprovider.NewBreaker(aiprovider.Config{Threshold: 1000, Cooldown: time.Hour})
	s.aiProvCalls = aiprovider.NewMetrics(s.aiBreaker)
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey, Model: "gemini-flash-latest"})
	g := startFakeGemini(t, 200, geminiOK)
	g.mu.Lock()
	g.statusFor = map[string]int{"gemini-flash-latest": 503}
	g.mu.Unlock()

	claims := superA()
	orch := s.newOrchestrator(aiTSRequest(claims), claims)
	if orch.AgentAnswer == nil {
		t.Fatal("fixture: the agent path must be wired, or this test proves nothing")
	}
	ctx, _ := ai.WithModelNote(context.Background())
	ans, err := orch.AgentAnswer(ctx, s.aiPrincipal(claims), "explain the network topology", nil)
	if err != nil {
		t.Fatalf("the fallback model must answer: %v (calls %v)", err, g.urls)
	}
	if ans.Provider != "gemini" || ans.Model != "gemini-2.5-flash" {
		t.Fatalf("the answer must name the model that answered: %s/%s", ans.Provider, ans.Model)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last := g.urls[len(g.urls)-1]
	if !strings.Contains(g.urls[0], "gemini-flash-latest:") || !strings.Contains(last, "gemini-2.5-flash:") || g.keys[len(g.keys)-1] != platformKey {
		t.Fatalf("configured model first, then the fallback on the same key: %v", g.urls)
	}
}
