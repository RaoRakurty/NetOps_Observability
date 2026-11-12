// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_provider_guard_test.go — Iris "connect a model" + latency batch
// (tracker 337, 2026-11-10), at the root seams:
//
//   - every provider failure is logged with its class and no secret (§10);
//   - the (tenant, provider) breaker opens after consecutive failures, skips
//     calls while open (no provider hit), probes, closes — per tenant (§3a);
//   - the model-compile fallback is skipped when every provider is paused;
//   - C1: a provider with no model configured gets ITS OWN default model;
//   - C3: "Test connection" — platform-admin only, the key never persisted,
//     logged or echoed; the tenant test uses ONLY the caller's own key (§3a);
//   - C5/D4: the config view (banner source) is admin-only and carries the
//     budget status; the default budget is 1 M tokens/day.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aiprovider"
	"netops/backend/internal/applog"
)

// clearAIEnv removes every env input to provider resolution so a test sees
// only what it configures.
func clearAIEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"COPILOT_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY",
		"COPILOT_PROVIDER", "COPILOT_MODEL", "COPILOT_PROVIDER_CHAIN", "GEMINI_MODEL", "OPENAI_MODEL", "ANTHROPIC_MODEL", "AI_TOOLS_DAILY_TOKENS"} {
		t.Setenv(k, "")
	}
}

// fakeGemini is a Gemini endpoint that records the key each call carried.
type fakeGemini struct {
	mu     sync.Mutex
	keys   []string
	urls   []string
	status int
	body   string
	hang   bool
	// statusFor answers a model (named in the URL path) with its own status
	// and an overloaded body instead of status/body.
	statusFor map[string]int
}

func (g *fakeGemini) set(status int, body string) {
	g.mu.Lock()
	g.status, g.body = status, body
	g.mu.Unlock()
}

func (g *fakeGemini) hits() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.keys) }

func startFakeGemini(t *testing.T, status int, body string) *fakeGemini {
	t.Helper()
	g := &fakeGemini{status: status, body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		g.mu.Lock()
		g.keys = append(g.keys, r.Header.Get("x-goog-api-key"))
		g.urls = append(g.urls, r.URL.String())
		st, b, hang := g.status, g.body, g.hang
		for m, code := range g.statusFor {
			if strings.Contains(r.URL.Path, "/"+m+":") {
				st, b = code, `{"error":{"code":503,"message":"This model is currently experiencing high demand.","status":"UNAVAILABLE"}}`
			}
		}
		g.mu.Unlock()
		if hang {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = io.WriteString(w, b)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(ai.SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	return g
}

const (
	geminiOK       = `{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":1}}`
	geminiNotFound = `{"error":{"code":404,"message":"models/gemini-x is not found for API version v1beta","status":"NOT_FOUND"}}`
	geminiBadKey   = `{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID"}]}}`
	platformKey    = "AIzaPLATFORM-secret-0001"
	tenantAKey     = "AIzaTENANT-A-secret-0002"
	draftKey       = "AIzaDRAFT-secret-0003"
)

// providerLogCapture collects every applog line emitted during a test.
type providerLogCapture struct {
	mu    sync.Mutex
	lines []map[string]any
}

func captureProviderLogs(t *testing.T) *providerLogCapture {
	t.Helper()
	c := &providerLogCapture{}
	restore := applog.SetObserver(func(level, component, msg string, fields map[string]any) {
		m := map[string]any{"level": level, "component": component, "msg": msg}
		for k, v := range fields {
			m[k] = v
		}
		c.mu.Lock()
		c.lines = append(c.lines, m)
		c.mu.Unlock()
	})
	t.Cleanup(restore)
	return c
}

func (c *providerLogCapture) find(msg string) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, l := range c.lines {
		if l["msg"] == msg {
			out = append(out, l)
		}
	}
	return out
}

func (c *providerLogCapture) mustNotContain(t *testing.T, secrets ...string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := json.Marshal(c.lines)
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Fatalf("SECRET IN LOGS: %q found in %s", s, b)
		}
	}
}

func platformGeminiServer(t *testing.T) *server {
	t.Helper()
	clearAIEnv(t)
	s := aiCfgTestServer(t)
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey})
	return s
}

func TestProviderFailureIsLoggedWithClassAndNoSecret(t *testing.T) {
	s := platformGeminiServer(t)
	g := startFakeGemini(t, 404, geminiNotFound)
	logs := captureProviderLogs(t)
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	_, _, _, err := l.CompleteTierWithUsage(context.Background(), ai.TierFast, "sys", []ai.LLMMessage{{Role: "user", Content: "q"}})
	if err == nil {
		t.Fatal("want an error")
	}
	if ai.ClassifyProviderError(err) != ai.ProvModelNotFound {
		t.Fatalf("the wrapped error must keep its class: %v", err)
	}
	// A model the key cannot use is followed by the provider's fallback model,
	// same key (2026-11-12) — both are refused here, so two calls, two lines.
	rec := ai.RecommendedModels()["gemini"]
	if g.hits() != 2 || g.keys[0] != platformKey || g.keys[1] != platformKey || strings.Contains(g.urls[0], platformKey) ||
		!strings.Contains(g.urls[0], rec.Fast+":") || !strings.Contains(g.urls[1], rec.Default+":") {
		t.Fatalf("request: hits=%d keys=%v urls=%v", g.hits(), g.keys, g.urls)
	}
	got := logs.find("model provider call failed")
	if len(got) != 2 {
		t.Fatalf("want one failure line per model asked, got %d: %v", len(got), logs.lines)
	}
	for i, want := range []struct {
		model    string
		fallback bool
	}{{rec.Fast, false}, {rec.Default, true}} {
		f := got[i]
		if f["provider"] != "gemini" || f["model"] != want.model || f["fallback"] != want.fallback || f["tier"] != "fast" ||
			f["error_class"] != ai.ProvModelNotFound || f["http_status"] != 404 || f["provider_reason"] != "NOT_FOUND" {
			t.Fatalf("failure line %d fields: %v", i, f)
		}
		if _, ok := f["latency_ms"]; !ok {
			t.Fatalf("latency missing: %v", f)
		}
	}
	logs.mustNotContain(t, platformKey)
}

func TestProviderBreakerOpensSkipsProbesAndCloses(t *testing.T) {
	s := platformGeminiServer(t)
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	s.aiBreaker = aiprovider.NewBreaker(aiprovider.Config{Threshold: 3, Cooldown: time.Minute,
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	s.aiProvCalls = aiprovider.NewMetrics(s.aiBreaker)
	g := startFakeGemini(t, 400, geminiBadKey)
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	call := func() error {
		_, _, _, err := l.CompleteTierWithUsage(context.Background(), ai.TierFast, "s", []ai.LLMMessage{{Role: "user", Content: "q"}})
		return err
	}
	for i := 0; i < 3; i++ {
		if err := call(); ai.ClassifyProviderError(err) != ai.ProvAuth {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if g.hits() != 3 {
		t.Fatalf("hits = %d", g.hits())
	}
	start := time.Now()
	if err := call(); !errors.Is(err, ai.ErrProviderBreakerOpen) {
		t.Fatalf("an open breaker must refuse with ErrProviderBreakerOpen, got %v", err)
	}
	if g.hits() != 3 || time.Since(start) > 100*time.Millisecond {
		t.Fatal("an open breaker must skip the provider entirely, at once")
	}
	if len(s.usableProviderCandidates(aiPlatformOwn, ai.TierStrong)) != 0 {
		t.Fatal("no usable provider while the only one is paused — the model-compile fallback must be skipped")
	}
	// Cool-down passes; the provider is fixed; one probe closes the breaker.
	mu.Lock()
	now = now.Add(61 * time.Second)
	mu.Unlock()
	g.set(200, geminiOK)
	if err := call(); err != nil {
		t.Fatalf("probe: %v", err)
	}
	// A refused key is about the whole provider: the PROVIDER breaker opened
	// (and the fallback model was never sent the bad key — 3 calls, not 6), and
	// the probe closes it; every model of it is usable again.
	if s.aiBreaker.State(TenantGlobal, "gemini") != aiprovider.Closed || len(s.usableProviderCandidates(aiPlatformOwn, ai.TierStrong)) != 2 {
		t.Fatalf("a successful probe must close the breaker: state=%v usable=%+v", s.aiBreaker.State(TenantGlobal, "gemini"), s.usableProviderCandidates(aiPlatformOwn, ai.TierStrong))
	}
	var sb strings.Builder
	_ = s.aiProvCalls.Write(&sb)
	// breaker_open 2: the configured model and its fallback were both refused by
	// the open provider breaker on the fourth call.
	for _, want := range []string{`outcome="auth"} 3`, `outcome="breaker_open"} 2`, `netops_ai_provider_breaker_transitions_total{provider="gemini",to="open"} 1`} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, sb.String())
		}
	}
}

// §3a: tenant A's failing BYO key never pauses tenant B.
func TestProviderBreakerIsPerTenant(t *testing.T) {
	clearAIEnv(t)
	s := aiCfgTestServer(t)
	s.aiBreaker = aiprovider.NewBreaker(aiprovider.Config{Threshold: 2, Cooldown: time.Hour})
	for _, tn := range []string{"t-a", "t-b"} {
		if _, err := s.aiTenantCfg.SetTenantSettings(tn, ai.TenantSettings{Provider: "gemini", Key: "AIza-" + tn}); err != nil {
			t.Fatal(err)
		}
	}
	g := startFakeGemini(t, 401, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`)
	a := aiLLM{srv: s, claims: aiTenantUserA}
	for i := 0; i < 3; i++ {
		_, _, _, _ = a.CompleteTierWithUsage(context.Background(), ai.TierFast, "s", []ai.LLMMessage{{Role: "user", Content: "q"}})
	}
	if g.hits() != 2 {
		t.Fatalf("t-a: breaker must stop calls after 2 failures, hits=%d", g.hits())
	}
	b := aiLLM{srv: s, claims: jwtClaims{Role: "viewer", Tenant: "t-b", Sub: "user-b"}}
	_, _, _, err := b.CompleteTierWithUsage(context.Background(), ai.TierFast, "s", []ai.LLMMessage{{Role: "user", Content: "q"}})
	if errors.Is(err, ai.ErrProviderBreakerOpen) || g.hits() != 3 || g.keys[2] != "AIza-t-b" {
		t.Fatalf("ISOLATION: t-a's breaker affected t-b (err=%v hits=%d)", err, g.hits())
	}
}

// A hanging provider is bounded by the caller's deadline and classed timeout;
// a caller that LEFT is not counted against the provider.
func TestProviderTimeoutCountsButCallerCancelDoesNot(t *testing.T) {
	s := platformGeminiServer(t)
	s.aiBreaker = aiprovider.NewBreaker(aiprovider.Config{Threshold: 1, Cooldown: time.Hour})
	g := startFakeGemini(t, 200, geminiOK)
	g.mu.Lock()
	g.hang = true
	g.mu.Unlock()
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, _, _, err := l.CompleteTierWithUsage(ctx, ai.TierFast, "s", []ai.LLMMessage{{Role: "user", Content: "q"}})
	if ai.ClassifyProviderError(err) != ai.ProvCanceled || s.aiBreaker.State(TenantGlobal, "gemini") != aiprovider.Closed {
		t.Fatalf("a caller that left must not open the breaker: %v state=%v", err, s.aiBreaker.State(TenantGlobal, "gemini"))
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel2()
	start := time.Now()
	_, _, _, err = l.CompleteTierWithUsage(ctx2, ai.TierFast, "s", []ai.LLMMessage{{Role: "user", Content: "q"}})
	if ai.ClassifyProviderError(err) != ai.ProvTimeout || time.Since(start) > 2*time.Second {
		t.Fatalf("hanging provider: %v after %v", err, time.Since(start))
	}
	// A timeout is about the model asked (2026-11-12: one alias hung while a
	// dated model answered): that model's breaker opens, the provider's does
	// not, and the fallback was not blamed for the budget the first one spent.
	fast := aiprovider.Target("gemini", ai.RecommendedModels()["gemini"].Fast)
	fallback := aiprovider.Target("gemini", ai.RecommendedModels()["gemini"].Default)
	if s.aiBreaker.State(TenantGlobal, fast) != aiprovider.Open {
		t.Fatal("a model timeout counts against that model")
	}
	if s.aiBreaker.State(TenantGlobal, "gemini") != aiprovider.Closed || s.aiBreaker.State(TenantGlobal, fallback) != aiprovider.Closed {
		t.Fatal("the provider and the fallback model must not pay for one model's timeout")
	}
	if g.hits() != 2 {
		t.Fatalf("once the budget is spent no fallback is called: hits=%d", g.hits())
	}
}

// C1 — TestProviderDefaultModelFollowsProvider: with COPILOT_PROVIDER=gemini
// and no COPILOT_MODEL, the gemini candidate gets gemini's default, never the
// old hard-coded Claude model; an explicitly stored model still wins.
func TestProviderDefaultModelFollowsProvider(t *testing.T) {
	clearAIEnv(t)
	t.Setenv("COPILOT_PROVIDER", "gemini")
	s := aiCfgTestServer(t)
	if got := s.copilotCfg.Get(); got.Provider != "gemini" || got.Model != "" {
		t.Fatalf("defaults = %+v, want gemini with an empty model", got)
	}
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey})
	rec := ai.RecommendedModels()["gemini"]
	for tier, want := range map[ai.ModelTier]string{"": rec.Default, ai.TierFast: rec.Fast, ai.TierStrong: rec.Strong} {
		c := primaries(t, s.providerCandidatesForTier(aiPlatformOwn, tier))
		if len(c) != 1 || c[0].name != "gemini" || c[0].model != want {
			t.Fatalf("tier %q candidates = %+v, want %s", tier, c, want)
		}
	}
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Model: "gemini-2.5-pro"})
	if c := primaries(t, s.providerCandidatesForTier(aiPlatformOwn, "")); c[0].model != "gemini-2.5-pro" {
		t.Fatalf("an explicit operator model must win on the default path: %+v", c)
	}
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Model: "gemini-2.5-pro", ModelFast: "gemini-2.5-pro"})
	if c := primaries(t, s.providerCandidatesForTier(aiPlatformOwn, ai.TierFast)); c[0].model != "gemini-2.5-pro" {
		t.Fatalf("an explicit tier model must win: %+v", c)
	}
	// An env model configured for ANOTHER provider never reaches gemini.
	t.Setenv("COPILOT_PROVIDER", "anthropic")
	t.Setenv("COPILOT_MODEL", "claude-sonnet-4-6")
	s2 := aiCfgTestServer(t)
	s2.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey})
	if got := s2.copilotCfg.Get(); got.Model != "" {
		t.Fatalf("COPILOT_MODEL for anthropic leaked into the gemini config: %q", got.Model)
	}
	if c := primaries(t, s2.providerCandidatesForTier(aiPlatformOwn, ai.TierFast)); len(c) != 1 || c[0].model != ai.RecommendedModels()["gemini"].Fast {
		t.Fatalf("candidates = %+v", c)
	}
}
