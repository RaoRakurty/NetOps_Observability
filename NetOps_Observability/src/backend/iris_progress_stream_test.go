// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_progress_stream_test.go — tracker 337 N-E2: the progress an operator
// sees while Iris works reaches past the orchestrator — the AI
// investigation's own lookups, its grounding, and a switch to the fallback
// model — carries nothing but the closed vocabulary, and a streamed ask is
// refused (as JSON, before any stream opens) when it names someone else's
// conversation.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aiprovider"
)

type progressRec struct {
	mu  sync.Mutex
	evs []ai.TraceEvent
}

func (r *progressRec) Trace(e ai.TraceEvent) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }

func (r *progressRec) seq() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.evs))
	for _, e := range r.evs {
		s := string(e.Type)
		if e.Tool != "" {
			s += ":" + e.Tool
		}
		if e.Outcome != "" {
			s += "=" + e.Outcome
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

// The agent loop's lookups are traced through the request context: each
// start has its finish, grounding follows, and no event carries the
// evidence the lookup returned.
func TestAgentLoopTracesEachLookupAndGrounding(t *testing.T) {
	s, p, reg, pol, specs := agentTestSetup("t-a")
	round := 0
	call := func(_ context.Context, _ string, _ []ai.AgentTurn, _ []ai.ToolSpec) (string, []ai.ToolCall, error) {
		round++
		if round == 1 {
			return "", []ai.ToolCall{{ID: "c1", Name: "get_active_major_incidents", Args: json.RawMessage(`{}`)}}, nil
		}
		return "One incident is open [problem:" + problemA + "].", nil, nil
	}
	rec := &progressRec{}
	ctx := ai.WithTrace(context.Background(), rec)
	if _, err := s.runAgentLoop(ctx, jwtClaims{Tenant: "t-a", Sub: "u"}, p, reg, pol, specs, "sys",
		[]copilotMessage{{Role: "user", Content: "what is open?"}}, nil, call); err != nil {
		t.Fatal(err)
	}
	got := rec.seq()
	if want := "tool_started:get_active_major_incidents tool_finished:get_active_major_incidents=ok grounding"; got != want {
		t.Fatalf("progress:\n got %s\nwant %s", got, want)
	}
	b, err := json.Marshal(rec.evs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "BGP peer down") || strings.Contains(string(b), problemA) {
		t.Fatalf("evidence leaked into progress: %s", b)
	}
}

// Without a sink in the context (the copilot chat path) the same loop emits
// nothing and behaves the same.
func TestAgentLoopWithoutASinkEmitsNothing(t *testing.T) {
	s, p, reg, pol, specs := agentTestSetup("t-a")
	call := func(_ context.Context, _ string, _ []ai.AgentTurn, sp []ai.ToolSpec) (string, []ai.ToolCall, error) {
		return "nothing to look up", nil, nil
	}
	res, err := s.runAgentLoop(context.Background(), jwtClaims{Tenant: "t-a", Sub: "u"}, p, reg, pol, specs, "sys",
		[]copilotMessage{{Role: "user", Content: "hi"}}, nil, call)
	if err != nil || res.Text != "nothing to look up" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// An AI investigation whose configured model is overloaded shows the
// investigation start and then the switch to the fallback model — once, and
// without naming either model.
func TestAgentFallbackTracesTheInvestigationAndTheSwitch(t *testing.T) {
	s := oneRegistryServer(t)
	clearAIEnv(t)
	setAIModelsForTest(t, s, true, true)
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
	rec := &progressRec{}
	ctx, _ := ai.WithModelNote(ai.WithTrace(context.Background(), rec))
	if _, err := orch.AgentAnswer(ctx, s.aiPrincipal(claims), "explain the network topology", nil); err != nil {
		t.Fatalf("the fallback model must answer: %v", err)
	}
	got := rec.seq()
	i, f := strings.Index(got, "investigating"), strings.Index(got, "model_fallback")
	if i != 0 || f < 0 || strings.Count(got, "model_fallback") != 1 {
		t.Fatalf("want investigating first, then one model_fallback: %s", got)
	}
	if strings.Contains(got, "gemini") {
		t.Fatalf("a progress event named a model: %s", got)
	}
}

// The single grounded call's provider chain shows the switch as well.
func TestProviderChainTracesTheFallback(t *testing.T) {
	s := strikeServer(t)
	s.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey, Model: "gemini-flash-latest"})
	g := startFakeGemini(t, 200, geminiOK)
	g.mu.Lock()
	g.statusFor = map[string]int{"gemini-flash-latest": 503}
	g.mu.Unlock()
	rec := &progressRec{}
	l := aiLLM{srv: s, claims: aiPlatformOwn}
	ctx, _ := ai.WithModelNote(ai.WithTrace(context.Background(), rec))
	if _, _, _, err := l.CompleteTierWithUsage(ctx, "", "s", []ai.LLMMessage{{Role: "user", Content: "q"}}); err != nil {
		t.Fatalf("the fallback model must answer: %v", err)
	}
	if got := rec.seq(); got != "model_fallback" {
		t.Fatalf("want exactly one model_fallback, got %q", got)
	}

	// A first model that answers: no switch is shown.
	g.mu.Lock()
	g.statusFor = nil
	g.mu.Unlock()
	rec2 := &progressRec{}
	ctx2, _ := ai.WithModelNote(ai.WithTrace(context.Background(), rec2))
	if _, _, _, err := l.CompleteTierWithUsage(ctx2, "", "s", []ai.LLMMessage{{Role: "user", Content: "q"}}); err != nil {
		t.Fatal(err)
	}
	if got := rec2.seq(); got != "" {
		t.Fatalf("no fallback, no event: %q", got)
	}
}

// §3a: a streamed ask naming another principal's conversation is refused
// with the same JSON 404 as the plain ask — the stream never opens, so no
// progress of any kind reaches the caller.
func TestStreamedAskRefusesSomeoneElsesConversationBeforeStreaming(t *testing.T) {
	s, a, b := irisBoxFixture(t)
	id := startConvo(t, s, a)
	colleague := a
	colleague.Sub = "ua-colleague"
	for name, c := range map[string]jwtClaims{"other tenant": b, "same-tenant colleague": colleague} {
		body, _ := json.Marshal(map[string]any{"question": "show cpu on edge-a for the last hour", "conversation_id": id}) // discard: cannot fail
		r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(string(body)))
		r.Header.Set("Accept", "text/event-stream")
		r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
		w := httptest.NewRecorder()
		s.handleAIAsk(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", name, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
			t.Errorf("%s: a refusal must not open a stream (Content-Type %q)", name, ct)
		}
		if strings.Contains(w.Body.String(), "event: ") {
			t.Errorf("%s: progress reached a refused caller: %q", name, w.Body.String())
		}
	}
}
