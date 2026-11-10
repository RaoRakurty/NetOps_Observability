// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// provider_outcome_test.go — the Iris latency guarantees (2026-11-10):
//   - a ready deterministic answer is never held hostage by a model: a
//     provider that hangs costs at most the per-stage budget, and the answer
//     says "Model narrative timed out; showing the evidence answer.";
//   - the budget is ON by default (zero StageBudgets = 8 s fast / 15 s strong);
//   - every failure maps onto a closed outcome class;
//   - the per-answer footnote names the model that actually answered.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/applog"
)

// hangingLLM is a provider that never answers on its own: it returns only when
// its context ends (or after `max`, a backstop so a broken budget fails the
// test instead of hanging it). It records the deadline it was given.
type hangingLLM struct {
	max time.Duration
	mu  sync.Mutex
	dl  []time.Duration // remaining time to the deadline at call start
}

func (h *hangingLLM) Complete(ctx context.Context, _ string, _ []LLMMessage) (string, string, error) {
	h.mu.Lock()
	if d, ok := ctx.Deadline(); ok {
		h.dl = append(h.dl, time.Until(d))
	} else {
		h.dl = append(h.dl, -1)
	}
	h.mu.Unlock()
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case <-time.After(h.max):
		return "a narrative that arrived far too late", "mock", nil
	}
}

// TestNarrationNeverBlocksAReadyAnswer is the lab's 82.9 s answer, reproduced:
// the evidence is ready, the provider hangs. Before this change the answer
// waited for the transport's 60 s client timeout; now it ships at the stage
// budget with the disclosure.
func TestNarrationNeverBlocksAReadyAnswer(t *testing.T) {
	cases := []struct {
		name, q string
		ctx     map[string]string
		budget  time.Duration
	}{
		{"current state (fast tier)", "what is going on right now", nil, 150 * time.Millisecond},
		{"module health (fast tier)", "show me the top talkers", nil, 150 * time.Millisecond},
		{"problem explanation (strong tier)", "explain problem pa", map[string]string{"problem_id": "pa"}, 250 * time.Millisecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ds := newMockDS()
			llm := &hangingLLM{max: 30 * time.Second}
			o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: llm, Flags: func(string) bool { return false },
				ModelBudgets: StageBudgets{Fast: 150 * time.Millisecond, Strong: 250 * time.Millisecond}}
			p := opsA()
			if c.ctx != nil {
				p = tenantA()
			}
			start := time.Now()
			ans, err := o.Ask(context.Background(), p, c.q, c.ctx)
			took := time.Since(start)
			if err != nil {
				t.Fatalf("ask: %v", err)
			}
			if len(llm.dl) == 0 {
				t.Fatal("the test did not reach a narration call — the case no longer exercises the budget")
			}
			if took > c.budget+2*time.Second {
				t.Fatalf("answer took %v with a %v stage budget — a hanging provider held the ready answer", took, c.budget)
			}
			if !ans.EvidenceOnly || strings.TrimSpace(ans.Text) == "" {
				t.Fatalf("the evidence answer must ship: evidence_only=%v text=%q", ans.EvidenceOnly, ans.Text)
			}
			if ans.ProviderNote != NoteModelTimedOut {
				t.Fatalf("provider note = %q, want %q", ans.ProviderNote, NoteModelTimedOut)
			}
			if ans.Model != "" {
				t.Fatalf("an evidence-only answer names no model, got %q", ans.Model)
			}
			t.Logf("hanging provider, %v budget → answered in %v", c.budget, took.Round(time.Millisecond))
		})
	}
}

// TestStageBudgetIsOnByDefault: a zero StageBudgets still bounds every model
// call — 8 s for the fast tier, 15 s for the strong tier.
func TestStageBudgetIsOnByDefault(t *testing.T) {
	for _, c := range []struct {
		q    string
		ctx  map[string]string
		p    Principal
		want time.Duration
	}{
		{"show me the top talkers", nil, opsA(), DefaultFastBudget},
		{"explain problem pa", map[string]string{"problem_id": "pa"}, tenantA(), DefaultStrongBudget},
	} {
		ds := newMockDS()
		llm := &hangingLLM{max: time.Millisecond} // answers at once; we only read the deadline
		o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: llm, Flags: func(string) bool { return false }}
		if _, err := o.Ask(context.Background(), c.p, c.q, c.ctx); err != nil {
			t.Fatal(err)
		}
		if len(llm.dl) == 0 {
			t.Fatalf("%q: no model call reached", c.q)
		}
		got := llm.dl[0]
		if got <= 0 || got > c.want || got < c.want-2*time.Second {
			t.Fatalf("%q: model call deadline %v, want ≈ %v (the default must be ON)", c.q, got, c.want)
		}
	}
}

func TestStageBudgetsForAndClamp(t *testing.T) {
	var zero StageBudgets
	if zero.For(TierFast) != DefaultFastBudget || zero.For(TierStrong) != DefaultStrongBudget || zero.For("") != DefaultStrongBudget {
		t.Fatalf("zero budgets must be the defaults: %v %v %v", zero.For(TierFast), zero.For(TierStrong), zero.For(""))
	}
	b := StageBudgets{Fast: 2 * time.Second, Strong: 10 * time.Minute}
	if b.For(TierFast) != 2*time.Second {
		t.Fatalf("configured fast = %v", b.For(TierFast))
	}
	if b.For(TierStrong) != MaxStageBudget {
		t.Fatalf("a configured budget is clamped to %v, got %v", MaxStageBudget, b.For(TierStrong))
	}
}

// failLLM returns a fixed error.
type failLLM struct{ err error }

func (f failLLM) Complete(context.Context, string, []LLMMessage) (string, string, error) {
	return "", "", f.err
}

func TestFallbackNoteNamesTheReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrProviderBreakerOpen, NoteModelPaused},
		{fmt.Errorf("wrapped: %w", ErrBudgetExhausted), NoteBudgetSpent},
		{fmt.Errorf("no AI provider answered: %w", context.DeadlineExceeded), NoteModelTimedOut},
		{errors.New("provider down"), ProviderFallbackNote(false)},
		{nil, ProviderFallbackNote(false)},
	}
	for _, c := range cases {
		if got := FallbackNoteFor(c.err); got != c.want {
			t.Errorf("FallbackNoteFor(%v) = %q, want %q", c.err, got, c.want)
		}
	}
	// End to end through an answer.
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: failLLM{ErrProviderBreakerOpen}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), opsA(), "show me the top talkers", nil)
	if err != nil || ans.ProviderNote != NoteModelPaused {
		t.Fatalf("paused provider: note=%q err=%v", ans.ProviderNote, err)
	}
}

// namingLLM answers and records the model on the request's note, as the root
// adapter does.
type namingLLM struct{}

func (namingLLM) Complete(ctx context.Context, _ string, _ []LLMMessage) (string, string, error) {
	NoteModelUsed(ctx, "gemini", "gemini-flash-latest")
	return "Two links on edge-1 are saturated.", "gemini", nil
}

func TestAnswerNamesTheModelThatAnswered(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: namingLLM{}, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), opsA(), "show me the top talkers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Provider != "gemini" || ans.Model != "gemini-flash-latest" {
		t.Fatalf("footnote fields: provider=%q model=%q", ans.Provider, ans.Model)
	}
	// A note for a DIFFERENT provider never labels this answer.
	ctx, n := WithModelNote(context.Background())
	NoteModelUsed(ctx, "openai", "gpt-4o-mini")
	if n.Model("gemini") != "" || n.Model("openai") != "gpt-4o-mini" {
		t.Fatal("ModelNote must match the provider that answered")
	}
	var nilNote *ModelNote
	if nilNote.Model("x") != "" {
		t.Fatal("nil note is empty")
	}
	NoteModelUsed(context.Background(), "x", "y") // no note: a no-op, no panic
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyProviderError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ProvOK},
		{&ProviderStatusError{Provider: "gemini", Status: 401}, ProvAuth},
		{&ProviderStatusError{Provider: "gemini", Status: 403}, ProvAuth},
		{&ProviderStatusError{Provider: "gemini", Status: 400, Reason: "API_KEY_INVALID"}, ProvAuth},
		{&ProviderStatusError{Provider: "gemini", Status: 404, Reason: "NOT_FOUND"}, ProvModelNotFound},
		{&ProviderStatusError{Provider: "gemini", Status: 400, Reason: "INVALID_ARGUMENT"}, ProvBadRequest},
		{&ProviderStatusError{Provider: "gemini", Status: 429}, ProvRateLimited},
		{&ProviderStatusError{Provider: "anthropic", Status: 529}, ProvServer},
		{&ProviderStatusError{Provider: "openai", Status: 504}, ProvTimeout},
		{&ProviderEmptyError{Provider: "gemini", FinishReason: "MAX_TOKENS"}, ProvEmpty},
		{fmt.Errorf("x: %w", context.DeadlineExceeded), ProvTimeout},
		{&url.Error{Op: "Post", URL: "https://x", Err: timeoutErr{}}, ProvTimeout},
		{context.Canceled, ProvCanceled},
		{&net.OpError{Op: "dial", Err: errors.New("connection refused")}, ProvNetwork},
		{&net.DNSError{Name: "x"}, ProvNetwork},
		{ErrProviderBreakerOpen, ProvBreakerOpen},
		{ErrBudgetExhausted, ProvBudget},
		{fmt.Errorf("none: %w", ErrNoProvider), ProvNoProvider},
		{errors.New("unexpected end of JSON input"), ProvError},
	}
	for _, c := range cases {
		if got := ClassifyProviderError(c.err); got != c.want {
			t.Errorf("ClassifyProviderError(%v) = %q, want %q", c.err, got, c.want)
		}
	}
	for _, o := range []string{ProvCanceled, ProvBreakerOpen, ProvBudget, ProvNoProvider, ProvOK} {
		if CountsAgainstProvider(o) {
			t.Errorf("%s must not move the breaker", o)
		}
	}
	for _, o := range []string{ProvTimeout, ProvAuth, ProvModelNotFound, ProvRateLimited, ProvServer, ProvEmpty, ProvNetwork} {
		if !CountsAgainstProvider(o) {
			t.Errorf("%s is the provider failing and must count", o)
		}
	}
	if ProviderStatusOf(&ProviderStatusError{Status: 404}) != 404 || ProviderStatusOf(errors.New("x")) != 0 {
		t.Fatal("ProviderStatusOf")
	}
	_ = http.StatusOK
}

// slowLLM answers after `delay` unless its context ends first.
type slowLLM struct{ delay time.Duration }

func (s slowLLM) Complete(ctx context.Context, _ string, _ []LLMMessage) (string, string, error) {
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case <-time.After(s.delay):
		return "narrated", "mock", nil
	}
}

// Live 2026-11-10 15:33Z: a page reload cancelled the request and the Gemini
// narration died 0.35 s in with "context canceled", silently. A narration now
// runs to its OWN budget regardless of the caller's cancellation, and the
// cancellation is logged.
func TestModelCallHonoursItsOwnBudgetNotTheCallersCancel(t *testing.T) {
	var logged []string
	restore := applog.SetObserver(func(_, component, msg string, _ map[string]any) {
		if component == "ai.provider" {
			logged = append(logged, msg)
		}
	})
	defer restore()
	o := &Orchestrator{LLM: slowLLM{delay: 150 * time.Millisecond}, ModelBudgets: StageBudgets{Fast: 2 * time.Second}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	text, _, err := o.completeTier(ctx, TierFast, "s", []LLMMessage{{Role: "user", Content: "q"}}, false)
	if err != nil || text != "narrated" {
		t.Fatalf("a cancelled caller must not kill the narration: text=%q err=%v", text, err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "cancelled while a model call ran") {
		t.Fatalf("the caller's cancellation must be logged, got %v", logged)
	}
}

// …but an earlier DEADLINE the caller set (a skill turn, a tie-break) still
// bounds the call.
func TestModelCallStillHonoursTheCallersDeadline(t *testing.T) {
	o := &Orchestrator{LLM: slowLLM{delay: 10 * time.Second}, ModelBudgets: StageBudgets{Fast: 5 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := o.completeTier(ctx, TierFast, "s", nil, false)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("the caller's earlier deadline must bound the call: err=%v after %v", err, time.Since(start))
	}
	// And context values survive the detachment (ledger, model note).
	vctx, n := WithModelNote(context.Background())
	mctx, mcancel := ModelCallContext(vctx, time.Second)
	defer mcancel()
	NoteModelUsed(mctx, "gemini", "m")
	if n.Model("gemini") != "m" {
		t.Fatal("ModelCallContext must keep the request's values")
	}
}
