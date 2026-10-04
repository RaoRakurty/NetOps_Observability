// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Validate that each provider's response shape is extracted correctly (the part
// most likely to break when a provider tweaks its API), using real-shaped bodies.
func TestParseOpenAI(t *testing.T) {
	body := `{"id":"x","choices":[{"message":{"role":"assistant","content":"Create inventory in NetBox."},"finish_reason":"stop"}],"model":"gpt-4o-mini"}`
	got, err := parseOpenAI([]byte(body))
	if err != nil || got.Text != "Create inventory in NetBox." || got.Usage.Reported {
		t.Fatalf("parseOpenAI = %+v, err=%v (no usage block → Reported must be false)", got, err)
	}
	if _, err := parseOpenAI([]byte(`{"choices":[]}`)); err == nil {
		t.Error("empty choices must error")
	}
	if _, err := parseOpenAI([]byte(`not json`)); err == nil {
		t.Error("malformed must error")
	}
}

func TestParseGemini(t *testing.T) {
	body := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Open "},{"text":"NetBox."}]}}]}`
	got, err := parseGemini([]byte(body))
	if err != nil || got.Text != "Open NetBox." || got.Usage.Reported {
		t.Fatalf("parseGemini = %+v, err=%v (no usage block → Reported must be false)", got, err)
	}
	if _, err := parseGemini([]byte(`{"candidates":[]}`)); err == nil {
		t.Error("no candidates must error")
	}
}

func TestParseAnthropic(t *testing.T) {
	body := `{"content":[{"type":"text","text":"NetBox is the source of truth."},{"type":"tool_use","id":"t"}],"role":"assistant"}`
	got, err := parseAnthropic([]byte(body))
	if err != nil || got.Text != "NetBox is the source of truth." || got.Usage.Reported {
		t.Fatalf("parseAnthropic = %+v, err=%v (no usage block → Reported must be false)", got, err)
	}
	if _, err := parseAnthropic([]byte(`{"content":[]}`)); err == nil {
		t.Error("no text blocks must error")
	}
}

// providerDo returns the body on 2xx and, on non-2xx, an error WITHOUT leaking the
// provider body to the caller (SR-022). Exercised against a local server.
func TestProviderDoSuccessAndRedaction(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer ok.Close()
	rb, err := ProviderDo(context.Background(), ok.URL, nil, []byte(`{}`), "test")
	if err != nil || string(rb) != `{"hello":"world"}` {
		t.Fatalf("2xx: rb=%q err=%v", rb, err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"secret-org-id leaked here"}}`))
	}))
	defer bad.Close()
	_, err = ProviderDo(context.Background(), bad.URL, nil, []byte(`{}`), "test")
	if err == nil {
		t.Fatal("non-2xx must return an error")
	}
	if strings.Contains(err.Error(), "secret-org-id") {
		t.Error("provider error body must NOT leak into the returned error (SR-022)")
	}
}

// Usage is the PROVIDER'S OWN accounting, read from each provider's usage
// block — never estimated. Real-shaped bodies.
func TestParseProviderUsage(t *testing.T) {
	cases := []struct {
		name string
		body string
		fn   func([]byte) (Completion, error)
		in   int64
		out  int64
	}{
		{"openai", `{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150}}`, parseOpenAI, 120, 30},
		{"gemini", `{"candidates":[{"content":{"parts":[{"text":"x"}]}}],"usageMetadata":{"promptTokenCount":80,"candidatesTokenCount":12,"totalTokenCount":92}}`, parseGemini, 80, 12},
		{"anthropic", `{"content":[{"type":"text","text":"x"}],"usage":{"input_tokens":200,"output_tokens":45}}`, parseAnthropic, 200, 45},
	}
	for _, c := range cases {
		got, err := c.fn([]byte(c.body))
		if err != nil || !got.Usage.Reported || got.Usage.InputTokens != c.in || got.Usage.OutputTokens != c.out {
			t.Errorf("%s: got %+v err=%v, want in=%d out=%d reported", c.name, got.Usage, err, c.in, c.out)
		}
	}
}

// withFastRetries makes the retry policy test-speed and returns the waits it
// was asked to sleep.
func withFastRetries(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	prevSleep, prevBase := providerSleep, providerBackoffBase
	providerSleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	providerBackoffBase = time.Millisecond
	t.Cleanup(func() { providerSleep, providerBackoffBase = prevSleep, prevBase })
	return &waits
}

// §9: a transient provider failure is retried with backoff, bounded.
func TestProviderDoRetriesTransientFailures(t *testing.T) {
	waits := withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	rb, err := ProviderDo(context.Background(), srv.URL, nil, []byte(`{}`), "test")
	if err != nil || string(rb) != `{"ok":true}` {
		t.Fatalf("want success on the third attempt, got rb=%q err=%v", rb, err)
	}
	if calls.Load() != 3 || len(*waits) != 2 {
		t.Fatalf("calls=%d waits=%d — want 3 attempts and 2 backoffs", calls.Load(), len(*waits))
	}
}

// A caller error is never retried — asking again cannot fix it.
func TestProviderDoDoesNotRetryCallerErrors(t *testing.T) {
	waits := withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	_, err := ProviderDo(context.Background(), srv.URL, nil, []byte(`{}`), "test")
	var se *ProviderStatusError
	if !errors.As(err, &se) || se.Status != http.StatusBadRequest {
		t.Fatalf("want a typed 400, got %v", err)
	}
	if calls.Load() != 1 || len(*waits) != 0 {
		t.Fatalf("a 400 must be tried once: calls=%d waits=%d", calls.Load(), len(*waits))
	}
}

// The attempt count is bounded, and Retry-After raises the wait (capped).
func TestProviderDoIsBoundedAndHonoursRetryAfter(t *testing.T) {
	waits := withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := ProviderDo(context.Background(), srv.URL, nil, []byte(`{}`), "test")
	if err == nil || int(calls.Load()) != providerMaxAttempts {
		t.Fatalf("calls=%d err=%v — want exactly %d attempts then an error", calls.Load(), err, providerMaxAttempts)
	}
	for _, w := range *waits {
		if w != providerRetryAfterCap {
			t.Fatalf("a 60 s Retry-After must be honoured but capped at %v, got %v", providerRetryAfterCap, w)
		}
	}
}

// A cancelled context stops the loop — no sleep outlasts the caller.
func TestProviderDoStopsOnCancel(t *testing.T) {
	prevSleep := providerSleep
	t.Cleanup(func() { providerSleep = prevSleep })
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := ProviderDo(ctx, srv.URL, nil, []byte(`{}`), "test"); err == nil {
		t.Fatal("a cancelled call must fail")
	}
	if calls.Load() != 1 {
		t.Fatalf("after cancel there must be no further attempt, got %d", calls.Load())
	}
}

func TestProviderBackoffIsBoundedFullJitter(t *testing.T) {
	for n := 1; n <= 10; n++ {
		for i := 0; i < 50; i++ {
			if d := providerBackoff(n, 0); d < 0 || d > providerBackoffCap {
				t.Fatalf("backoff(%d) = %v outside [0, %v]", n, d, providerBackoffCap)
			}
		}
	}
}

// A provider that hangs to the client timeout is NOT retried — the chain falls
// through to the next provider instead of waiting another full timeout.
func TestProviderDoDoesNotRetryATimeout(t *testing.T) {
	waits := withFastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-time.After(500 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	restore := SwapProviderHTTPForTest(&http.Client{Timeout: 50 * time.Millisecond})
	defer restore()
	if _, err := ProviderDo(context.Background(), srv.URL, nil, []byte(`{}`), "test"); err == nil {
		t.Fatal("a timed-out call must fail")
	}
	if calls.Load() != 1 || len(*waits) != 0 {
		t.Fatalf("a timeout must not be retried: calls=%d waits=%d", calls.Load(), len(*waits))
	}
}
