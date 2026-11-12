// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// gemini_wire_test.go — the Gemini request Correlix builds and how it reads
// Gemini's answers, against a fake server speaking Gemini's real shapes
// (Iris latency batch 2026-11-10: two lab calls failed and nothing said why).
//
//   - the key travels in x-goog-api-key, NEVER in the URL (a transport error
//     prints the URL, so a key in the query string reached the failure log);
//   - "models/" prefixes are tolerated;
//   - each Gemini error shape maps onto the right class with the provider's
//     own reason (NOT_FOUND, API_KEY_INVALID, RESOURCE_EXHAUSTED);
//   - a 200 with no text (the output cap spent on thinking, a blocked prompt)
//     is an error naming the reason, not a silent empty "success".

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type geminiFake struct {
	mu      sync.Mutex
	paths   []string
	queries []string
	keys    []string
	bodies  []string
	status  int
	body    string
}

func (g *geminiFake) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	g.paths = append(g.paths, r.URL.Path)
	g.queries = append(g.queries, r.URL.RawQuery)
	g.keys = append(g.keys, r.Header.Get("x-goog-api-key"))
	g.bodies = append(g.bodies, string(b))
	st, body := g.status, g.body
	g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(st)
	_, _ = io.WriteString(w, body)
}

func startGeminiFake(t *testing.T, status int, body string) *geminiFake {
	t.Helper()
	g := &geminiFake{status: status, body: body}
	srv := httptest.NewServer(http.HandlerFunc(g.handler))
	t.Cleanup(srv.Close)
	t.Cleanup(SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	prevSleep := providerSleep
	providerSleep = func(context.Context, time.Duration) error { return nil } // no real backoff in tests
	t.Cleanup(func() { providerSleep = prevSleep })
	return g
}

const geminiTestKey = "AIzaSyTEST-not-a-real-key-0123456789"

func TestGeminiKeyRidesInTheHeaderNeverTheURL(t *testing.T) {
	g := startGeminiFake(t, 200, `{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":1,"totalTokenCount":13}}`)
	c, err := CallProviderUsage(context.Background(), "gemini", geminiTestKey, "models/gemini-flash-latest", "sys", []ChatMessage{{Role: "user", Content: "q"}})
	if err != nil || c.Text != "OK" || !c.Usage.Reported || c.Usage.InputTokens != 12 {
		t.Fatalf("completion = %+v err=%v", c, err)
	}
	if g.keys[0] != geminiTestKey {
		t.Fatalf("x-goog-api-key = %q", g.keys[0])
	}
	if strings.Contains(g.queries[0], "key") || strings.Contains(g.queries[0], geminiTestKey) {
		t.Fatalf("the key must not be in the URL: query %q", g.queries[0])
	}
	if g.paths[0] != "/v1beta/models/gemini-flash-latest:generateContent" {
		t.Fatalf("path = %q (a models/ prefix must not double up)", g.paths[0])
	}
	if !strings.Contains(g.bodies[0], `"system_instruction"`) || !strings.Contains(g.bodies[0], `"maxOutputTokens"`) {
		t.Fatalf("request shape changed: %s", g.bodies[0])
	}
}

// A transport failure's message must not carry the key either (it is what the
// failure log prints).
func TestGeminiTransportErrorDoesNotLeakTheKey(t *testing.T) {
	t.Cleanup(SwapGeminiBaseForTest("http://127.0.0.1:1/v1beta/models/")) // nothing listens on port 1
	prevSleep := providerSleep
	providerSleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { providerSleep = prevSleep })
	_, err := CallProviderUsage(context.Background(), "gemini", geminiTestKey, "gemini-flash-latest", "s", []ChatMessage{{Role: "user", Content: "q"}})
	if err == nil {
		t.Fatal("want a connection error")
	}
	if strings.Contains(err.Error(), geminiTestKey) {
		t.Fatalf("KEY LEAK in the error message: %v", err)
	}
	if ClassifyProviderError(err) != ProvNetwork {
		t.Fatalf("class = %q, want network (%v)", ClassifyProviderError(err), err)
	}
}

func TestGeminiErrorShapesClassify(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		class      string
		reason     string
		wantFinish string
		wantBlock  string
	}{
		{"model not found", 404,
			`{"error":{"code":404,"message":"models/gemini-9-flash is not found for API version v1beta, or is not supported for generateContent.","status":"NOT_FOUND"}}`,
			ProvModelNotFound, "NOT_FOUND", "", ""},
		{"invalid key", 400,
			`{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com"}]}}`,
			ProvAuth, "API_KEY_INVALID", "", ""},
		{"permission denied", 403,
			`{"error":{"code":403,"message":"Method doesn't allow unregistered callers.","status":"PERMISSION_DENIED"}}`,
			ProvAuth, "PERMISSION_DENIED", "", ""},
		{"quota", 429,
			`{"error":{"code":429,"message":"You exceeded your current quota.","status":"RESOURCE_EXHAUSTED"}}`,
			ProvRateLimited, "RESOURCE_EXHAUSTED", "", ""},
		{"bad field", 400,
			`{"error":{"code":400,"message":"Invalid JSON payload received. Unknown name \"foo\"","status":"INVALID_ARGUMENT"}}`,
			ProvBadRequest, "INVALID_ARGUMENT", "", ""},
		{"thinking spent the output cap", 200,
			`{"candidates":[{"content":{"role":"model"},"finishReason":"MAX_TOKENS","index":0}],"usageMetadata":{"promptTokenCount":3100,"totalTokenCount":4124,"thoughtsTokenCount":1024}}`,
			ProvEmpty, "", "MAX_TOKENS", ""},
		{"prompt blocked", 200,
			`{"promptFeedback":{"blockReason":"SAFETY"},"usageMetadata":{"promptTokenCount":40,"totalTokenCount":40}}`,
			ProvEmpty, "", "", "SAFETY"},
		{"only a thought part", 200,
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"pondering…","thought":true}]},"finishReason":"MAX_TOKENS"}]}`,
			ProvEmpty, "", "MAX_TOKENS", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := startGeminiFake(t, c.status, c.body)
			_, err := CallProviderUsage(context.Background(), "gemini", geminiTestKey, "gemini-flash-latest", "s", []ChatMessage{{Role: "user", Content: "q"}})
			if err == nil {
				t.Fatal("want an error")
			}
			if got := ClassifyProviderError(err); got != c.class {
				t.Fatalf("class = %q, want %q (%v)", got, c.class, err)
			}
			var se *ProviderStatusError
			if c.reason != "" && (!errors.As(err, &se) || se.Reason != c.reason) {
				t.Fatalf("reason = %+v, want %q", se, c.reason)
			}
			var ee *ProviderEmptyError
			if c.class == ProvEmpty {
				if !errors.As(err, &ee) || ee.FinishReason != c.wantFinish || ee.BlockReason != c.wantBlock {
					t.Fatalf("empty error = %+v", ee)
				}
			}
			if strings.Contains(err.Error(), "API key not valid") || strings.Contains(err.Error(), "quota") {
				t.Fatalf("the provider's message text must not ride the error: %v", err)
			}
			if c.status == 429 && len(g.paths) != providerMaxAttempts {
				t.Fatalf("a 429 is retried (%d attempts), got %d", providerMaxAttempts, len(g.paths))
			}
			if (c.status == 400 || c.status == 403 || c.status == 404) && len(g.paths) != 1 {
				t.Fatalf("a caller error is never retried, got %d attempts", len(g.paths))
			}
		})
	}
}

func TestOpenAIAndAnthropicEmptyRepliesAreErrors(t *testing.T) {
	if _, err := parseOpenAI([]byte(`{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}]}`)); ClassifyProviderError(err) != ProvEmpty {
		t.Fatalf("openai empty: %v", err)
	}
	_, err := parseAnthropic([]byte(`{"content":[],"stop_reason":"max_tokens"}`))
	var ee *ProviderEmptyError
	if !errors.As(err, &ee) || ee.FinishReason != "max_tokens" || !strings.HasPrefix(err.Error(), "anthropic: empty response") {
		t.Fatalf("anthropic empty: %v", err)
	}
	if enumOnly("free text with spaces") != "" || enumOnly("MAX_TOKENS") != "MAX_TOKENS" {
		t.Fatal("enumOnly keeps identifiers only")
	}
}

// Lab, 2026-11-12: Google answered 503 "high demand" for gemini-flash-latest,
// the client retried, and the 10 s test budget ran out on the retry. That read
// as "timeout" and the settings page told the operator to check the server's
// internet access while another model answered the same key in 0.8 s. When
// time runs out AFTER the provider's own retryable answer, the class is the
// provider's (server_error, http 503); the deadline stays visible in the chain.
func TestDeadlineAfterAnOverloadedAnswerReadsAsTheProvidersAnswer(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"code":503,"message":"This model is currently experiencing high demand.","status":"UNAVAILABLE"}}`)
			return
		}
		_, _ = io.ReadAll(r.Body) // the server notices the client leaving only once the body is read
		<-r.Context().Done()      // the retry hangs until the caller's deadline
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	prevSleep := providerSleep
	providerSleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { providerSleep = prevSleep })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := CallProviderUsage(ctx, "gemini", geminiTestKey, "gemini-flash-latest", "s", []ChatMessage{{Role: "user", Content: "q"}})
	if err == nil {
		t.Fatal("want an error")
	}
	srv.CloseClientConnections()
	if got := ClassifyProviderError(err); got != ProvServer {
		t.Fatalf("class = %q, want server_error: %v", got, err)
	}
	if ProviderStatusOf(err) != http.StatusServiceUnavailable {
		t.Fatalf("http status = %d, want 503", ProviderStatusOf(err))
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the deadline must stay in the chain: %v", err)
	}
	if strings.Contains(err.Error(), geminiTestKey) {
		t.Fatalf("KEY LEAK: %v", err)
	}
}

// A provider that never answered at all is still a timeout, and a caller that
// left after a 503 is still a cancellation (nobody's failure).
func TestPlainHangStaysTimeoutAndCancelStaysCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := CallProviderUsage(ctx, "gemini", geminiTestKey, "m", "s", []ChatMessage{{Role: "user", Content: "q"}})
	if got := ClassifyProviderError(err); got != ProvTimeout {
		t.Fatalf("a provider that never answered: class %q, want timeout (%v)", got, err)
	}
	if e := withPriorStatus(context.Canceled, &ProviderStatusError{Status: 503}); !errors.Is(e, context.Canceled) || ProviderStatusOf(e) != 0 {
		t.Fatal("a cancellation after a 503 must stay a cancellation")
	}
	if e := withPriorStatus(errors.New("decode"), &ProviderStatusError{Status: 503}); ClassifyProviderError(e) != ProvError {
		t.Fatal("only a deadline borrows the prior status")
	}
}
