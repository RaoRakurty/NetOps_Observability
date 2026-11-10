// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// failingTransport records the request it was handed and fails it the way a
// cancelled or unreachable call does, so the error carries a *url.Error.
type failingTransport struct{ got *http.Request }

func (f *failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.got = r
	return nil, context.Canceled
}

// Found live 2026-11-10: a failed Gemini call logged
// "Post https://…:generateContent?key=<the API key>: context canceled", because
// the key travelled in the URL and *url.Error embeds the URL. The key must
// travel in the x-goog-api-key header, and no failed call may carry it in its
// error (which is what gets logged and returned).
func TestGeminiKeyTravelsInTheHeaderAndNeverInAnError(t *testing.T) {
	// A low-entropy placeholder built at run time, so no key-shaped literal
	// lives in the repo (gitleaks scans the full history).
	key := "placeholder-" + strings.Repeat("x", 16)
	ft := &failingTransport{}
	restore := SwapProviderHTTPForTest(&http.Client{Transport: ft})
	defer restore()

	_, err := callGemini(context.Background(), key, "gemini-flash-latest", "sys", []ChatMessage{{Role: "user", Content: "hi"}})
	if err == nil {
		t.Fatal("the transport failed, so the call must fail")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("the API key leaked into the error (and so into the log): %v", err)
	}
	if ft.got == nil {
		t.Fatal("no request reached the transport")
	}
	if strings.Contains(ft.got.URL.String(), key) || ft.got.URL.Query().Get("key") != "" {
		t.Fatalf("the API key is in the request URL: %s", ft.got.URL.Redacted())
	}
	if got := ft.got.Header.Get("x-goog-api-key"); got != key {
		t.Fatalf("x-goog-api-key header = %q, want the key", got)
	}
}

func TestScrubURLErrorDropsQueryUserinfoAndFragment(t *testing.T) {
	in := &url.Error{Op: "Post", URL: "https://user:pw@example.com/v1/x:gen?key=SECRET&a=b#frag", Err: context.Canceled}
	out := scrubURLError(in)
	s := out.Error()
	for _, bad := range []string{"SECRET", "user:pw", "frag", "?"} {
		if strings.Contains(s, bad) {
			t.Errorf("scrubbed error still contains %q: %s", bad, s)
		}
	}
	if !strings.Contains(s, "https://example.com/v1/x:gen") || !errors.Is(out, context.Canceled) {
		t.Errorf("scrubbed error lost its useful parts: %s", s)
	}
	plain := errors.New("not a url error")
	if !errors.Is(scrubURLError(plain), plain) {
		t.Error("a non-URL error must pass through unchanged")
	}
}
