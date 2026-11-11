// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type egressCapture struct{ body []byte }

func (c *egressCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		c.body, _ = io.ReadAll(r.Body)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)),
		Header: http.Header{"Content-Type": []string{"application/json"}}, Request: r}, nil
}

// The request context's scrub runs on the payload, after the pattern sweep, and
// what it returns is what leaves.
func TestProviderDoAppliesTheContextScrubLast(t *testing.T) {
	cap := &egressCapture{}
	restore := SwapProviderHTTPForTest(&http.Client{Transport: cap})
	defer restore()
	value := "fixture-comm-" + strings.Repeat("q", 6)
	var seen []byte
	scrub := func(b []byte) []byte {
		seen = append([]byte(nil), b...)
		return bytes.ReplaceAll(b, []byte(value), []byte(Mask))
	}
	ctx := WithEgressScrub(context.Background(), scrub)
	raw := []byte(`{"m":"poller ` + value + ` password=hunter2"}`)
	if _, err := ProviderDo(ctx, "https://api.openai.com/v1/chat/completions", nil, raw, "openai"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(seen), "hunter2") {
		t.Errorf("the scrub ran before the pattern sweep: %s", seen)
	}
	if strings.Contains(string(cap.body), value) || !strings.Contains(string(cap.body), "poller "+Mask) {
		t.Errorf("payload = %s", cap.body)
	}
}

// Without a context scrub the boot-time default applies, so a background job
// (context.Background()) cannot bypass the last line; a context scrub wins.
func TestProviderDoFallsBackToTheDefaultScrub(t *testing.T) {
	cap := &egressCapture{}
	restore := SwapProviderHTTPForTest(&http.Client{Transport: cap})
	defer restore()
	value := "fixture-comm-" + strings.Repeat("q", 6)
	SetDefaultEgressScrub(func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(value), []byte(Mask)) })
	t.Cleanup(func() { SetDefaultEgressScrub(nil) })
	raw := []byte(`{"m":"poller ` + value + `"}`)
	if _, err := ProviderDo(context.Background(), "https://api.openai.com/v1/chat/completions", nil, raw, "openai"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cap.body), value) {
		t.Fatalf("a background call bypassed the default scrub: %s", cap.body)
	}
	marker := []byte("context-scrub-ran")
	ctx := WithEgressScrub(context.Background(), func(b []byte) []byte { return append(b, marker...) })
	if _, err := ProviderDo(ctx, "https://api.openai.com/v1/chat/completions", nil, raw, "openai"); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(cap.body, marker) {
		t.Errorf("the context scrub did not take precedence: %s", cap.body)
	}
	SetDefaultEgressScrub(nil)
	if egressScrubFrom(context.Background()) != nil {
		t.Error("SetDefaultEgressScrub(nil) left a default")
	}
}

func TestWithEgressScrubNilAndAbsent(t *testing.T) {
	ctx := context.Background()
	if WithEgressScrub(ctx, nil) != ctx {
		t.Error("a nil scrub must leave the context unchanged")
	}
	if egressScrubFrom(ctx) != nil {
		t.Error("a bare context carries no scrub")
	}
}
