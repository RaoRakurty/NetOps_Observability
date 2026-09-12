// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// rtFunc is a RoundTripper backed by a function.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mkResp(status int, hdr map[string]string, body string) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

func TestRetryDoerRetriesOn429ThenSucceeds(t *testing.T) {
	var calls int
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return mkResp(429, map[string]string{"Retry-After": "2"}, "slow down"), nil
		}
		return mkResp(200, nil, "ok"), nil
	})}
	var slept time.Duration
	d := NewRetryDoer(client, NewTokenBucket(0), DefaultRetry())
	d.sleep = func(_ context.Context, dur time.Duration) error { slept += dur; return nil }

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x/api", nil)
	resp, err := d.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("expected 200 after retry: %v %v", resp, err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	if slept != 2*time.Second {
		t.Fatalf("should have honored Retry-After=2s, slept %v", slept)
	}
}

func TestRetryDoerGivesUpAfterMaxTries(t *testing.T) {
	var calls int
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return mkResp(503, nil, "down"), nil
	})}
	d := NewRetryDoer(client, NewTokenBucket(0), ExpoRetry{Base: time.Millisecond, Max: time.Second, MaxTries: 3})
	d.sleep = func(context.Context, time.Duration) error { return nil }
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", nil)
	resp, err := d.Do(req)
	// Returns the final 503 (not an error) for the caller to inspect.
	if err != nil || resp.StatusCode != 503 {
		t.Fatalf("expected final 503: %v %v", resp, err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryDoer4xxNoRetry(t *testing.T) {
	var calls int
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return mkResp(404, nil, "nope"), nil
	})}
	d := NewRetryDoer(client, NewTokenBucket(0), DefaultRetry())
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x", nil)
	resp, _ := d.Do(req)
	if resp.StatusCode != 404 || calls != 1 {
		t.Fatalf("404 must not retry: status=%d calls=%d", resp.StatusCode, calls)
	}
}

func TestPipelineRoutesThreeClasses(t *testing.T) {
	p := NewPipeline(100)
	t0 := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	b := Batch{
		Metrics: []ControllerMetric{
			{Name: "controller_metric_loss_pct", Value: 3, Tags: map[string]string{"device": "r1"}, Time: t0},
			{Name: "", Value: 9}, // nameless → dropped
		},
		States: []ControllerState{
			{IntegrationID: "i", EntityKey: "t1", StateKind: "tunnel", CurrentState: "up", Time: t0},
		},
		Events: []ControllerEvent{
			{IntegrationID: "i", EventID: "e1", NormalizedEventType: "controller_alarm"},
			{IntegrationID: "i", EventID: "e1"}, // dup
		},
	}
	out := p.Route(b)
	if len(out.MetricLines) != 1 {
		t.Fatalf("metrics: want 1 line, got %d", len(out.MetricLines))
	}
	if len(out.Events) != 1 {
		t.Fatalf("events: dedupe failed, got %d", len(out.Events))
	}
	if len(out.StateChanges) != 0 {
		t.Fatalf("first-sighting state must not emit a change, got %d", len(out.StateChanges))
	}
	// A transition now emits a change.
	out2 := p.Route(Batch{States: []ControllerState{
		{IntegrationID: "i", EntityKey: "t1", StateKind: "tunnel", CurrentState: "down", Time: t0.Add(time.Minute)},
	}})
	if len(out2.StateChanges) != 1 || out2.StateChanges[0].To != "down" {
		t.Fatalf("transition change wrong: %+v", out2.StateChanges)
	}
}
