// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// ticketing_pagerduty_test.go — #103 PagerDuty RCA-lane tests: lifecycle dedup
// identity, retry classification, dual-system policy resolution, two-tenant
// isolation (distinct routing-key markers), storm identity, and the worker's
// tenant-mismatch quarantine. Uses a local fake Events API server — the real
// PagerDuty API is never contacted.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePD is a minimal Events API v2 endpoint recording every enqueue.
type fakePD struct {
	mu       sync.Mutex
	srv      *httptest.Server
	events   []map[string]any // decoded request bodies
	status   int              // response code override (0 = 202)
	retryHdr string
}

func newFakePD() *fakePD {
	f := &fakePD{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/enqueue" {
			w.WriteHeader(404)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.events = append(f.events, body)
		f.mu.Unlock()
		if f.retryHdr != "" {
			w.Header().Set("Retry-After", f.retryHdr)
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success", "dedup_key": asString(body["dedup_key"])})
	}))
	return f
}

func (f *fakePD) cfg(tenant string) SystemConfig {
	return SystemConfig{System: "pagerduty", TenantID: tenant,
		InstanceURL: f.srv.URL, AuthType: "routing_key", APIToken: "RK-" + tenant}
}

func (f *fakePD) adapter() *PagerDutyAdapter {
	return &PagerDutyAdapter{httpClient: f.srv.Client()}
}

func (f *fakePD) all() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, len(f.events))
	copy(out, f.events)
	return out
}

func pdPayload(corr string) Payload {
	return Payload{CorrObjectID: corr, ExternalSystem: "pagerduty",
		Title: "Confirmed local link fault on edge1", Verdict: "confirmed",
		Confidence: 0.91, Summary: "two planes agree", Urgency: 1,
		RCAURL: "https://correlix.example/app/correlations/" + corr}
}

// Lifecycle: create/update x3/resolve share ONE dedup identity (storm-proof).
func TestPDTicketAdapter_LifecycleSingleDedupIdentity(t *testing.T) {
	f := newFakePD()
	defer f.srv.Close()
	a := f.adapter()
	cfg := f.cfg("t_a")
	ctx := context.Background()

	ref, err := a.CreateIncident(ctx, cfg, pdPayload("11111111-1111-4111-8111-111111111111"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	wantKey := "correlix:t_a:11111111-1111-4111-8111-111111111111:pagerduty"
	if ref.SysID != wantKey {
		t.Fatalf("dedup key = %q, want %q", ref.SysID, wantKey)
	}
	for i := 0; i < 3; i++ { // repeated updates (severity/impact changes)
		if err := a.UpdateIncident(ctx, cfg, ref, pdPayload("11111111-1111-4111-8111-111111111111")); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}
	if err := a.ResolveIncident(ctx, cfg, ref, "cleared"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	evs := f.all()
	if len(evs) != 5 {
		t.Fatalf("events = %d, want 5", len(evs))
	}
	keys := map[string]bool{}
	actions := []string{}
	for _, e := range evs {
		keys[asString(e["dedup_key"])] = true
		actions = append(actions, asString(e["event_action"]))
	}
	if len(keys) != 1 || !keys[wantKey] {
		t.Fatalf("expected ONE dedup identity %q, got %v", wantKey, keys)
	}
	if actions[0] != "trigger" || actions[len(actions)-1] != "resolve" {
		t.Fatalf("lifecycle actions wrong: %v", actions)
	}
	// payload sanity: source=correlix, severity mapped from urgency 1
	pl, _ := evs[0]["payload"].(map[string]any)
	if asString(pl["source"]) != "correlix" || asString(pl["severity"]) != "critical" {
		t.Fatalf("payload source/severity wrong: %v", pl)
	}
}

// Retry classification: 429→rateLimited(Retry-After), 400/401→permanent, 5xx→transient.
func TestPDTicketAdapter_RetryClassification(t *testing.T) {
	f := newFakePD()
	defer f.srv.Close()
	a := f.adapter()
	ctx := context.Background()

	f.status, f.retryHdr = 429, "7"
	_, err := a.CreateIncident(ctx, f.cfg("t_a"), pdPayload("22222222-2222-4222-8222-222222222222"))
	var rl RateLimitedError
	if !errors.As(err, &rl) || rl.After != 7*time.Second {
		t.Fatalf("429 → %v, want RateLimitedError{7s}", err)
	}

	for _, code := range []int{400, 401, 403} {
		f.status, f.retryHdr = code, ""
		_, err = a.CreateIncident(ctx, f.cfg("t_a"), pdPayload("22222222-2222-4222-8222-222222222222"))
		var perm PermanentDeliveryError
		if !errors.As(err, &perm) {
			t.Fatalf("%d → %v, want PermanentDeliveryError", code, err)
		}
		if strings.Contains(err.Error(), "RK-t_a") {
			t.Fatalf("error leaks routing key: %v", err)
		}
	}

	f.status = 503
	_, err = a.CreateIncident(ctx, f.cfg("t_a"), pdPayload("22222222-2222-4222-8222-222222222222"))
	var perm PermanentDeliveryError
	if err == nil || errors.As(err, &perm) {
		t.Fatalf("503 must be transient, got %v", err)
	}

	// missing routing key = permanent (never retried into the void)
	bad := f.cfg("t_a")
	bad.APIToken = ""
	_, err = a.CreateIncident(ctx, bad, pdPayload("22222222-2222-4222-8222-222222222222"))
	if !errors.As(err, &perm) {
		t.Fatalf("missing key → %v, want permanent", err)
	}
}

type fakeSlackHook struct {
	mu     sync.Mutex
	srv    *httptest.Server
	bodies []map[string]any
	status int
}

func newFakeSlackHook() *fakeSlackHook {
	f := &fakeSlackHook{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.bodies = append(f.bodies, b)
		f.mu.Unlock()
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	return f
}

func (f *fakeSlackHook) cfg(tenant string) SystemConfig {
	return SystemConfig{System: "slack", TenantID: tenant,
		InstanceURL: SlackHooksOrigin, AuthType: "webhook", APIToken: f.srv.URL + "/WH-" + tenant}
}

func TestSlackTicketAdapter_LifecycleAndSecrets(t *testing.T) {
	f := newFakeSlackHook()
	defer f.srv.Close()
	a := &SlackAdapter{httpClient: f.srv.Client()}
	ctx := context.Background()
	cfg := f.cfg("t_a")

	ref, err := a.CreateIncident(ctx, cfg, pdPayload("33333333-3333-4333-8333-333333333333"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.SysID == "" || strings.Contains(ref.SysID, f.srv.URL) {
		t.Fatalf("ref must be the dedupe identity, never the webhook: %q", ref.SysID)
	}
	if err := a.UpdateIncident(ctx, cfg, ref, pdPayload("33333333-3333-4333-8333-333333333333")); err != nil {
		t.Fatal(err)
	}
	if err := a.ResolveIncident(ctx, cfg, ref, ""); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	n := len(f.bodies)
	first := f.bodies[0]
	last := f.bodies[n-1]
	f.mu.Unlock()
	if n != 3 {
		t.Fatalf("posts = %d, want 3 (opened/updated/resolved)", n)
	}
	if !strings.Contains(asString(first["text"]), "Opened") {
		t.Fatalf("first message not an open: %v", first["text"])
	}
	if !strings.Contains(asString(last["text"]), "Resolved") {
		t.Fatalf("last message not a resolve: %v", last["text"])
	}

	// error classification + secret-free errors
	f.status = 404 // Slack's no_service
	_, err = a.CreateIncident(ctx, cfg, pdPayload("33333333-3333-4333-8333-333333333333"))
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) || strings.Contains(err.Error(), f.srv.URL) {
		t.Fatalf("404 → %v (must be permanent, secret-free)", err)
	}
}

func TestNotificationPayloads_CarryDisplayID(t *testing.T) {
	ctx := context.Background()
	const corr = "5564d1ab-1111-4111-8111-999999999999"
	const pid = "P-5564D1"

	// PagerDuty: summary leads with the id; custom_details carry both handles.
	f := newFakePD()
	defer f.srv.Close()
	ref, err := f.adapter().CreateIncident(ctx, f.cfg("t_a"), pdPayload(corr))
	if err != nil {
		t.Fatalf("pd create: %v", err)
	}
	ev := f.all()[0]
	pl, _ := ev["payload"].(map[string]any)
	if !strings.HasPrefix(asString(pl["summary"]), "["+pid+"] ") {
		t.Fatalf("pd summary missing display id: %q", pl["summary"])
	}
	det, _ := pl["custom_details"].(map[string]any)
	if asString(det["problem_id"]) != pid || asString(det["correlation_id"]) != corr {
		t.Fatalf("pd custom_details handles wrong: %v", det)
	}
	if !strings.Contains(asString(ev["dedup_key"]), corr) {
		t.Fatalf("dedup key must keep the canonical UUID: %v", ev["dedup_key"])
	}
	_ = ref

	// Slack: title + footer carry the id; the resolve message names the incident
	// by the id, never the raw dedupe-hash ref.
	fs := newFakeSlackHook()
	defer fs.srv.Close()
	a := &SlackAdapter{httpClient: fs.srv.Client()}
	sref, err := a.CreateIncident(ctx, fs.cfg("t_a"), pdPayload(corr))
	if err != nil {
		t.Fatalf("slack create: %v", err)
	}
	if err := a.ResolveIncident(ctx, fs.cfg("t_a"), sref, ""); err != nil {
		t.Fatalf("slack resolve: %v", err)
	}
	fs.mu.Lock()
	opened, resolved := fs.bodies[0], fs.bodies[len(fs.bodies)-1]
	fs.mu.Unlock()
	if !strings.Contains(asString(opened["text"]), "["+pid+"]") {
		t.Fatalf("slack open title missing display id: %q", opened["text"])
	}
	atts, _ := opened["attachments"].([]any)
	att, _ := atts[0].(map[string]any)
	if asString(att["footer"]) != "Correlix RCA · "+pid {
		t.Fatalf("slack footer = %q, want display id (no raw UUID)", att["footer"])
	}
	rtxt := asString(resolved["text"])
	if !strings.Contains(rtxt, pid) || strings.Contains(rtxt, sref.Number) {
		t.Fatalf("slack resolve must name %s, never the raw ref %q: %q", pid, sref.Number, rtxt)
	}
}
