// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"netops/backend/models"
)

// TestPagerDutySend proves the PagerDuty channel fires a well-formed Events API
// v2 trigger (local fake server; the endpoint var is redirected for the test).
func TestPagerDutySend(t *testing.T) {
	var calls int32
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	orig := pagerDutyEventsV2URL
	pagerDutyEventsV2URL = srv.URL
	defer func() { pagerDutyEventsV2URL = orig }()

	p := NewPagerDuty("routing-key-123")
	if err := p.Send(models.Alert{ID: "a1", Rule: "CPUHigh", Severity: "critical", Summary: "CPU 99% on spine1", DeviceID: "spine1"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if calls != 1 {
		t.Fatalf("events api calls = %d, want 1", calls)
	}
	if body["routing_key"] != "routing-key-123" || body["event_action"] != "trigger" || body["dedup_key"] != "a1" {
		t.Errorf("unexpected pagerduty envelope: %+v", body)
	}
	payload, _ := body["payload"].(map[string]any)
	if payload == nil || payload["summary"] != "CPU 99% on spine1" || payload["severity"] != "critical" {
		t.Errorf("unexpected pagerduty payload: %+v", payload)
	}
}

func TestPagerDutySendUnconfigured(t *testing.T) {
	if err := NewPagerDuty("").Send(models.Alert{Severity: "critical"}); err == nil {
		t.Fatal("expected error when routing key is empty")
	}
}

// TestPagerDutySendNormalizesPayload pins the Events v2 validity rules that a
// live 400 exposed (2026-07-11): source must never be empty (test alerts have
// no DeviceID) and severity must land in the v2 enum (critical|error|warning|
// info) — "notice"/"warn"/"crit" style platform values are mapped, never sent raw.
func TestPagerDutySendNormalizesPayload(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()
	orig := pagerDutyEventsV2URL
	pagerDutyEventsV2URL = srv.URL
	defer func() { pagerDutyEventsV2URL = orig }()

	p := NewPagerDuty("rk")
	// No DeviceID (the channel-test shape) + a non-enum severity.
	if err := p.Send(models.Alert{ID: "t1", Severity: "notice", Summary: "test"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	payload, _ := body["payload"].(map[string]any)
	if payload["source"] == "" || payload["source"] == nil {
		t.Fatalf("source must never be empty, got %v", payload["source"])
	}
	if payload["severity"] != "info" {
		t.Fatalf("severity notice must map to info, got %v", payload["severity"])
	}

	for in, want := range map[string]string{
		"critical": "critical", "crit": "critical", "error": "error",
		"warn": "warning", "high": "warning", "notice": "info", "": "info", "weird": "warning",
	} {
		if got := pdSeverity(in); got != want {
			t.Fatalf("pdSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPagerDutySendResolve pins the resolution event: same dedup key, action
// resolve, no payload required — this is what closes the PD incident when the
// alert clears (2026-07-11: without it incidents accumulated forever).
func TestPagerDutySendResolve(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()
	orig := pagerDutyEventsV2URL
	pagerDutyEventsV2URL = srv.URL
	defer func() { pagerDutyEventsV2URL = orig }()

	p := NewPagerDuty("rk")
	if err := p.SendResolve(models.Alert{ID: "a1"}); err != nil {
		t.Fatalf("SendResolve: %v", err)
	}
	if body["event_action"] != "resolve" || body["dedup_key"] != "a1" || body["routing_key"] != "rk" {
		t.Fatalf("unexpected resolve envelope: %+v", body)
	}
	// A severity gate must pass resolves through to the wrapped channel.
	body = nil
	gated := NewSeverityGate(p, "critical")
	if err := gated.SendResolve(models.Alert{ID: "a2", Severity: "info"}); err != nil {
		t.Fatalf("gated SendResolve: %v", err)
	}
	if body["dedup_key"] != "a2" {
		t.Fatalf("severity gate swallowed the resolve: %+v", body)
	}
}
