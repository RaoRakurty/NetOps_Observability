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
