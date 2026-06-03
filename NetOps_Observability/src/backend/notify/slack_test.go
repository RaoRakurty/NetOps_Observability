package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"netops/backend/models"
)

// TestSlackSend proves the Slack channel actually POSTs a well-formed message to
// its webhook (no external service needed — a local fake stands in).
func TestSlackSend(t *testing.T) {
	var calls int32
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		atomic.AddInt32(&calls, 1)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSlack(srv.URL)
	if err := s.Send(models.Alert{Rule: "LinkDown", Severity: "critical", Summary: "eth0 down on leaf1"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if calls != 1 {
		t.Fatalf("webhook calls = %d, want 1", calls)
	}
	if txt := body["text"]; !strings.Contains(txt, "critical") || !strings.Contains(txt, "LinkDown") || !strings.Contains(txt, "eth0 down on leaf1") {
		t.Errorf("unexpected slack text: %q", txt)
	}
}

func TestSlackSendUnconfigured(t *testing.T) {
	if err := NewSlack("").Send(models.Alert{Severity: "critical"}); err == nil {
		t.Fatal("expected error when webhook url is empty")
	}
}

// TestSlackSeverityGate proves the gate that wraps Slack in the config layer
// drops sub-threshold alerts and forwards those at/above it.
func TestSlackSeverityGate(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gated := NewSeverityGate(NewSlack(srv.URL), "warning")
	if err := gated.Send(models.Alert{Severity: "info", Summary: "noise"}); err != nil {
		t.Fatalf("Send info: %v", err)
	}
	if calls != 0 {
		t.Fatalf("info alert should be gated out, calls = %d", calls)
	}
	if err := gated.Send(models.Alert{Severity: "critical", Summary: "real"}); err != nil {
		t.Fatalf("Send critical: %v", err)
	}
	if calls != 1 {
		t.Fatalf("critical alert should pass the gate, calls = %d", calls)
	}
}
