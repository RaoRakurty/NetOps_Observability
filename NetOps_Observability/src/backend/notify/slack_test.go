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

// TestSlackIncidentActionContract pins the OUTBOUND button contract to the
// INBOUND translator: action_ids must be ack_incident/resolve_incident/
// escalate_incident and every button's value must be the incident id, or the
// bidirectional loop silently breaks (a click wouldn't correlate).
func TestSlackIncidentActionContract(t *testing.T) {
	blocks := BuildIncidentBlocks(IncidentNotice{
		IncidentID: "inc-123", Title: "BGP down", Severity: "critical", Status: "open",
	})
	// Re-marshal/parse so we assert on the actual wire shape Slack receives.
	raw, _ := json.Marshal(blocks)
	var msg struct {
		Text   string `json:"text"`
		Blocks []struct {
			Type     string `json:"type"`
			Elements []struct {
				Type     string `json:"type"`
				ActionID string `json:"action_id"`
				Value    string `json:"value"`
			} `json:"elements"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.Contains(msg.Text, "BGP down") {
		t.Errorf("fallback text missing title: %q", msg.Text)
	}
	want := map[string]bool{"ack_incident": false, "resolve_incident": false, "escalate_incident": false}
	for _, b := range msg.Blocks {
		if b.Type != "actions" {
			continue
		}
		for _, e := range b.Elements {
			if e.Type != "button" {
				continue
			}
			if _, ok := want[e.ActionID]; !ok {
				t.Errorf("unexpected action_id %q (inbound translator won't map it)", e.ActionID)
			}
			want[e.ActionID] = true
			if e.Value != "inc-123" {
				t.Errorf("button %q value = %q, want incident id", e.ActionID, e.Value)
			}
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("missing action button %q", id)
		}
	}
}

// TestSlackSendIncident proves SendIncident POSTs the Block Kit payload.
func TestSlackSendIncident(t *testing.T) {
	var calls int32
	var gotBlocks bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		b, _ := io.ReadAll(r.Body)
		gotBlocks = strings.Contains(string(b), "resolve_incident") && strings.Contains(string(b), "inc-9")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := NewSlack(srv.URL).SendIncident(IncidentNotice{IncidentID: "inc-9", Title: "X", Severity: "high", Status: "open"}); err != nil {
		t.Fatalf("SendIncident: %v", err)
	}
	if calls != 1 || !gotBlocks {
		t.Fatalf("calls=%d gotBlocks=%v", calls, gotBlocks)
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
