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

// TestTeamsSend proves the Teams channel POSTs a well-formed MessageCard to its
// webhook. Teams was env-only and untested before G10 — it shipped as the one
// notification destination with no proof it could deliver anything.
func TestTeamsSend(t *testing.T) {
	var calls int32
	var card map[string]any
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		atomic.AddInt32(&calls, 1)
		contentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &card)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tm := NewTeams(srv.URL)
	a := models.Alert{Rule: "ContainerDown", Severity: "critical", Summary: "kafka restarting", Description: "3 restarts in 5m"}
	if err := tm.Send(a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if calls != 1 {
		t.Fatalf("webhook calls = %d, want 1", calls)
	}
	if !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("content-type = %q", contentType)
	}
	if card["@type"] != "MessageCard" {
		t.Errorf("@type = %v, want MessageCard", card["@type"])
	}
	if got := card["themeColor"]; got != "E11D48" {
		t.Errorf("critical themeColor = %v, want E11D48", got)
	}
	title, _ := card["title"].(string)
	if !strings.Contains(title, "critical") || !strings.Contains(title, "ContainerDown") {
		t.Errorf("title = %q", title)
	}
	text, _ := card["text"].(string)
	if !strings.Contains(text, "kafka restarting") || !strings.Contains(text, "3 restarts in 5m") {
		t.Errorf("text = %q", text)
	}
}

func TestTeamsSendRequiresWebhook(t *testing.T) {
	if err := NewTeams("").Send(models.Alert{Rule: "X", Severity: "critical"}); err == nil {
		t.Fatal("an unconfigured Teams channel must return an error, not silently succeed")
	}
}

func TestTeamsSendSurfacesHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	err := NewTeams(srv.URL).Send(models.Alert{Rule: "X", Severity: "critical"})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("want a 502-bearing error, got %v", err)
	}
}
