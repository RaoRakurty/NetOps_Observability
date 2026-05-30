package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/models"
)

// mockServiceNow stands in for a ServiceNow instance, counting incident creates
// (POST) and resolves (PATCH to /incident/{sys_id}).
func mockServiceNow(t *testing.T, calls *int32, lastBody *map[string]string) *httptest.Server {
	return mockServiceNowWithResolve(t, calls, nil, lastBody)
}

func mockServiceNowWithResolve(t *testing.T, calls, resolves *int32, lastBody *map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u == "" || p == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/now/table/incident" && r.Method == http.MethodPost:
			atomic.AddInt32(calls, 1)
			if lastBody != nil {
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, lastBody)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"result":{"number":"INC0012345","sys_id":"abc"}}`))
		case strings.HasPrefix(r.URL.Path, "/api/now/table/incident/") && r.Method == http.MethodPatch:
			if resolves != nil {
				atomic.AddInt32(resolves, 1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result":{"number":"INC0012345","sys_id":"abc","state":"6"}}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func criticalAlert() models.Alert {
	return models.Alert{
		ID: "a1", Rule: "DeviceDown", Severity: "critical", DeviceID: "core-1",
		Summary: "core-1 unreachable", FiredAt: time.Now().UTC(),
	}
}

func TestServiceNowOpensTicketForCritical(t *testing.T) {
	var calls int32
	var body map[string]string
	srv := mockServiceNow(t, &calls, &body)
	defer srv.Close()

	sn := NewServiceNow(srv.URL, "admin", "secret")
	if err := sn.Send(criticalAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 incident create, got %d", calls)
	}
	if body["impact"] != "1" || body["urgency"] != "1" {
		t.Errorf("critical should map to impact/urgency 1, got %+v", body)
	}
	if body["short_description"] == "" {
		t.Error("missing short_description")
	}
}

func TestServiceNowIgnoresNonCritical(t *testing.T) {
	var calls int32
	srv := mockServiceNow(t, &calls, nil)
	defer srv.Close()

	sn := NewServiceNow(srv.URL, "admin", "secret")
	for _, sev := range []string{"warning", "error", "info", "notice"} {
		a := criticalAlert()
		a.Severity = sev
		if err := sn.Send(a); err != nil {
			t.Fatalf("Send(%s): %v", sev, err)
		}
	}
	if calls != 0 {
		t.Errorf("non-critical alerts should not create tickets, got %d calls", calls)
	}
}

func TestServiceNowDedupAndReopen(t *testing.T) {
	var calls int32
	srv := mockServiceNow(t, &calls, nil)
	defer srv.Close()

	sn := NewServiceNow(srv.URL, "admin", "secret")
	a := criticalAlert()
	// Same alert firing repeatedly opens exactly one ticket.
	_ = sn.Send(a)
	_ = sn.Send(a)
	_ = sn.Send(a)
	if calls != 1 {
		t.Fatalf("dedup failed: expected 1 ticket, got %d", calls)
	}
	// Resolution clears the fingerprint; a genuine re-fire opens a new one.
	resolved := a
	now := time.Now().UTC()
	resolved.ResolvedAt = &now
	_ = sn.Send(resolved)
	_ = sn.Send(a)
	if calls != 2 {
		t.Errorf("re-fire after resolve should open a new ticket: got %d", calls)
	}
}

func TestServiceNowUnconfigured(t *testing.T) {
	sn := NewServiceNow("", "", "")
	if err := sn.Send(criticalAlert()); err == nil {
		t.Error("expected error when instance url is unconfigured")
	}
}

func TestServiceNowAutoCloseOnResolve(t *testing.T) {
	var creates, resolves int32
	srv := mockServiceNowWithResolve(t, &creates, &resolves, nil)
	defer srv.Close()

	sn := NewServiceNow(srv.URL, "admin", "secret")
	a := criticalAlert()
	if err := sn.Send(a); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := len(sn.Tickets()); got != 1 {
		t.Fatalf("expected 1 open ticket, got %d", got)
	}
	// Clearing the alert should PATCH the incident to Resolved and forget it.
	resolved := a
	now := time.Now().UTC()
	resolved.ResolvedAt = &now
	if err := sn.Send(resolved); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolves != 1 {
		t.Errorf("expected 1 auto-resolve PATCH, got %d", resolves)
	}
	if got := len(sn.Tickets()); got != 0 {
		t.Errorf("ticket should be forgotten after resolve, still have %d", got)
	}
}

func TestServiceNowThreshold(t *testing.T) {
	var creates int32
	srv := mockServiceNow(t, &creates, nil)
	defer srv.Close()

	// Lower the bar to warning: warning/error/critical now ticket.
	sn := NewServiceNow(srv.URL, "admin", "secret").WithThreshold("warning")
	for _, sev := range []string{"info", "notice", "warning", "error", "critical"} {
		a := criticalAlert()
		a.ID = "id-" + sev // distinct fingerprints so dedup doesn't hide it
		a.Severity = sev
		if err := sn.Send(a); err != nil {
			t.Fatalf("Send(%s): %v", sev, err)
		}
	}
	if creates != 3 {
		t.Errorf("warning threshold should ticket warning/error/critical (3), got %d", creates)
	}
}

func TestServiceNowStatePersists(t *testing.T) {
	var creates int32
	srv := mockServiceNow(t, &creates, nil)
	defer srv.Close()
	state := t.TempDir() + "/tickets.json"

	sn := NewServiceNow(srv.URL, "admin", "secret").WithStateFile(state)
	if err := sn.Send(criticalAlert()); err != nil {
		t.Fatalf("open: %v", err)
	}
	// A fresh connector loading the same state file sees the open ticket and
	// dedups a re-fire instead of opening a duplicate.
	sn2 := NewServiceNow(srv.URL, "admin", "secret").WithStateFile(state)
	if got := len(sn2.Tickets()); got != 1 {
		t.Fatalf("reloaded connector should see 1 open ticket, got %d", got)
	}
	if err := sn2.Send(criticalAlert()); err != nil {
		t.Fatalf("re-fire: %v", err)
	}
	if creates != 1 {
		t.Errorf("re-fire after restart should dedup, got %d creates", creates)
	}
}
