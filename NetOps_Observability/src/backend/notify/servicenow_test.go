package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/models"
)

// mockServiceNow stands in for a ServiceNow instance, counting incident creates.
func mockServiceNow(t *testing.T, calls *int32, lastBody *map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/now/table/incident" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u == "" || p == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(calls, 1)
		if lastBody != nil {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, lastBody)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"number":"INC0012345","sys_id":"abc"}}`))
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
