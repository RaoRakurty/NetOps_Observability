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
)

// mockJira stands in for a Jira Cloud instance, counting issue creates (POST
// /rest/api/2/issue) and resolve transitions (POST .../transitions). A GET on
// the transitions endpoint advertises a "Done" transition so auto-resolve can
// pick it.
func mockJira(t *testing.T, creates, resolves *int32, lastFields *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u == "" || p == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/rest/api/2/issue" && r.Method == http.MethodPost:
			if creates != nil {
				atomic.AddInt32(creates, 1)
			}
			if lastFields != nil {
				b, _ := io.ReadAll(r.Body)
				var env struct {
					Fields map[string]any `json:"fields"`
				}
				_ = json.Unmarshal(b, &env)
				*lastFields = env.Fields
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"10001","key":"NETOPS-1"}`))
		case strings.HasSuffix(r.URL.Path, "/transitions") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"transitions":[{"id":"11","name":"In Progress"},{"id":"31","name":"Done"}]}`))
		case strings.HasSuffix(r.URL.Path, "/transitions") && r.Method == http.MethodPost:
			if resolves != nil {
				atomic.AddInt32(resolves, 1)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func newJiraConn(url string) *Jira {
	return NewJira(url, "bot@example.com", "token", "NETOPS")
}

func TestJiraOpensTicketForCritical(t *testing.T) {
	var creates int32
	var fields map[string]any
	srv := mockJira(t, &creates, nil, &fields)
	defer srv.Close()

	j := newJiraConn(srv.URL)
	if err := j.Send(criticalAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if creates != 1 {
		t.Fatalf("expected 1 issue create, got %d", creates)
	}
	if proj, _ := fields["project"].(map[string]any); proj == nil || proj["key"] != "NETOPS" {
		t.Errorf("expected project key NETOPS, got %+v", fields["project"])
	}
	if s, _ := fields["summary"].(string); !strings.Contains(s, "CRITICAL") {
		t.Errorf("summary should carry the severity, got %q", s)
	}
}

func TestJiraIgnoresNonCritical(t *testing.T) {
	var creates int32
	srv := mockJira(t, &creates, nil, nil)
	defer srv.Close()

	j := newJiraConn(srv.URL)
	for _, sev := range []string{"warning", "error", "info", "notice"} {
		a := criticalAlert()
		a.Severity = sev
		if err := j.Send(a); err != nil {
			t.Fatalf("Send(%s): %v", sev, err)
		}
	}
	if creates != 0 {
		t.Errorf("non-critical alerts should not open issues, got %d", creates)
	}
}

func TestJiraDedupAndReopen(t *testing.T) {
	var creates, resolves int32
	srv := mockJira(t, &creates, &resolves, nil)
	defer srv.Close()

	j := newJiraConn(srv.URL)
	a := criticalAlert()
	_ = j.Send(a)
	_ = j.Send(a)
	_ = j.Send(a)
	if creates != 1 {
		t.Fatalf("dedup failed: expected 1 issue, got %d", creates)
	}
	resolved := a
	now := time.Now().UTC()
	resolved.ResolvedAt = &now
	_ = j.Send(resolved)
	_ = j.Send(a)
	if creates != 2 {
		t.Errorf("re-fire after resolve should open a new issue: got %d", creates)
	}
}

func TestJiraAutoCloseOnResolve(t *testing.T) {
	var creates, resolves int32
	srv := mockJira(t, &creates, &resolves, nil)
	defer srv.Close()

	j := newJiraConn(srv.URL)
	a := criticalAlert()
	if err := j.Send(a); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := len(j.Tickets()); got != 1 {
		t.Fatalf("expected 1 open ticket, got %d", got)
	}
	resolved := a
	now := time.Now().UTC()
	resolved.ResolvedAt = &now
	if err := j.Send(resolved); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolves != 1 {
		t.Errorf("expected 1 resolve transition, got %d", resolves)
	}
	if got := len(j.Tickets()); got != 0 {
		t.Errorf("ticket should be forgotten after resolve, still have %d", got)
	}
}

func TestJiraUnconfigured(t *testing.T) {
	j := NewJira("", "", "", "")
	if err := j.Send(criticalAlert()); err == nil {
		t.Error("expected error when base url / project key is unconfigured")
	}
}

func TestJiraThreshold(t *testing.T) {
	var creates int32
	srv := mockJira(t, &creates, nil, nil)
	defer srv.Close()

	j := newJiraConn(srv.URL).WithThreshold("warning")
	for _, sev := range []string{"info", "notice", "warning", "error", "critical"} {
		a := criticalAlert()
		a.ID = "id-" + sev
		a.Severity = sev
		if err := j.Send(a); err != nil {
			t.Fatalf("Send(%s): %v", sev, err)
		}
	}
	if creates != 3 {
		t.Errorf("warning threshold should open warning/error/critical (3), got %d", creates)
	}
}

func TestJiraStatePersists(t *testing.T) {
	var creates int32
	srv := mockJira(t, &creates, nil, nil)
	defer srv.Close()
	state := t.TempDir() + "/jira.json"

	j := newJiraConn(srv.URL).WithStateFile(state)
	if err := j.Send(criticalAlert()); err != nil {
		t.Fatalf("open: %v", err)
	}
	j2 := newJiraConn(srv.URL).WithStateFile(state)
	if got := len(j2.Tickets()); got != 1 {
		t.Fatalf("reloaded connector should see 1 open ticket, got %d", got)
	}
	if err := j2.Send(criticalAlert()); err != nil {
		t.Fatalf("re-fire: %v", err)
	}
	if creates != 1 {
		t.Errorf("re-fire after restart should dedup, got %d creates", creates)
	}
}
