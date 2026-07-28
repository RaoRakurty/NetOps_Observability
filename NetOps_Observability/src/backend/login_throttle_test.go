package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/loginguard"
)

// Server-integration halves of the F-25 throttle suite (the pure white-box
// tests moved to internal/loginguard with the throttle).
func TestLoginRefusesUncountableAttempt(t *testing.T) {
	_, srv := newTestServerState(t)
	srv.loginThrottle = loginguard.NewThrottleWithLimits(2, time.Now, nil)
	// Fill both slots with live locks.
	srv.loginThrottle.Fail("locked-a", 1, 600)
	srv.loginThrottle.Fail("locked-b", 1, 600)

	body, err := json.Marshal(map[string]string{"username": "someone-else", "password": "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	srv.handleLogin(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 — a failure the throttle cannot count must be refused, not answered 401", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the fail-closed refusal — clients cannot back off correctly")
	}
	if srv.loginThrottle.Saturations() == 0 {
		t.Error("saturation not counted on the HTTP path")
	}
}

// TestLoginThrottleMetricsExposed: the counters must actually reach /metrics —
// an unexported counter is not observability.
func TestLoginThrottleMetricsExposed(t *testing.T) {
	_, srv := newTestServerState(t)
	srv.alerts = alerts.NewEngine("", nil)
	w := httptest.NewRecorder()
	srv.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := w.Body.String()
	for _, want := range []string{
		"netops_login_throttle_accounts",
		"netops_login_throttle_evictions_total",
		"netops_login_throttle_swept_total",
		"netops_login_throttle_saturated_total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %s — F-25's failure mode stays invisible without it", want)
		}
	}
}
