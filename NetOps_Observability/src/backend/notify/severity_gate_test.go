// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

import (
	"sync"
	"testing"
	"time"

	"netops/backend/models"
)

type recordingChannel struct {
	mu   sync.Mutex
	sent []string
}

func (r *recordingChannel) Name() string { return "rec" }
func (r *recordingChannel) Send(a models.Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, a.Severity)
	return nil
}
func (r *recordingChannel) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

// A SeverityGate set to "critical" forwards critical, drops anything lower.
func TestSeverityGateFilters(t *testing.T) {
	rec := &recordingChannel{}
	gate := NewSeverityGate(rec, "critical")

	for _, sev := range []string{"info", "warning", "error", "critical"} {
		if err := gate.Send(models.Alert{Severity: sev}); err != nil {
			t.Fatal(err)
		}
	}
	if rec.count() != 1 || rec.sent[0] != "critical" {
		t.Fatalf("gate should forward only critical, got %v", rec.sent)
	}
}

// Unguarded bypasses the gate so an explicit DispatchTo (reports) still delivers
// a low-severity message through a critical-gated channel.
func TestSeverityGateUnguardedBypass(t *testing.T) {
	rec := &recordingChannel{}
	gate := NewSeverityGate(rec, "critical")

	d := NewDispatcher()
	d.Register(gate)
	// Broadcast of an info alert is gated out.
	d.Dispatch(models.Alert{Severity: "info"})
	// Explicit DispatchTo("rec") must bypass the gate (report use case).
	n := d.DispatchTo(models.Alert{Severity: "info"}, []string{"rec"})
	if n != 1 {
		t.Fatalf("DispatchTo matched %d channels, want 1", n)
	}
	// Give the async sends a moment.
	waitFor(t, rec, 1)
}

func waitFor(t *testing.T, rec *recordingChannel, n int) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if rec.count() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected at least %d sends, got %d", n, rec.count())
}
