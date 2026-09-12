// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// storefailure_test.go — what the module does when the capture REGISTER itself
// is broken, as opposed to when the operator asked for something out of bounds.
// The two are different failures and must not share a status code, a message or
// a silence:
//
//   - a guardrail breach is a 400 naming the bound (that is the operator's to
//     fix);
//   - a store failure is a 500 whose cause is LOGGED and never handed to the
//     caller, because a driver string carries SQLSTATEs, server file paths and
//     column names (§8);
//   - and a store READ that fails must never quietly disable a gate (§10 no
//     silent failures, §3 default-closed).

// brokenStore is a real store with one method sabotaged. Embedding Store means a
// method added to the interface later fails to compile here rather than silently
// falling through to a nil pointer.
type brokenStore struct {
	Store
	activeErr error
	putErr    error

	mu   sync.Mutex
	puts int
}

func (b *brokenStore) ActiveFor(ctx context.Context, tenant string, cross bool, deviceID string) (Capture, bool, error) {
	if b.activeErr != nil {
		return Capture{}, false, b.activeErr
	}
	return b.Store.ActiveFor(ctx, tenant, cross, deviceID)
}

func (b *brokenStore) Put(ctx context.Context, tenant string, cross bool, c Capture) error {
	b.mu.Lock()
	b.puts++
	b.mu.Unlock()
	if b.putErr != nil {
		return b.putErr
	}
	return b.Store.Put(ctx, tenant, cross, c)
}

func (b *brokenStore) putCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.puts
}

// driverish is the kind of string a real driver hands back: it names the server,
// a file path on it and a SQLSTATE. None of it is a response field.
const driverish = `pq: duplicate key value violates unique constraint "pcap_captures_pkey" ` +
	`(SQLSTATE 23505) at /var/lib/postgresql/data/base/16384/2619`

// logSink records structured log lines so a test can prove the failure was
// OBSERVED and not merely swallowed.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) log(msg string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rendered := msg
	if e, ok := fields["error"].(string); ok {
		rendered += " | " + e
	}
	l.lines = append(l.lines, rendered)
}

func (l *logSink) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.lines))
	copy(out, l.lines)
	return out
}

func (l *logSink) mentioning(sub string) bool {
	for _, line := range l.all() {
		if strings.Contains(line, sub) {
			return true
		}
	}
	return false
}

// TestStartRefusesWhenTheInFlightCheckFails is the 3.5-11 regression.
//
// ActiveFor's error used to be consumed as `aerr == nil && found`, so a store
// read failure SILENTLY disabled the durable one-capture-per-device gate: the
// capture proceeded and nothing was logged. A packet capture is a privileged,
// payload-revealing action on a production device and a second capture point on
// an interface that already has one is the design's top operational risk, so the
// gate is default-closed.
func TestStartRefusesWhenTheInFlightCheckFails(t *testing.T) {
	var (
		sink   logSink
		broken *brokenStore
		ran    int
	)
	fx := newFixture(t, func(d *Deps) {
		broken = &brokenStore{Store: d.Store, activeErr: errors.New(driverish)}
		d.Store = broken
		d.LogError = sink.log
		d.Run = func(func()) { ran++ }
	})
	_, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme")
	if err == nil {
		t.Fatal("a capture started while the one-at-a-time gate could not be read — " +
			"the gate is not default-closed")
	}
	if !errors.Is(err, ErrStore) {
		t.Fatalf("err = %v, want it wrapped in ErrStore so the handler can answer 500", err)
	}
	if ran != 0 {
		t.Fatalf("the capture body ran %d times — a refused start must not touch the device", ran)
	}
	if broken.putCount() != 0 {
		t.Fatalf("a row was written (%d puts) for a capture that was refused", broken.putCount())
	}
	if !sink.mentioning("in-flight check failed") {
		t.Fatalf("the store read failure was not logged (§10 no silent failures): %v", sink.all())
	}
	if !sink.mentioning("SQLSTATE 23505") {
		t.Fatalf("the log does not carry the cause an operator would debug from: %v", sink.all())
	}
}

// TestStartAnswers500AndLogsWhenTheStoreRefusesTheWrite is the 3.5-09
// regression: the catch-all arm of handleStart returned EVERY remaining error as
// a 400 carrying err.Error() verbatim, so a driver message reached the caller and
// nothing was logged.
func TestStartAnswers500AndLogsWhenTheStoreRefusesTheWrite(t *testing.T) {
	var sink logSink
	fx := newFixture(t, func(d *Deps) {
		d.Store = &brokenStore{Store: d.Store, putErr: errors.New(driverish)}
		d.LogError = sink.log
	})
	fx.as("acme", false)
	w := fx.do(http.MethodPost, "/api/devices/acme-core/pcap", `{"interface":"Ethernet1/1","duration_s":1}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a store write failure = %d, want 500 (it is not the operator's mistake): %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, leak := range []string{"SQLSTATE", "pcap_captures_pkey", "/var/lib/postgresql", "pq:"} {
		if strings.Contains(body, leak) {
			t.Errorf("the response leaked the driver's own message (%q): %s", leak, body)
		}
	}
	if !strings.Contains(body, "packet captures are unavailable") {
		t.Errorf("the 500 body is not the generic refusal: %s", body)
	}
	if !sink.mentioning("SQLSTATE 23505") {
		t.Fatalf("the store write failure was not logged: %v", sink.all())
	}
}

// TestStartStillAnswers400ForAGuardrailBreach guards the other half: routing
// store failures to 500 must NOT turn the operator-actionable bounds into
// opaque 500s. A breached bound keeps its reason, verbatim, at 400.
func TestStartStillAnswers400ForAGuardrailBreach(t *testing.T) {
	fx := newFixture(t, nil)
	fx.as("acme", false)
	for _, tc := range []struct{ body, want string }{
		{`{"interface":"Ethernet1/1","duration_s":3600}`, "60 seconds or less"},
		{`{"interface":"Ethernet1/1","max_packets":999999}`, "10000 or less"},
		{`{"interface":"eth0; reboot"}`, "forbidden character"},
		{`{"interface":"Ethernet1/1","filter":"host 1.2.3.4; rm -rf /"}`, "forbidden character"},
	} {
		w := fx.do(http.MethodPost, "/api/devices/acme-core/pcap", tc.body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", tc.body, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s -> %s, want it to name the bound (%q)", tc.body, w.Body.String(), tc.want)
		}
	}
}
