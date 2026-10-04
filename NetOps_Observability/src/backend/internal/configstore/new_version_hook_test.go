// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

// new_version_hook_test.go — the capture trigger on the version row, and the
// OnNewVersion seam the change ledger's config_capture producer hangs off
// (Iris N-D2).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type hookRecorder struct {
	mu     sync.Mutex
	events []NewVersionEvent
	err    error
}

func (h *hookRecorder) observe(_ context.Context, ev NewVersionEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, ev)
	return h.err
}

func (h *hookRecorder) seen() []NewVersionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]NewVersionEvent(nil), h.events...)
}

// Only a capture that stored a NEW version is a change; an unchanged capture is
// not, and a failed one is not.
func TestOnNewVersionFiresOnlyForANewVersion(t *testing.T) {
	hook := &hookRecorder{}
	f := newFixture(t, func(d *Deps) { d.OnNewVersion = hook.observe })
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	ctx := context.Background()

	f.gw.set("d1", sampleConfig("edge-01"))
	v1, err := f.mgr.Capture(ctx, dev, "acme", TriggerScheduled)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	if _, err := f.mgr.Capture(ctx, dev, "acme", TriggerScheduled); err != nil { // unchanged
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	f.gw.set("d1", sampleConfig("edge-02"))
	v2, err := f.mgr.Capture(ctx, dev, "acme", ManualTrigger("u_ops"))
	if err != nil {
		t.Fatal(err)
	}
	f.gw.fail("d1", errors.New("unreachable"))
	f.now = f.now.Add(time.Hour)
	if _, err := f.mgr.Capture(ctx, dev, "acme", TriggerScheduled); err == nil {
		t.Fatal("the failing capture must fail")
	}

	got := hook.seen()
	if len(got) != 2 {
		t.Fatalf("OnNewVersion fired %d times, want 2 (first capture + the real change): %+v", len(got), got)
	}
	if got[0].HasPrevious || got[0].Version.SHA != v1.SHA || got[0].Version.Trigger != TriggerScheduled {
		t.Fatalf("first event = %+v", got[0])
	}
	second := got[1]
	if !second.HasPrevious || second.PreviousSHA != v1.SHA || second.Version.SHA != v2.SHA {
		t.Fatalf("second event does not link the previous version: %+v", second)
	}
	if second.Version.Trigger != "manual:u_ops" || second.Tenant != "acme" || second.Device.ID != "d1" {
		t.Fatalf("second event lost its provenance: %+v", second)
	}
	// The drift verdict is stamped BEFORE the consumer is told, so the change
	// it records can say how big the change was.
	if second.Version.Drift != DriftChanged || second.Version.Added != 1 {
		t.Fatalf("the consumer saw no drift verdict: %+v", second.Version)
	}
}

// The trigger is stored on the row — the new one, and the failed one — and an
// unchanged capture keeps the trigger of the capture that produced the version.
func TestTheTriggerIsStoredOnTheVersionRow(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	ctx := context.Background()
	f.gw.set("d1", sampleConfig("edge-01"))
	v1, err := f.mgr.Capture(ctx, dev, "acme", ManualTrigger("u_ops"))
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	if _, err := f.mgr.Capture(ctx, dev, "acme", TriggerScheduled); err != nil {
		t.Fatal(err)
	}
	row, err := f.store.Get(ctx, "acme", false, "d1", v1.SHA)
	if err != nil {
		t.Fatal(err)
	}
	if row.Trigger != "manual:u_ops" {
		t.Fatalf("stored trigger = %q — an unchanged re-verification must not re-attribute the version", row.Trigger)
	}
	f.gw.fail("d1", errors.New("unreachable"))
	f.now = f.now.Add(time.Hour)
	if _, err := f.mgr.Capture(ctx, dev, "acme", TriggerScheduled); err == nil {
		t.Fatal("want a failure")
	}
	rows, err := f.store.List(ctx, "acme", false, "d1")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Status == StatusFailed && r.Trigger != TriggerScheduled {
			t.Fatalf("failed row trigger = %q", r.Trigger)
		}
	}
}

// A refused change-ledger write is COUNTED and logged and does not fail the
// capture: the version is durable, and failing the capture would report a
// reachable device as unreachable.
func TestARefusedLedgerWriteIsCountedNotFatal(t *testing.T) {
	hook := &hookRecorder{err: errors.New("ledger down")}
	var warned []string
	var mu sync.Mutex
	f := newFixture(t, func(d *Deps) {
		d.OnNewVersion = hook.observe
		d.LogWarn = func(msg string, _ map[string]any) {
			mu.Lock()
			warned = append(warned, msg)
			mu.Unlock()
		}
	})
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.gw.set("d1", sampleConfig("edge-01"))
	v, err := f.mgr.Capture(context.Background(), dev, "acme", TriggerScheduled)
	if err != nil || v.Status != StatusOK {
		t.Fatalf("the capture failed because the ledger did: %v %+v", err, v)
	}
	if n := f.metrics.Snapshot()["new_version_hook_failures_total"]; n != 1 {
		t.Fatalf("hook failures counted = %d, want 1", n)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, w := range warned {
		found = found || strings.Contains(w, "change ledger did not record it")
	}
	if !found {
		t.Fatalf("the refusal was not logged: %v", warned)
	}
}

// A manual capture through the HTTP route records the AUTHENTICATED principal
// as its trigger — never anything from the request.
func TestManualCaptureRecordsTheCallerAsTheTrigger(t *testing.T) {
	hook := &hookRecorder{}
	f := newFixture(t, func(d *Deps) { d.OnNewVersion = hook.observe })
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.principal = Principal{Tenant: "acme", Subject: "u_ops"}
	f.gw.set("d1", sampleConfig("edge-01"))
	if w := f.do(http.MethodPost, "/api/devices/d1/config/backup", ""); w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	deadline := time.Now().Add(3 * time.Second)
	for (f.mgr.InFlight("d1") || len(hook.seen()) == 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := hook.seen()
	if len(got) != 1 || got[0].Version.Trigger != "manual:u_ops" {
		t.Fatalf("manual capture events = %+v", got)
	}
}

func TestTriggerHelpers(t *testing.T) {
	for _, tc := range []struct{ subject, want string }{
		{"u_ops", "manual:u_ops"},
		{"", TriggerManual},
		{"  \t", TriggerManual},
		{"u ops\n", "manual:uops"},
		{strings.Repeat("x", maxTriggerBytes), TriggerManual}, // never a truncated id
	} {
		if got := ManualTrigger(tc.subject); got != tc.want {
			t.Errorf("ManualTrigger(%q) = %q, want %q", tc.subject, got, tc.want)
		}
	}
	for _, tc := range []struct{ trigger, kind, subject string }{
		{"manual:u_ops", TriggerManual, "u_ops"},
		{TriggerManual, TriggerManual, ""},
		{TriggerScheduled, TriggerScheduled, ""},
		{"", "", ""},
	} {
		if k, s := SplitTrigger(tc.trigger); k != tc.kind || s != tc.subject {
			t.Errorf("SplitTrigger(%q) = (%q, %q), want (%q, %q)", tc.trigger, k, s, tc.kind, tc.subject)
		}
	}
}
