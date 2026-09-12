// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// trace_retention_test.go — the two lifetimes of a trace, kept apart.
//
// THE BUG THIS FILE EXISTS TO HOLD CLOSED. The retention wait used to select on
// the RUN's own context (context.WithTimeout(ttl)), so the finished result was
// dropped the instant the TTL expired and the stated retention window never
// once elapsed: a caller who polled a settled trace a minute after it finished
// got "no such trace", and the 15-minute constant was dead code that read like
// a guarantee.
//
// The durations here are milliseconds, not minutes, because the store's
// retention is a FIELD: the same code path runs, only faster.

import (
	"testing"
	"time"
)

// waitForTrace polls the store until `want` matches presence, or the deadline
// passes. Polling (rather than sleeping once) keeps the test honest on a busy
// machine: it fails on the CONDITION, never on a missed instant.
func waitForTrace(t *testing.T, api *API, marker string, want bool, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if _, ok := api.traces.get(marker); ok == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startTraceForTest runs one follow to completion and returns its marker.
func startTraceForTest(t *testing.T, api *API, ttl, retention time.Duration) string {
	t.Helper()
	api.traces.retention = retention
	marker := NewMarker(time.Now())
	api.traces.start(api, marker, KindSyslog, "spine1", "acme",
		Principal{Subject: "owner", Cross: true}, ttl, nil)
	// The follow ends when its TTL expires (the fake stores never satisfy every
	// stage), which is exactly the moment the old code discarded the result.
	if !waitForDone(t, api, marker, 5*time.Second) {
		t.Fatal("the follow never finished")
	}
	return marker
}

func waitForDone(t *testing.T, api *API, marker string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if st, ok := api.traces.get(marker); ok && st.Done {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// A FINISHED trace must outlive its own TTL. The TTL bounds the RUN; the result
// is evidence, and it is kept for the retention window.
func TestAFinishedTraceOutlivesItsTTLAndIsDroppedAfterRetention(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	t.Cleanup(api.Stop)

	const ttl = 100 * time.Millisecond
	const retain = 3 * time.Second
	marker := startTraceForTest(t, api, ttl, retain)

	// Well past the TTL, nowhere near the retention window: the settled result
	// must still be readable. This is the regression — it used to be gone.
	time.Sleep(ttl + 400*time.Millisecond)
	st, ok := api.traces.get(marker)
	if !ok {
		t.Fatal("the finished trace was dropped when its TTL expired — the retention window is being cut short by the run's own context")
	}
	if !st.Done {
		t.Fatalf("the retained trace is not marked done: %+v", st)
	}
	if len(st.Stages) == 0 {
		t.Error("the retained trace carries no stages — the evidence was dropped but the entry kept")
	}

	// And it does eventually go: a debug result is evidence, not state.
	if !waitForTrace(t, api, marker, false, retain+3*time.Second) {
		t.Error("the trace was never dropped — the retention window does not end")
	}
}

// Shutdown is the ONE thing allowed to cut a retention window short.
func TestStopDropsRetainedTracesImmediately(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())

	marker := startTraceForTest(t, api, 100*time.Millisecond, time.Hour)
	if _, ok := api.traces.get(marker); !ok {
		t.Fatal("the finished trace is not retained")
	}
	api.Stop()
	if !waitForTrace(t, api, marker, false, 2*time.Second) {
		t.Error("Stop left a retained trace behind — its goroutine would outlive the process's own teardown")
	}
	// A trace started after teardown is not retained either: a late request
	// must not resurrect a store that was just stopped.
	late := NewMarker(time.Now())
	api.traces.start(api, late, KindSyslog, "spine1", "acme", Principal{Cross: true}, 50*time.Millisecond, nil)
	if !waitForTrace(t, api, late, false, 2*time.Second) {
		t.Error("a trace started after Stop was retained")
	}
}

// The concurrency bound still evicts, and eviction still ends the retention
// wait rather than leaving a goroutine parked on a 15-minute timer.
func TestTheOldestTraceIsEvictedWhenTheBoundIsReached(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	t.Cleanup(api.Stop)
	api.traces.retention = time.Hour

	markers := make([]string, 0, maxLiveTraces+2)
	for i := 0; i < maxLiveTraces+2; i++ {
		m := NewMarker(time.Now())
		markers = append(markers, m)
		api.traces.start(api, m, KindSyslog, "spine1", "acme", Principal{Cross: true}, 50*time.Millisecond, nil)
	}
	for _, m := range markers[:2] {
		if !waitForTrace(t, api, m, false, 2*time.Second) {
			t.Errorf("trace %s was not evicted by the maxLiveTraces bound", m)
		}
	}
	if _, ok := api.traces.get(markers[len(markers)-1]); !ok {
		t.Error("the newest trace was evicted instead of the oldest")
	}
}
