package main

import (
	"testing"
	"time"

	"netops/backend/nms"
)

// Shuttled back from the nms store tests: the scheduler runtime is integrator
// code (newNMSRuntime), only the store moved.
// due(): each integration polls on its own floored interval; a just-run
// integration is not due again until the interval elapses.
func TestNMSSchedulerDue(t *testing.T) {
	rt := newNMSRuntime(nms.NewMemStore())
	ic := nms.Integration{Tenant: "t-a", ID: "i-a", PollIntervalS: 60}
	if !rt.due(ic) {
		t.Fatal("first evaluation must be due")
	}
	if rt.due(ic) {
		t.Fatal("must not be due again immediately")
	}
	// Backdate the last run beyond the interval → due again.
	rt.mu.Lock()
	rt.lastRun[nms.Key("t-a", "i-a")] = time.Now().Add(-2 * time.Minute)
	rt.mu.Unlock()
	if !rt.due(ic) {
		t.Fatal("must be due after the interval elapses")
	}
	// Sub-floor intervals fall back to the default (5m), not a hot loop.
	fast := nms.Integration{Tenant: "t-a", ID: "i-fast", PollIntervalS: 1}
	if !rt.due(fast) {
		t.Fatal("first evaluation due")
	}
	rt.mu.Lock()
	rt.lastRun[nms.Key("t-a", "i-fast")] = time.Now().Add(-2 * time.Minute)
	rt.mu.Unlock()
	if rt.due(fast) {
		t.Fatal("1s interval must be floored to the default, so 2m ago is not due")
	}
}
