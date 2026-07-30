package nms

import (
	"testing"
	"time"
)

// due(): each integration polls on its own floored interval; a just-run
// integration is not due again until the interval elapses. (Moved in-package
// with the runtime, P2 W4.17.)
func TestSchedulerDue(t *testing.T) {
	rt := NewRuntime(NewMemStore(), Sinks{}, 0)
	ic := Integration{Tenant: "t-a", ID: "i-a", PollIntervalS: 60}
	if !rt.due(ic) {
		t.Fatal("first evaluation must be due")
	}
	if rt.due(ic) {
		t.Fatal("must not be due again immediately")
	}
	// Backdate the last run beyond the interval → due again.
	rt.mu.Lock()
	rt.lastRun[Key("t-a", "i-a")] = time.Now().Add(-2 * time.Minute)
	rt.mu.Unlock()
	if !rt.due(ic) {
		t.Fatal("must be due after the interval elapses")
	}
	// Sub-floor intervals fall back to the default (5m), not a hot loop.
	fast := Integration{Tenant: "t-a", ID: "i-fast", PollIntervalS: 1}
	if !rt.due(fast) {
		t.Fatal("first evaluation due")
	}
	rt.mu.Lock()
	rt.lastRun[Key("t-a", "i-fast")] = time.Now().Add(-2 * time.Minute)
	rt.mu.Unlock()
	if rt.due(fast) {
		t.Fatal("1s interval must be floored to the default, so 2m ago is not due")
	}
}
