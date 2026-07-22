package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/models"
)

// delivery_test.go — F-22 FAILURE-PATH tests.
//
// The dispatcher's existing tests all assert that a HEALTHY channel receives
// the alert. Every one of them stayed green while a transient 502 silently
// discarded a page, while a storm spawned 30,000 goroutines, and while nothing
// counted any of it. These tests only exercise faults: flaky channels, always
// failing channels, a wedged channel, and queue overflow.

// flakyChannel fails its first `failures` sends, then succeeds.
type flakyChannel struct {
	name     string
	failures int32
	attempts atomic.Int32
	mu       sync.Mutex
	got      []models.Alert
}

func (c *flakyChannel) Name() string { return c.name }

func (c *flakyChannel) Send(a models.Alert) error {
	n := c.attempts.Add(1)
	if n <= c.failures {
		return fmt.Errorf("transient upstream error (attempt %d)", n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, a)
	return nil
}

func (c *flakyChannel) delivered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

// blockingChannel parks every send until released — a tarpitting provider.
type blockingChannel struct {
	name    string
	release chan struct{}
	entered atomic.Int32
}

func (c *blockingChannel) Name() string { return c.name }
func (c *blockingChannel) Send(models.Alert) error {
	c.entered.Add(1)
	<-c.release
	return nil
}

// fastRetries removes the real backoff so retry behaviour is asserted in
// milliseconds. The jitter/backoff calculation itself is covered separately.
func fastRetries(d *Dispatcher) {
	d.delivery.sleep = func(ctx context.Context, _ time.Duration) bool {
		return ctx.Err() == nil
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestTransientFailureIsRetriedNotLost is the F-22 defect proper: the old
// dispatcher called Send exactly once and logged the error. One 502 from Slack
// during an incident = one page that never existed.
func TestTransientFailureIsRetriedNotLost(t *testing.T) {
	d := NewDispatcher()
	defer d.Close()
	fastRetries(d)
	c := &flakyChannel{name: "slack", failures: 2}
	d.Register(c)

	d.Dispatch(dispatcherAlert())

	waitUntil(t, "delivery after retries", func() bool { return c.delivered() == 1 })
	if got := c.attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3 (2 failures then success)", got)
	}
	if n := d.statsSnapshot("slack").retries; n == 0 {
		t.Error("retries were not counted")
	}
	if n := d.statsSnapshot("slack").sent; n != 1 {
		t.Errorf("sent = %d, want 1", n)
	}
}

// TestPermanentFailureIsCountedAndLogged: when retries are exhausted the page
// really is lost — and that MUST be loud. Silence here is the whole finding.
func TestPermanentFailureIsCountedAndLogged(t *testing.T) {
	d := NewDispatcher()
	defer d.Close()
	fastRetries(d)

	var logMu sync.Mutex
	var logged []string
	d.SetLogger(func(level, msg string, fields map[string]any) {
		logMu.Lock()
		defer logMu.Unlock()
		logged = append(logged, level+": "+msg+fmt.Sprint(fields["alert_id"]))
	})
	c := &flakyChannel{name: "pagerduty", failures: 1 << 30} // never succeeds
	d.Register(c)

	d.Dispatch(dispatcherAlert())

	waitUntil(t, "failure to be counted", func() bool { return d.statsSnapshot("pagerduty").failed == 1 })
	if got := c.attempts.Load(); got != deliveryAttempts {
		t.Errorf("attempts = %d, want %d — the retry budget must be exhausted before giving up", got, deliveryAttempts)
	}
	logMu.Lock()
	defer logMu.Unlock()
	found := false
	for _, l := range logged {
		if strings.HasPrefix(l, "error: ") && strings.Contains(l, "did not go out") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a permanently failed page produced no error log: %v", logged)
	}
}

// TestFanOutIsBounded: the storm case. 500 alerts × 4 channels used to be 2,000
// simultaneous goroutines each holding a socket. Concurrency must stay at the
// worker-pool bound no matter how much is queued.
func TestFanOutIsBounded(t *testing.T) {
	d := NewDispatcher()
	defer d.Close()

	block := &blockingChannel{name: "wedged", release: make(chan struct{})}
	d.Register(block)

	for i := 0; i < 500; i++ {
		d.Dispatch(models.Alert{ID: fmt.Sprintf("a%d", i), Rule: "storm"})
	}
	// Give the pool time to saturate, then assert it did not exceed its bound.
	waitUntil(t, "workers to saturate", func() bool { return block.entered.Load() >= deliveryWorkers })
	time.Sleep(50 * time.Millisecond)
	if got := block.entered.Load(); got > deliveryWorkers {
		t.Fatalf("%d concurrent sends in flight, bound is %d — the unbounded fan-out is back", got, deliveryWorkers)
	}
	close(block.release)
}

// TestQueueOverflowIsCountedNotSilent: the bounded queue must shed loudly.
// A silent shed would reintroduce the finding in a new place.
func TestQueueOverflowIsCountedNotSilent(t *testing.T) {
	d := NewDispatcher()
	defer d.Close()

	var dropLogs atomic.Int32
	d.SetLogger(func(level, msg string, _ map[string]any) {
		if level == "error" && strings.Contains(msg, "DROPPED") {
			dropLogs.Add(1)
		}
	})
	block := &blockingChannel{name: "wedged", release: make(chan struct{})}
	d.Register(block)

	// Fill the queue past its bound while every worker is parked.
	for i := 0; i < deliveryQueueSize+deliveryWorkers+64; i++ {
		d.Dispatch(models.Alert{ID: fmt.Sprintf("a%d", i), Rule: "flood"})
	}
	waitUntil(t, "drops to be recorded", func() bool { return d.statsSnapshot("wedged").dropped > 0 })
	if dropLogs.Load() == 0 {
		t.Error("notifications were shed with no error log — §10 forbids a silent drop")
	}
	close(block.release)
}

// TestDispatchDoesNotBlockTheAlertLoop: enqueue must never block, even with
// every worker wedged and the queue full — the alert engine's tick loop calls
// Dispatch synchronously.
func TestDispatchDoesNotBlockTheAlertLoop(t *testing.T) {
	d := NewDispatcher()
	defer d.Close()
	block := &blockingChannel{name: "wedged", release: make(chan struct{})}
	d.Register(block)
	for i := 0; i < deliveryQueueSize+128; i++ {
		d.Dispatch(models.Alert{ID: "fill", Rule: "r"})
	}
	done := make(chan struct{})
	go func() { d.Dispatch(dispatcherAlert()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Dispatch blocked on a full queue — one wedged provider would stall alert evaluation for every tenant")
	}
	close(block.release)
}

// TestBackoffHasPerCallJitter guards the F-28 shape: jitter derived from the
// attempt number gives every queued item at attempt N an identical delay, so
// 10k items retry in lockstep against a recovering provider.
func TestBackoffHasPerCallJitter(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		seen[backoff(2)] = true
	}
	if len(seen) < 10 {
		t.Fatalf("backoff(2) produced only %d distinct delays over 200 calls — the jitter is not per-call, "+
			"so every queued retry fires in the same instant", len(seen))
	}
	// Bound the spread: base·2^(attempt-1) ± 50%.
	base := deliveryRetryBase << 1
	for d := range seen {
		if d < base/2 || d > base+base/2 {
			t.Fatalf("backoff(2) = %v outside base±50%% of %v", d, base)
		}
	}
}

// TestResolveFailureIsAlsoRetried: the resolve leg had the identical bug, and a
// lost resolve leaves a PagerDuty incident open forever.
func TestResolveFailureIsAlsoRetried(t *testing.T) {
	d := NewDispatcher()
	defer d.Close()
	fastRetries(d)
	c := &flakyResolver{flakyChannel: flakyChannel{name: "pd", failures: 1}}
	d.Register(c)

	d.DispatchResolve(dispatcherAlert())
	waitUntil(t, "resolve retry", func() bool { return c.resolves.Load() == 2 })
	if n := d.statsSnapshot("pd").sent; n != 1 {
		t.Errorf("resolve sent = %d, want 1", n)
	}
}

type flakyResolver struct {
	flakyChannel
	resolves atomic.Int32
}

func (c *flakyResolver) SendResolve(models.Alert) error {
	if c.resolves.Add(1) <= c.failures {
		return errors.New("transient")
	}
	return nil
}

// TestWriteMetricsExposesPerChannelCounters: an unexported counter is not
// observability. handlePromMetrics must be able to render it.
func TestWriteMetricsExposesPerChannelCounters(t *testing.T) {
	d := NewDispatcher()
	defer d.Close()
	fastRetries(d)
	d.Register(&flakyChannel{name: "slack", failures: 1 << 30})
	d.Dispatch(dispatcherAlert())
	waitUntil(t, "failure", func() bool { return d.statsSnapshot("slack").failed == 1 })

	var sb strings.Builder
	d.WriteMetrics(&sb)
	out := sb.String()
	for _, want := range []string{
		`netops_notify_failures_total{channel="slack"} 1`,
		"netops_notify_sent_total",
		"netops_notify_retries_total",
		"netops_notify_dropped_total",
		"netops_notify_queue_depth",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n%s", want, out)
		}
	}
}

// TestCloseDrainsInFlight: shutdown must not abandon a send mid-flight — a
// deploy during an incident is exactly when the page matters.
func TestCloseDrainsInFlight(t *testing.T) {
	d := NewDispatcher()
	block := &blockingChannel{name: "slow", release: make(chan struct{})}
	d.Register(block)
	d.Dispatch(dispatcherAlert())
	waitUntil(t, "send to start", func() bool { return block.entered.Load() == 1 })

	closed := make(chan struct{})
	go func() { d.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a send was still in flight — that is the abandoned-write defect")
	case <-time.After(100 * time.Millisecond):
	}
	close(block.release)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after the in-flight send completed")
	}
}
