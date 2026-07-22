package notify

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"netops/backend/models"
)

// delivery.go — the bounded, retrying, observable outbound path for alert
// notifications (audit F-22).
//
// What this replaces, and why it mattered:
//
//	for _, c := range channels {
//	    go func(c Channel) {
//	        if err := c.Send(a); err != nil { log.Printf("notify %s: %v", ...) }
//	    }(c)
//	}
//
// Three defects stacked in those five lines, on the ONE path the platform
// exists to protect:
//
//  1. UNBOUNDED FAN-OUT. One goroutine per channel per alert, spawned from the
//     alert engine's tick loop over every newly-active alert. A correlated
//     failure (a core link drops and 5,000 interface alerts fire in one tick)
//     × 6 channels = 30,000 concurrent outbound HTTP/SMTP goroutines, each
//     holding a socket, in the process that also serves the API. The blast
//     radius of an incident included the tool used to see the incident.
//  2. NO RETRY (CLAUDE.md §9 requires retry with backoff + jitter). A single
//     transient 502 from Slack or PagerDuty was a permanently, silently lost
//     page — during the outage it was reporting.
//  3. NO OBSERVABILITY. An unstructured log.Printf and no counter of any kind,
//     so "did the page go out?" was unanswerable after the fact.
//
// The queue is bounded and a full queue is COUNTED AND LOGGED, never silently
// dropped: under a storm the platform says "I shed N pages" instead of
// pretending it delivered them.

const (
	// deliveryQueueSize bounds queued sends. Deep enough to absorb a storm tick
	// (a few thousand alerts × channels), shallow enough that the memory is
	// bounded and a wedged provider surfaces as shed pages rather than a heap.
	deliveryQueueSize = 4096
	// deliveryWorkers bounds CONCURRENT outbound sends across all channels —
	// the number the 30,000 goroutines above collapse into.
	deliveryWorkers = 8
	// deliveryAttempts is the total tries per send (1 initial + 3 retries).
	deliveryAttempts = 4
	// deliveryRetryBase is the first backoff step; each retry doubles it and
	// applies ±50% jitter so a recovering provider is not re-stormed in lockstep.
	deliveryRetryBase = 500 * time.Millisecond
	// deliverySendBudget bounds the total wall time one alert may spend being
	// retried, so a tarpitting provider cannot hold a worker forever.
	deliverySendBudget = 90 * time.Second
	// errBodyMaxBytes bounds how much of a provider's ERROR body is read into a
	// Go error string (F-27 class). Diagnostic text, not a payload.
	errBodyMaxBytes = 4 << 10
)

// Logger receives a structured delivery event. Injected (not a package global)
// so the API routes it into the same JSON log as everything else, while tests
// and standalone binaries can supply their own. A nil Logger discards — the
// counters are still kept, so nothing becomes invisible.
type Logger func(level, msg string, fields map[string]any)

// channelStats is the per-channel delivery record exposed on /metrics.
type channelStats struct {
	sent    atomic.Uint64
	failed  atomic.Uint64
	retries atomic.Uint64
	dropped atomic.Uint64
}

// sendJob is one queued delivery attempt.
type sendJob struct {
	ch      Channel
	alert   models.Alert
	resolve bool
}

// delivery is the worker pool. Workers start lazily on the first enqueue, so a
// Dispatcher that is constructed and never used (every unit test that builds
// one) spawns nothing.
type delivery struct {
	start     sync.Once
	closeOnce sync.Once
	jobs      chan sendJob
	quit      chan struct{}
	wg        sync.WaitGroup

	mu    sync.Mutex
	stats map[string]*channelStats

	logMu sync.RWMutex
	log   Logger

	// sleep is the backoff seam: returns false if the wait was cut short.
	// Overridden in tests so retry behaviour is asserted without real delays.
	sleep func(ctx context.Context, d time.Duration) bool
}

func newDelivery() *delivery {
	return &delivery{
		jobs:  make(chan sendJob, deliveryQueueSize),
		quit:  make(chan struct{}),
		stats: map[string]*channelStats{},
		sleep: sleepCtx,
	}
}

// SetLogger installs the structured logger for delivery events.
func (d *Dispatcher) SetLogger(l Logger) {
	d.delivery.logMu.Lock()
	defer d.delivery.logMu.Unlock()
	d.delivery.log = l
}

func (dl *delivery) logf(level, msg string, fields map[string]any) {
	dl.logMu.RLock()
	l := dl.log
	dl.logMu.RUnlock()
	if l != nil {
		l(level, msg, fields)
	}
}

func (dl *delivery) statsFor(name string) *channelStats {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	s := dl.stats[name]
	if s == nil {
		s = &channelStats{}
		dl.stats[name] = s
	}
	return s
}

// enqueue submits a send. It NEVER blocks the caller (the alert engine's
// evaluation tick): a full queue is refused, counted and logged as a lost page,
// which is the honest answer under overload — §9 bounded queue + backpressure,
// §10 no silent failure.
func (dl *delivery) enqueue(j sendJob) {
	dl.startWorkers()
	select {
	case dl.jobs <- j:
	default:
		dl.statsFor(j.ch.Name()).dropped.Add(1)
		dl.logf("error", "notification DROPPED — delivery queue full", map[string]any{
			"channel":  j.ch.Name(),
			"alert_id": j.alert.ID,
			"rule":     j.alert.Rule,
			"severity": j.alert.Severity,
			"queue":    deliveryQueueSize,
		})
	}
}

func (dl *delivery) startWorkers() {
	dl.start.Do(func() {
		for i := 0; i < deliveryWorkers; i++ {
			dl.wg.Add(1)
			go dl.worker()
		}
	})
}

func (dl *delivery) worker() {
	defer dl.wg.Done()
	for {
		select {
		case <-dl.quit:
			return
		case j := <-dl.jobs:
			dl.deliver(j)
		}
	}
}

// deliver runs one job with bounded retries. Retriability is not knowable from
// the Channel interface (it returns a bare error), so every failure is retried
// within the attempt/time budget: a duplicate page is a far cheaper mistake
// than a missing one, and the channels that can dedupe (PagerDuty dedup_key,
// ServiceNow correlation id) already do.
func (dl *delivery) deliver(j sendJob) {
	name := j.ch.Name()
	st := dl.statsFor(name)

	ctx, cancel := context.WithTimeout(context.Background(), deliverySendBudget)
	defer cancel()

	var lastErr error
	for attempt := 1; attempt <= deliveryAttempts; attempt++ {
		err := send(j)
		if err == nil {
			st.sent.Add(1)
			if attempt > 1 {
				dl.logf("info", "notification delivered after retry", map[string]any{
					"channel": name, "alert_id": j.alert.ID, "attempts": attempt, "resolve": j.resolve,
				})
			}
			return
		}
		lastErr = err
		if attempt == deliveryAttempts {
			break
		}
		st.retries.Add(1)
		if !dl.sleep(ctx, backoff(attempt)) {
			break // budget exhausted — stop burning the worker
		}
	}
	st.failed.Add(1)
	dl.logf("error", "notification delivery FAILED after retries — this page did not go out", map[string]any{
		"channel":  name,
		"alert_id": j.alert.ID,
		"rule":     j.alert.Rule,
		"severity": j.alert.Severity,
		"resolve":  j.resolve,
		"attempts": deliveryAttempts,
		"err":      errText(lastErr),
	})
}

func send(j sendJob) error {
	if j.resolve {
		rs, ok := j.ch.(ResolveSender)
		if !ok {
			return nil
		}
		return rs.SendResolve(j.alert)
	}
	return j.ch.Send(j.alert)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// backoff is base·2^(attempt-1) with ±50% jitter. The jitter is per-CALL, not
// derived from the attempt number: 5,000 alerts queued behind one recovering
// provider must not all retry in the same millisecond (that is the F-28 defect
// in the ticketing outbox, which derives its jitter from the attempt count and
// so gives every item at attempt N an identical delay).
func backoff(attempt int) time.Duration {
	d := deliveryRetryBase << (attempt - 1)
	// #nosec G404 -- retry scheduling jitter, not a security context.
	return d + time.Duration(rand.Int64N(int64(d))) - d/2
}

// sleepCtx waits d unless ctx dies first; false means it was cut short.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Close stops the workers and waits for in-flight sends, so shutdown does not
// abandon a page mid-flight. Safe to call on a Dispatcher that never dispatched.
func (d *Dispatcher) Close() {
	dl := d.delivery
	dl.closeOnce.Do(func() { close(dl.quit) })
	dl.wg.Wait()
}

// QueueDepth reports queued-but-unsent notifications (metrics + tests).
func (d *Dispatcher) QueueDepth() int { return len(d.delivery.jobs) }

// deliveryCounts is a point-in-time copy of one channel's delivery record.
type deliveryCounts struct{ sent, failed, retries, dropped uint64 }

// statsSnapshot reads a channel's counters without exposing the atomics.
func (d *Dispatcher) statsSnapshot(channel string) deliveryCounts {
	s := d.delivery.statsFor(channel)
	return deliveryCounts{
		sent:    s.sent.Load(),
		failed:  s.failed.Load(),
		retries: s.retries.Load(),
		dropped: s.dropped.Load(),
	}
}

// WriteMetrics emits the Prometheus exposition for alert delivery. Before F-22
// there was NO notify counter anywhere, so a page lost to a transient 502
// during an incident left no trace at all.
func (d *Dispatcher) WriteMetrics(w io.Writer) {
	if d == nil {
		return
	}
	dl := d.delivery
	dl.mu.Lock()
	names := make([]string, 0, len(dl.stats))
	for n := range dl.stats {
		names = append(names, n)
	}
	snapshot := make(map[string]*channelStats, len(dl.stats))
	for n, s := range dl.stats {
		snapshot[n] = s
	}
	dl.mu.Unlock()
	sort.Strings(names) // stable output

	fmt.Fprintf(w, "# HELP netops_notify_sent_total Alert notifications delivered.\n")
	fmt.Fprintf(w, "# TYPE netops_notify_sent_total counter\n")
	fmt.Fprintf(w, "# HELP netops_notify_failures_total Alert notifications that exhausted their retries — pages that did NOT go out.\n")
	fmt.Fprintf(w, "# TYPE netops_notify_failures_total counter\n")
	fmt.Fprintf(w, "# HELP netops_notify_retries_total Notification send retries.\n")
	fmt.Fprintf(w, "# TYPE netops_notify_retries_total counter\n")
	fmt.Fprintf(w, "# HELP netops_notify_dropped_total Notifications shed because the bounded delivery queue was full.\n")
	fmt.Fprintf(w, "# TYPE netops_notify_dropped_total counter\n")
	for _, n := range names {
		s := snapshot[n]
		fmt.Fprintf(w, "netops_notify_sent_total{channel=%q} %d\n", n, s.sent.Load())
		fmt.Fprintf(w, "netops_notify_failures_total{channel=%q} %d\n", n, s.failed.Load())
		fmt.Fprintf(w, "netops_notify_retries_total{channel=%q} %d\n", n, s.retries.Load())
		fmt.Fprintf(w, "netops_notify_dropped_total{channel=%q} %d\n", n, s.dropped.Load())
	}
	fmt.Fprintf(w, "# HELP netops_notify_queue_depth Notifications queued for delivery.\n")
	fmt.Fprintf(w, "# TYPE netops_notify_queue_depth gauge\n")
	fmt.Fprintf(w, "netops_notify_queue_depth %d\n", len(dl.jobs))
}
