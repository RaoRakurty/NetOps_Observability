// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// recorder.go — the sampling loop and the module's own metrics.
//
// SAMPLING SHAPE (owner decision, 2026-09-05): an hourly snapshot folded into a
// persisted daily roll-up. Hourly is chosen against both ends: a per-minute
// sample would write a row 1,440 times a day to move a number that changes when
// an operator clicks something, and a once-a-day sample would miss the peak
// entirely — a fleet that doubled for four hours would be invisible.
//
// THE RECORDER NEVER GATES ANYTHING. It has no admission path and returns its
// errors to a log, not to a caller who could be blocked by them. A metering
// outage costs a usage report some hours; it can never refuse a device, a
// login, or a page.

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// Sampler produces one snapshot: tenant key → that tenant's readings, with
// ScopeInstallation ("") carrying the installation-wide meters.
//
// It is the ONLY seam through which this package learns anything about the
// platform. internal/metering imports no store, no client and no registry: the
// composition root hands it a function, which is what keeps the data contract
// testable without a stack (the internal/licence precedent).
type Sampler func(ctx context.Context) map[string][]Reading

// DefaultInterval is how often a snapshot is taken.
const DefaultInterval = time.Hour

// Recorder samples on a schedule and folds each snapshot into the day.
type Recorder struct {
	store  Store
	sample Sampler
	warn   func(msg string, err error)
	now    func() time.Time

	// lastSnapshot is the unix second of the last SUCCESSFUL fold, 0 when there
	// has never been one. A zero is a value, not a gap: the alert rule guards on
	// `> 0` so a fresh boot is silent and a stopped recorder is not.
	lastSnapshot atomic.Int64
	// rows is the persisted row count as of the last snapshot.
	rows atomic.Int64
	// failures counts snapshots that did not land. §10: no silent failures.
	failures atomic.Int64
	// pruned counts rows dropped by the retention sweep.
	pruned atomic.Int64
}

// NewRecorder builds the recorder. warn may be nil.
func NewRecorder(store Store, sample Sampler, warn func(msg string, err error)) *Recorder {
	return &Recorder{
		store:  store,
		sample: sample,
		warn:   warn,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Snapshot takes one sample and folds it into the day's rows, then keeps the
// retention bound.
//
// It returns the error as well as recording it, so a caller that wants to know
// (the tests, a future admin action) can, while the loop simply logs.
func (r *Recorder) Snapshot(ctx context.Context) error {
	if r == nil || r.store == nil || r.sample == nil {
		return fmt.Errorf("metering: the recorder is not wired — no usage is being recorded")
	}
	at := r.now().UTC()
	readings := r.sample(ctx)
	if err := r.store.Record(ctx, at, readings); err != nil {
		r.failures.Add(1)
		r.fail("metering: this hour's usage snapshot was not recorded; the day's roll-up is short one sample", err)
		return err
	}
	r.lastSnapshot.Store(at.Unix())

	if n, err := r.store.Prune(ctx, PruneHorizon(at)); err != nil {
		// A prune that fails does NOT fail the snapshot: the numbers are
		// recorded, the history is simply longer than it should be, and that is
		// an operator's problem rather than a lost measurement.
		r.fail(fmt.Sprintf("metering: usage history older than %d days could not be pruned; it is being kept instead", RetentionDays), err)
	} else if n > 0 {
		r.pruned.Add(int64(n))
	}
	if n, err := r.store.Rows(ctx); err == nil {
		r.rows.Store(int64(n))
	}
	return nil
}

// Run takes a snapshot immediately and then every interval until ctx is done.
//
// The first snapshot is immediate on purpose: an api that has just started must
// publish a snapshot timestamp promptly, or the staleness rule spends its first
// hour unable to tell "just booted" from "stopped recording".
func (r *Recorder) Run(ctx context.Context, interval time.Duration) {
	if r == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	_ = r.Snapshot(ctx) // best-effort: Snapshot records and logs its own failure; the loop must still start
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.Snapshot(ctx) // best-effort: recorded in the failure counter and the log; a bad hour must not stop the loop
		}
	}
}

// LastSnapshot is when the last successful fold happened, zero if never.
func (r *Recorder) LastSnapshot() time.Time {
	if r == nil {
		return time.Time{}
	}
	sec := r.lastSnapshot.Load()
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

func (r *Recorder) fail(msg string, err error) {
	if r.warn != nil {
		r.warn(msg, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Metrics
// ─────────────────────────────────────────────────────────────────────────────

// Metric names. All four are emitted on EVERY scrape, including as zeros: a
// series that vanishes is indistinguishable from a scrape failure, and that
// ambiguity is what the 2026-09-02 outage was made of.
const (
	// MetricSnapshotTimestamp is the unix second of the last successful usage
	// snapshot, 0 = never. The staleness rule divides on it.
	MetricSnapshotTimestamp = "netops_metering_snapshot_timestamp_seconds"
	// MetricDailyRows is how many daily usage rows are persisted.
	MetricDailyRows = "netops_metering_daily_rows"
	// MetricSnapshotFailures counts snapshots that did not land.
	MetricSnapshotFailures = "netops_metering_snapshot_failures_total"
	// MetricPrunedRows counts rows dropped by the retention sweep.
	MetricPrunedRows = "netops_metering_pruned_rows_total"
)

// WriteMetrics emits the module's gauges and counters in Prometheus text
// format. Nil-safe, and it never blocks: every value is read from an atomic
// that the sampling loop already updated.
func (r *Recorder) WriteMetrics(w io.Writer) {
	if w == nil {
		return
	}
	var last, rows, failures, pruned int64
	if r != nil {
		last, rows = r.lastSnapshot.Load(), r.rows.Load()
		failures, pruned = r.failures.Load(), r.pruned.Load()
	}
	gauge(w, MetricSnapshotTimestamp,
		"Unix time of the last usage snapshot folded into the daily metering rows (0 = none yet). Metering never gates anything; a stale value costs a usage report, not a collection.", last)
	gauge(w, MetricDailyRows,
		"Daily usage rows currently persisted, across every tenant and the installation row.", rows)
	counter(w, MetricSnapshotFailures,
		"Usage snapshots that could not be recorded. Each one is an hour missing from a day's roll-up.", failures)
	counter(w, MetricPrunedRows,
		"Daily usage rows dropped by the retention sweep.", pruned)
}

func gauge(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
}

func counter(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}
