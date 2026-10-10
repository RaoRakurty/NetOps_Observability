// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// corr_current_reconcile.go — corr_current projection repair (#101).
//
// corr_current is the hot-read source of truth for Command Center (#100), but
// it is maintained by an app-level dual-write from the correlation engine: the
// history insert (corr_objects) is the truth write, and the projection insert
// can fail independently (observable via the engine's
// corr_current_projection_write_failures_total counter and the
// CorrCurrentProjectionFailing alert). A failed projection write means a STALE
// Command Center row until the object's next material persist — for a quiesced
// or closed object, that can be forever.
//
// This reconciler closes the loop with two idempotent repairs, both in the
// sanctioned #100 read shape (NARROW fold; the wide hypotheses blob is only
// ever JSONExtract'd keyed by the already-picked (tenant, id, version) set):
//
//  1. MISSING rows — an object with history but no corr_current row at all
//     (also the fresh-upgrade backfill; runs once per boot since #100).
//  2. DRIFTED rows — corr_current's row is OLDER than the object's latest
//     history version (created_at comparison, not version: engine restarts
//     reset in-memory versions to 1, and ReplacingMergeTree(created_at)
//     already encodes "latest write wins").
//
// The drift scan is bounded to a lookback window (default 7 days) — cheap, but
// on its own it was NOT enough: drift older than the window, and a stale row
// NEWER than history (a heartbeat touch landing after the close), were both
// permanent (tracker 328: 56,397 of 56,402 'open' rows wrong on the lab).
//  3. STATE-DRIFTED rows — projection says open, newest history row says
//     terminal, at any age. Keyed to the projection's open set, so it stays
//     cheap; repaired with a fresh created_at so it wins the fold.
//
// Every pass publishes what it found and repaired (netops_corr_current_*), so
// drift that the repair cannot clear is an alert, not a log line.
//
// Repaired rows lose only engine-derived, env-dependent decoration that
// history does not carry (chaos_fixture): the next engine persist re-tags it.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"netops/backend/internal/chschema"
	"strconv"
	"sync/atomic"
	"time"
)

// chschema.CorrCurrentNarrowInsertPrefix is the shared INSERT head for every corr_current
// repair: narrow columns + triage badges JSONExtract'd from the hypotheses blob
// keyed by an already-picked version set (never through a fold/sort).

// chschema.CorrCurrentBackfillSQL repairs MISSING corr_current rows from history —
// idempotent (NOT IN makes a re-run a no-op). Runs in the boot converge list
// (corr_schema.go) and from the periodic reconciler.

// corrOrphanOpenCloseHoursDefault is the age at which an 'open' corr_current
// row stops being a live problem: the engine re-persists every live open object
// at least every CORR_VERSION_HEARTBEAT_S (900 s), so a row this stale is an
// orphan (its engine lost the in-memory window at restart) awaiting a closing
// version.
const corrOrphanOpenCloseHoursDefault = 24

// corrOrphanOpenCloseHours resolves CORR_ORPHAN_OPEN_CLOSE_HOURS (0 = orphan
// sweep disabled). ONE source of truth on purpose: the sweep that force-closes
// stale open rows and every reader that asks "is this problem still live?" must
// share a horizon, or they report different realities for the same object.
func corrOrphanOpenCloseHours() int {
	if raw := envOr("CORR_ORPHAN_OPEN_CLOSE_HOURS", ""); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			return n
		}
	}
	return corrOrphanOpenCloseHoursDefault
}

// corrReconcileStats is what the reconciler last saw and has repaired, for
// /metrics. Gauges describe the newest pass; counters are monotonic.
type corrReconcileStats struct {
	lastRunUnix       atomic.Int64
	orphaned          atomic.Int64
	drifted           atomic.Int64
	stateDrifted      atomic.Int64
	repairedTotal     atomic.Int64 // rows re-projected (drift + state drift)
	orphanClosedTotal atomic.Int64
	failuresTotal     atomic.Int64 // any step that errored
}

// WriteMetrics renders the reconciler's gauges and counters.
func (st *corrReconcileStats) WriteMetrics(w io.Writer) {
	fmt.Fprint(w, "# HELP netops_corr_current_reconcile_last_run_timestamp_seconds When the corr_current reconciler last completed a pass (0 = never).\n")
	fmt.Fprint(w, "# TYPE netops_corr_current_reconcile_last_run_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "netops_corr_current_reconcile_last_run_timestamp_seconds %d\n", st.lastRunUnix.Load())
	fmt.Fprint(w, "# HELP netops_corr_current_drift_rows corr_current rows found wrong on the newest pass, by kind (orphaned = open with no persist past the horizon; drifted = older than history inside the lookback; state_drifted = open while history is terminal, any age).\n")
	fmt.Fprint(w, "# TYPE netops_corr_current_drift_rows gauge\n")
	fmt.Fprintf(w, "netops_corr_current_drift_rows{kind=\"orphaned\"} %d\n", st.orphaned.Load())
	fmt.Fprintf(w, "netops_corr_current_drift_rows{kind=\"drifted\"} %d\n", st.drifted.Load())
	fmt.Fprintf(w, "netops_corr_current_drift_rows{kind=\"state_drifted\"} %d\n", st.stateDrifted.Load())
	fmt.Fprint(w, "# HELP netops_corr_current_repaired_rows_total corr_current rows re-projected from history by the reconciler.\n")
	fmt.Fprint(w, "# TYPE netops_corr_current_repaired_rows_total counter\n")
	fmt.Fprintf(w, "netops_corr_current_repaired_rows_total %d\n", st.repairedTotal.Load())
	fmt.Fprint(w, "# HELP netops_corr_current_orphan_closed_total Orphaned open objects the reconciler closed through history.\n")
	fmt.Fprint(w, "# TYPE netops_corr_current_orphan_closed_total counter\n")
	fmt.Fprintf(w, "netops_corr_current_orphan_closed_total %d\n", st.orphanClosedTotal.Load())
	fmt.Fprint(w, "# HELP netops_corr_current_reconcile_failures_total Reconciler steps that errored (count or repair).\n")
	fmt.Fprint(w, "# TYPE netops_corr_current_reconcile_failures_total counter\n")
	fmt.Fprintf(w, "netops_corr_current_reconcile_failures_total %d\n", st.failuresTotal.Load())
}

// corrReconcileCH is the ClickHouse surface one pass needs — injectable so the
// pass is testable without a server.
type corrReconcileCH interface {
	count(ctx context.Context, sql, column string) (int, error)
	exec(ctx context.Context, sql string) error
}

type serverReconcileCH struct {
	s    *server
	base string
}

func (c serverReconcileCH) count(ctx context.Context, sql, column string) (int, error) {
	rows, err := c.s.chRowsScope(ctx, "__all__", sql, "worker:corr-current-reconcile")
	if err != nil {
		return 0, err
	}
	if len(rows) != 1 {
		return 0, fmt.Errorf("count returned %d rows, want 1", len(rows))
	}
	return int(asFloat(rows[0][column])), nil
}

func (c serverReconcileCH) exec(_ context.Context, sql string) error {
	if msg := chExecErr(c.base, sql); msg != "" {
		return errors.New(msg)
	}
	return nil
}

// corrReconcilePass runs one reconcile pass. Each step is independent: a failed
// step is counted and logged and the next step still runs (a broken drift count
// must not also stop the state repair — that is how drift became permanent).
func corrReconcilePass(ctx context.Context, ch corrReconcileCH, st *corrReconcileStats, lookbackDays, orphanHours int) {
	fail := func(step string, err error) {
		st.failuresTotal.Add(1)
		log.Printf("corr-current-reconcile: %s failed: %v", step, err)
	}
	// Orphaned-open sweep FIRST: the closing versions it writes are exactly
	// what the drift repair below re-projects in the same pass.
	st.orphaned.Store(0)
	if orphanHours > 0 {
		if n, err := ch.count(ctx, chschema.CorrOrphanCountSQL(orphanHours), "orphaned"); err != nil {
			fail("orphan count", err)
		} else {
			st.orphaned.Store(int64(n))
			if n > 0 {
				log.Printf("corr-current-reconcile: orphaned_open=%d threshold_hours=%d action=close", n, orphanHours)
				if err := ch.exec(ctx, chschema.CorrOrphanCloseSQL(orphanHours)); err != nil {
					fail("orphan close", err)
				} else {
					st.orphanClosedTotal.Add(int64(n))
					log.Printf("corr-current-reconcile: orphan_closed=%d (janitor closing versions written to history)", n)
				}
			}
		}
	}
	// Drift inside the lookback: a projection write was lost.
	if n, err := ch.count(ctx, chschema.CorrDriftCountSQL(lookbackDays), "drifted"); err != nil {
		fail("drift count", err)
	} else {
		st.drifted.Store(int64(n))
		if n > 0 {
			// Structured, observable repair (§10): the projection dual-write
			// lost writes (see the engine's corr_current_projection_write_failures_total).
			log.Printf("corr-current-reconcile: drifted_rows=%d lookback_days=%d action=repair", n, lookbackDays)
			if err := ch.exec(ctx, chschema.CorrDriftRepairSQL(lookbackDays)); err != nil {
				fail("drift repair", err)
			} else {
				st.repairedTotal.Add(int64(n))
				log.Printf("corr-current-reconcile: repaired=%d (projection re-seeded from corr_objects)", n)
			}
		}
	}
	// State drift at any age (tracker 328).
	if n, err := ch.count(ctx, chschema.CorrStateDriftCountSQL(), "state_drifted"); err != nil {
		fail("state drift count", err)
	} else {
		st.stateDrifted.Store(int64(n))
		if n > 0 {
			log.Printf("corr-current-reconcile: state_drifted_rows=%d action=repair (open in projection, terminal in history)", n)
			if err := ch.exec(ctx, chschema.CorrStateDriftRepairSQL()); err != nil {
				fail("state drift repair", err)
			} else {
				st.repairedTotal.Add(int64(n))
				log.Printf("corr-current-reconcile: state_repaired=%d (projection re-seeded from history, restamped)", n)
			}
		}
	}
	st.lastRunUnix.Store(time.Now().Unix())
}

func (s *server) corrCurrentReconcileLoop(ctx context.Context) {
	interval := durationOr("CORR_CURRENT_RECONCILE_INTERVAL", time.Hour)
	if interval <= 0 {
		log.Printf("corr-current-reconcile: disabled (CORR_CURRENT_RECONCILE_INTERVAL=0)")
		return
	}
	lookback := 7
	if raw := envOr("CORR_CURRENT_RECONCILE_LOOKBACK_DAYS", ""); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			lookback = n
		}
	}
	orphanHours := corrOrphanOpenCloseHours()
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return
	}
	ch := serverReconcileCH{s: s, base: base}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		corrReconcilePass(ctx, ch, &s.corrReconcile, lookback, orphanHours)
	}
}
