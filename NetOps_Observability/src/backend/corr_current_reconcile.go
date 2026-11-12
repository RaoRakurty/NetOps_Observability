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
// Every write is a BOUNDED batch (CORR_CURRENT_RECONCILE_BATCH objects, at most
// CORR_CURRENT_RECONCILE_MAX_BATCHES statements per step per pass): each repair
// runs under the 10 s exec budget and reads the wide hypotheses blob per row,
// so an unbounded statement over a large backlog could fail every pass and
// leave the drift permanent by another route (tracker 328, 2026-11-12).
//
// Repaired rows lose only engine-derived, env-dependent decoration that
// history does not carry (chaos_fixture): the next engine persist re-tags it.

import (
	"context"
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

// exec runs one repair statement under the exec budget (chDDLBudget) AND the
// loop's context, so a shutdown abandons an in-flight batch instead of waiting
// it out (§9: every IO is bounded).
func (c serverReconcileCH) exec(ctx context.Context, sql string) error {
	if err := chExecErrTyped(ctx, c.base, sql); err != nil {
		return fmt.Errorf("%s: %w", chStatementHead(sql), err)
	}
	return nil
}

// corrReconcileConfig is one pass's tuning, resolved once from the env.
type corrReconcileConfig struct {
	lookbackDays int // drift scan window on history (floor 1)
	orphanHours  int // orphan horizon (0 = sweep disabled)
	batch        int // objects per repair statement
	maxBatches   int // repair statements per step per pass
}

const (
	// corrReconcileBatchDefault: ~0.4 s / ~22 MiB of the repair's wide read on
	// the lab (2026-11-12 measurement, scaled) — far inside the 10 s exec budget.
	corrReconcileBatchDefault = 5000
	corrReconcileBatchCeiling = 50000
	// corrReconcileMaxBatchesDefault: 100k objects per step per pass at the
	// default batch, so the 2026-09-19 backlog (56k) drains in one pass.
	corrReconcileMaxBatchesDefault = 20
	corrReconcileMaxBatchesCeiling = 200
)

// envIntInRange reads a positive int knob; anything unparseable or below 1
// falls back to def, anything above ceiling is clamped (a typo can slow the
// repair down or bound it tighter, never make it unbounded).
func envIntInRange(key string, def, ceiling int) int {
	raw := envOr(key, "")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return def
	}
	if n > ceiling {
		return ceiling
	}
	return n
}

// corrReconcileConfigFromEnv resolves every reconciler knob.
func corrReconcileConfigFromEnv() corrReconcileConfig {
	return corrReconcileConfig{
		lookbackDays: envIntInRange("CORR_CURRENT_RECONCILE_LOOKBACK_DAYS", 7, 3650),
		orphanHours:  corrOrphanOpenCloseHours(),
		batch:        envIntInRange("CORR_CURRENT_RECONCILE_BATCH", corrReconcileBatchDefault, corrReconcileBatchCeiling),
		maxBatches:   envIntInRange("CORR_CURRENT_RECONCILE_MAX_BATCHES", corrReconcileMaxBatchesDefault, corrReconcileMaxBatchesCeiling),
	}
}

// repairInBatches drains `found` rows with bounded statements: ceil(found/batch)
// batches, capped at maxBatches, stopping on the first error or a cancelled
// context. Each statement re-picks, and rows a previous batch repaired have
// left the pick (they are no longer drifted/open), so batches make progress and
// an extra batch is a no-op. Returns the rows claimed repaired — an estimate
// from the count (rows that change between the count and the insert are picked
// up or dropped by the next pass), never more than were found.
func repairInBatches(ctx context.Context, ch corrReconcileCH, found int, cfg corrReconcileConfig, stmt func(limit int) string) (int, error) {
	batch := max(cfg.batch, 1)
	batches := min((found+batch-1)/batch, max(cfg.maxBatches, 1))
	repaired := 0
	for i := 0; i < batches; i++ {
		if err := ctx.Err(); err != nil {
			return repaired, err
		}
		if err := ch.exec(ctx, stmt(batch)); err != nil {
			return repaired, err
		}
		repaired += min(batch, found-repaired)
	}
	return repaired, nil
}

// corrReconcilePass runs one reconcile pass. Each step is independent: a failed
// step is counted and logged and the next step still runs (a broken drift count
// must not also stop the state repair — that is how drift became permanent).
// Gauges report what each step FOUND (the whole backlog); repairs are bounded
// batches, so a backlog larger than one pass's budget drains over passes and
// logs its residue.
func corrReconcilePass(ctx context.Context, ch corrReconcileCH, st *corrReconcileStats, cfg corrReconcileConfig) {
	fail := func(step string, err error) {
		if ctx.Err() != nil {
			// Shutdown, not a fault: the next boot's pass resumes the drain.
			log.Printf("corr-current-reconcile: %s abandoned (context done): %v", step, err)
			return
		}
		st.failuresTotal.Add(1)
		log.Printf("corr-current-reconcile: %s failed: %v", step, err)
	}
	// step counts one kind, publishes the gauge, then repairs it in batches.
	step := func(name, column, countSQL string, gauge *atomic.Int64, done *atomic.Int64, stmt func(int) string) {
		n, err := ch.count(ctx, countSQL, column)
		if err != nil {
			fail(name+" count", err)
			return
		}
		gauge.Store(int64(n))
		if n == 0 {
			return
		}
		log.Printf("corr-current-reconcile: step=%s found=%d batch=%d max_batches=%d action=repair", name, n, cfg.batch, cfg.maxBatches)
		repaired, err := repairInBatches(ctx, ch, n, cfg, stmt)
		done.Add(int64(repaired))
		if err != nil {
			fail(name+" repair", err)
		}
		log.Printf("corr-current-reconcile: step=%s repaired=%d residual=%d", name, repaired, n-repaired)
	}
	// Orphaned-open sweep FIRST: the closing versions it writes are exactly
	// what the drift repair below re-projects in the same pass.
	st.orphaned.Store(0)
	if cfg.orphanHours > 0 {
		step("orphan", "orphaned", chschema.CorrOrphanCountSQL(cfg.orphanHours), &st.orphaned, &st.orphanClosedTotal,
			func(limit int) string { return chschema.CorrOrphanCloseSQL(cfg.orphanHours, limit) })
	}
	// Drift inside the lookback: a projection write was lost (see the engine's
	// corr_current_projection_write_failures_total).
	step("drift", "drifted", chschema.CorrDriftCountSQL(cfg.lookbackDays), &st.drifted, &st.repairedTotal,
		func(limit int) string { return chschema.CorrDriftRepairSQL(cfg.lookbackDays, limit) })
	// State drift at any age (tracker 328): open in the projection, terminal in
	// history, however old the terminal version is.
	step("state_drift", "state_drifted", chschema.CorrStateDriftCountSQL(), &st.stateDrifted, &st.repairedTotal,
		chschema.CorrStateDriftRepairSQL)
	st.lastRunUnix.Store(time.Now().Unix())
}

func (s *server) corrCurrentReconcileLoop(ctx context.Context) {
	interval := durationOr("CORR_CURRENT_RECONCILE_INTERVAL", time.Hour)
	if interval <= 0 {
		log.Printf("corr-current-reconcile: disabled (CORR_CURRENT_RECONCILE_INTERVAL=0)")
		return
	}
	cfg := corrReconcileConfigFromEnv()
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
		corrReconcilePass(ctx, ch, &s.corrReconcile, cfg)
	}
}
