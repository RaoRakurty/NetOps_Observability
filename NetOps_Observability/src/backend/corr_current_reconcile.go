package main

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
// The drift scan is bounded to a lookback window (default 7 days): an object
// that has not persisted a version inside the window cannot have drifted
// inside it, and anything older that is missing outright is covered by the
// boot-time backfill's full (but narrow) fold.
//
// Repaired rows lose only engine-derived, env-dependent decoration that
// history does not carry (chaos_fixture): the next engine persist re-tags it.

import (
	"context"
	"log"
	"netops/backend/internal/chschema"
	"strconv"
	"time"
)

// chschema.CorrCurrentNarrowInsertPrefix is the shared INSERT head for every corr_current
// repair: narrow columns + triage badges JSONExtract'd from the hypotheses blob
// keyed by an already-picked version set (never through a fold/sort).

// chschema.CorrCurrentBackfillSQL repairs MISSING corr_current rows from history —
// idempotent (NOT IN makes a re-run a no-op). Runs in the boot converge list
// (corr_schema.go) and from the periodic reconciler.

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
	orphanHours := 24
	if raw := envOr("CORR_ORPHAN_OPEN_CLOSE_HOURS", ""); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			orphanHours = n
		}
	}
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Orphaned-open sweep FIRST: the closing versions it writes are exactly
		// what the drift repair below re-projects in the same tick.
		if orphanHours > 0 {
			rows, err := s.chRowsScope(ctx, "__all__", chschema.CorrOrphanCountSQL(orphanHours),
				"worker:corr-current-reconcile")
			n := 0
			if err == nil && len(rows) == 1 {
				n = int(asFloat(rows[0]["orphaned"]))
			}
			if err != nil {
				log.Printf("corr-current-reconcile: orphan count failed: %v", err)
			} else if n > 0 {
				log.Printf("corr-current-reconcile: orphaned_open=%d threshold_hours=%d action=close", n, orphanHours)
				if msg := chExecErr(base, chschema.CorrOrphanCloseSQL(orphanHours)); msg != "" {
					log.Printf("corr-current-reconcile: orphan close failed: %s", msg)
				} else {
					log.Printf("corr-current-reconcile: orphan_closed=%d (janitor closing versions written to history)", n)
				}
			}
		}
		rows, err := s.chRowsScope(ctx, "__all__", chschema.CorrDriftCountSQL(lookback),
			"worker:corr-current-reconcile")
		if err != nil {
			log.Printf("corr-current-reconcile: drift count failed: %v", err)
			continue
		}
		drifted := 0
		if len(rows) == 1 {
			drifted = int(asFloat(rows[0]["drifted"]))
		}
		if drifted == 0 {
			continue
		}
		// Structured, observable repair (§10): stale hot-read rows were found —
		// the projection dual-write lost writes (see the engine's
		// corr_current_projection_write_failures_total for the cause).
		log.Printf("corr-current-reconcile: drifted_rows=%d lookback_days=%d action=repair", drifted, lookback)
		if msg := chExecErr(base, chschema.CorrDriftRepairSQL(lookback)); msg != "" {
			log.Printf("corr-current-reconcile: repair failed: %s", msg)
			continue
		}
		log.Printf("corr-current-reconcile: repaired=%d (projection re-seeded from corr_objects)", drifted)
	}
}
