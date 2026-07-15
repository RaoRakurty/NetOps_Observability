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
	"strconv"
	"time"
)

// corrCurrentNarrowInsertPrefix is the shared INSERT head for every corr_current
// repair: narrow columns + triage badges JSONExtract'd from the hypotheses blob
// keyed by an already-picked version set (never through a fold/sort).
const corrCurrentNarrowInsertPrefix = `INSERT INTO netops.corr_current
    (tenant_id, correlation_id, version, state, window_start, window_end,
     top_hypothesis, top_confidence, verdict_tier, evidence_missing, affected,
     signal_count, node_count, engine_version, catalog_version, merged_into,
     created_at, owner, plane_count, debug_excluded, low_authority)
SELECT o.tenant_id, o.correlation_id, o.version, o.state, o.window_start, o.window_end,
       o.top_hypothesis, o.top_confidence, o.verdict_tier, o.evidence_missing, o.affected,
       o.signal_count, o.node_count, o.engine_version, o.catalog_version, o.merged_into,
       o.created_at,
       JSONExtractString(o.hypotheses,'ranking','hypotheses',1,'verdict','owner'),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','modality_coverage','Array(String)'))),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','excluded_debug_probes','Array(String)')) > 0),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','low_authority_probe_scopes','Array(String)')) > 0)
  FROM netops.corr_objects AS o
 WHERE (o.tenant_id, o.correlation_id, o.version) IN (`

// corrCurrentBackfillSQL repairs MISSING corr_current rows from history —
// idempotent (NOT IN makes a re-run a no-op). Runs in the boot converge list
// (corr_schema.go) and from the periodic reconciler.
func corrCurrentBackfillSQL() string {
	return corrCurrentNarrowInsertPrefix + `
       SELECT tenant_id, correlation_id, version
         FROM netops.corr_objects
        WHERE (tenant_id, correlation_id) NOT IN
              (SELECT tenant_id, correlation_id FROM netops.corr_current)
        ORDER BY tenant_id, correlation_id, version DESC
        LIMIT 1 BY tenant_id, correlation_id)`
}

// corrCurrentDriftSelect picks (tenant, id, version) of objects whose latest
// in-window history row is NEWER than the corr_current row — i.e. a projection
// write was lost. Missing rows also match (the LEFT JOIN default epoch
// created_at is older than any real row), so one statement repairs both inside
// the window. Narrow fold, created_at-bounded base scan.
func corrCurrentDriftSelect(lookbackDays int) string {
	d := strconv.Itoa(lookbackDays)
	return `
       SELECT l.tenant_id, l.correlation_id, l.version
         FROM (
              SELECT tenant_id, correlation_id, version, created_at
                FROM netops.corr_objects
               WHERE created_at >= now() - INTERVAL ` + d + ` DAY
               ORDER BY tenant_id, correlation_id, version DESC
               LIMIT 1 BY tenant_id, correlation_id
         ) AS l
         LEFT JOIN (
              SELECT tenant_id, correlation_id, created_at
                FROM netops.corr_current FINAL
         ) AS c ON c.tenant_id = l.tenant_id AND c.correlation_id = l.correlation_id
        WHERE c.created_at < l.created_at`
}

// corrCurrentDriftRepairSQL re-projects every drifted/missing in-window object.
func corrCurrentDriftRepairSQL(lookbackDays int) string {
	return corrCurrentNarrowInsertPrefix + corrCurrentDriftSelect(lookbackDays) + `)`
}

// corrCurrentDriftCountSQL measures drift without repairing (observability +
// dry-run; also what the runbook uses to verify projection health).
func corrCurrentDriftCountSQL(lookbackDays int) string {
	return `SELECT count() AS drifted FROM (` + corrCurrentDriftSelect(lookbackDays) + `) FORMAT JSON`
}

// ── Orphaned-open sweep ───────────────────────────────────────────────────────
//
// The engine closes an object when its window quiesces — but only for objects
// it TRACKS. An engine restart drops the in-memory windows, so any object that
// was open at restart time never receives a closing version: it sits "open"
// on the Command Center forever (live incident 2026-07-15: open+confirmed rows
// from June still in the action queue). A live open object is re-persisted at
// least every CORR_VERSION_HEARTBEAT_S (900s), so an open projection row with
// no persist for many hours is definitively abandoned. The sweep writes an
// AUDITABLE closing version into history (engine_version marks the janitor),
// then the drift repair re-projects it — Command Center state stays backed by
// corr_objects history, never a projection-only edit.

// corrOrphanCloseMarker identifies janitor-authored closing versions in history.
const corrOrphanCloseMarker = "reconciler/orphan-close"

// corrOrphanCloseInsertHead copies every history column of the picked latest
// versions into a closing version (state='closed', version+1, fresh
// created_at). Wide columns are carried VERBATIM — no fold in this literal
// (#100 rule 2: the fold lives in corrOrphanClosePickSQL, narrow keys only).
const corrOrphanCloseInsertHead = `INSERT INTO netops.corr_objects
    (tenant_id, correlation_id, version, state, window_start, window_end, trigger_signal,
     top_hypothesis, top_confidence, verdict_tier, hypotheses, evidence_missing, affected,
     signal_count, node_count, engine_version, topology_version, catalog_version,
     layer_coverage, app_impact, merged_into, created_at)
SELECT tenant_id, correlation_id, version + 1, 'closed', window_start, window_end, trigger_signal,
       top_hypothesis, top_confidence, verdict_tier, hypotheses, evidence_missing, affected,
       signal_count, node_count, '` + corrOrphanCloseMarker + `', topology_version, catalog_version,
       layer_coverage, app_impact, merged_into, now64(3)
  FROM netops.corr_objects
 WHERE (tenant_id, correlation_id, version, created_at) IN (`

// corrOrphanClosePickSQL picks the exact latest history row of every orphaned
// open object: projection rows still 'open' whose last persist is older than
// the threshold. Narrow fold, keyed to the (small) orphan set — never a
// whole-history scan; created_at ordering because engine restarts reset
// version counters. The outer state filter skips objects whose history is
// already terminal (a lost projection write — the drift repair owns those).
func corrOrphanClosePickSQL(hours int) string {
	h := strconv.Itoa(hours)
	return `
       SELECT tenant_id, correlation_id, version, created_at
         FROM (
              SELECT tenant_id, correlation_id, version, state, created_at
                FROM netops.corr_objects
               WHERE (tenant_id, correlation_id) IN (
                     SELECT tenant_id, correlation_id
                       FROM netops.corr_current FINAL
                      WHERE state = 'open'
                        AND created_at < now() - INTERVAL ` + h + ` HOUR)
               ORDER BY tenant_id, correlation_id, created_at DESC
               LIMIT 1 BY tenant_id, correlation_id
         )
        WHERE state = 'open'`
}

// corrOrphanCloseSQL writes the closing versions for every orphaned open object.
func corrOrphanCloseSQL(hours int) string {
	return corrOrphanCloseInsertHead + corrOrphanClosePickSQL(hours) + `)`
}

// corrOrphanCountSQL measures the orphan backlog without writing (logging +
// dry-run; the runbook's verify step).
func corrOrphanCountSQL(hours int) string {
	return `SELECT count() AS orphaned FROM (` + corrOrphanClosePickSQL(hours) + `) FORMAT JSON`
}

// corrCurrentReconcileLoop runs the drift detect/repair on a timer.
// CORR_CURRENT_RECONCILE_INTERVAL (default 1h, 0 = disabled) /
// CORR_CURRENT_RECONCILE_LOOKBACK_DAYS (default 7, floor 1) /
// CORR_ORPHAN_OPEN_CLOSE_HOURS (default 24, 0 = orphan sweep disabled).
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
			rows, err := s.chRowsScope(ctx, "__all__", corrOrphanCountSQL(orphanHours),
				"worker:corr-current-reconcile")
			n := 0
			if err == nil && len(rows) == 1 {
				n = int(asFloat(rows[0]["orphaned"]))
			}
			if err != nil {
				log.Printf("corr-current-reconcile: orphan count failed: %v", err)
			} else if n > 0 {
				log.Printf("corr-current-reconcile: orphaned_open=%d threshold_hours=%d action=close", n, orphanHours)
				if msg := chExecErr(base, corrOrphanCloseSQL(orphanHours)); msg != "" {
					log.Printf("corr-current-reconcile: orphan close failed: %s", msg)
				} else {
					log.Printf("corr-current-reconcile: orphan_closed=%d (janitor closing versions written to history)", n)
				}
			}
		}
		rows, err := s.chRowsScope(ctx, "__all__", corrCurrentDriftCountSQL(lookback),
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
		if msg := chExecErr(base, corrCurrentDriftRepairSQL(lookback)); msg != "" {
			log.Printf("corr-current-reconcile: repair failed: %s", msg)
			continue
		}
		log.Printf("corr-current-reconcile: repaired=%d (projection re-seeded from corr_objects)", drifted)
	}
}
