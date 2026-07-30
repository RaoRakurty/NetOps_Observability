package chschema

// corr_reconcile.go — the corr_current drift/orphan reconciliation SQL
// (Phase-2 W4.10, extracted from package main's corr_current_reconcile.go):
// the #101 projection-drift detect/repair statements and the orphan-close
// pick/insert/count set (append-only close rows stamped with the reconciler
// marker). Pure SQL construction over the corr schema this package owns; the
// reconcile loop, budgets and metrics stay in main.

import (
	"strconv"
)

// CorrDriftSelect picks (tenant, id, version) of objects whose latest
// in-window history row is NEWER than the corr_current row — i.e. a projection
// write was lost. Missing rows also match (the LEFT JOIN default epoch
// created_at is older than any real row), so one statement repairs both inside
// the window. Narrow fold, created_at-bounded base scan.
func CorrDriftSelect(lookbackDays int) string {
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

// CorrDriftRepairSQL re-projects every drifted/missing in-window object.
func CorrDriftRepairSQL(lookbackDays int) string {
	return CorrCurrentNarrowInsertPrefix + CorrDriftSelect(lookbackDays) + `)`
}

// CorrDriftCountSQL measures drift without repairing (observability +
// dry-run; also what the runbook uses to verify projection health).
func CorrDriftCountSQL(lookbackDays int) string {
	return `SELECT count() AS drifted FROM (` + CorrDriftSelect(lookbackDays) + `) FORMAT JSON`
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

// CorrOrphanCloseMarker identifies janitor-authored closing versions in history.
const CorrOrphanCloseMarker = "reconciler/orphan-close"

// corrOrphanCloseInsertHead copies every history column of the picked latest
// versions into a closing version (state='closed', version+1, fresh
// created_at). Wide columns are carried VERBATIM — no fold in this literal
// (#100 rule 2: the fold lives in CorrOrphanClosePickSQL, narrow keys only).
const corrOrphanCloseInsertHead = `INSERT INTO netops.corr_objects
    (tenant_id, correlation_id, version, state, window_start, window_end, trigger_signal,
     top_hypothesis, top_confidence, verdict_tier, hypotheses, evidence_missing, affected,
     signal_count, node_count, engine_version, topology_version, catalog_version,
     layer_coverage, app_impact, merged_into, created_at)
SELECT tenant_id, correlation_id, version + 1, 'closed', window_start, window_end, trigger_signal,
       top_hypothesis, top_confidence, verdict_tier, hypotheses, evidence_missing, affected,
       signal_count, node_count, '` + CorrOrphanCloseMarker + `', topology_version, catalog_version,
       layer_coverage, app_impact, merged_into, now64(3)
  FROM netops.corr_objects
 WHERE (tenant_id, correlation_id, version, created_at) IN (`

// CorrOrphanClosePickSQL picks the exact latest history row of every orphaned
// open object: projection rows still 'open' whose last persist is older than
// the threshold. Narrow fold, keyed to the (small) orphan set — never a
// whole-history scan; created_at ordering because engine restarts reset
// version counters. The outer state filter skips objects whose history is
// already terminal (a lost projection write — the drift repair owns those).
func CorrOrphanClosePickSQL(hours int) string {
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

// CorrOrphanCloseSQL writes the closing versions for every orphaned open object.
func CorrOrphanCloseSQL(hours int) string {
	return corrOrphanCloseInsertHead + CorrOrphanClosePickSQL(hours) + `)`
}

// CorrOrphanCountSQL measures the orphan backlog without writing (logging +
// dry-run; the runbook's verify step).
func CorrOrphanCountSQL(hours int) string {
	return `SELECT count() AS orphaned FROM (` + CorrOrphanClosePickSQL(hours) + `) FORMAT JSON`
}

// corrCurrentReconcileLoop runs the drift detect/repair on a timer.
// CORR_CURRENT_RECONCILE_INTERVAL (default 1h, 0 = disabled) /
// CORR_CURRENT_RECONCILE_LOOKBACK_DAYS (default 7, floor 1) /
// CORR_ORPHAN_OPEN_CLOSE_HOURS (default 24, 0 = orphan sweep disabled).
