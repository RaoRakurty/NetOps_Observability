// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// corr_current_reconcile_batch_test.go — tracker 328 hardening of the
// corr_current reconciler: bounded repair batches, the state-drift shapes as
// SQL properties, structural tenant keying (§3a), and shutdown behaviour.

import (
	"context"
	"errors"
	"netops/backend/internal/chschema"
	"strings"
	"testing"
)

func testReconcileCfg(orphanHours int) corrReconcileConfig {
	return corrReconcileConfig{lookbackDays: 7, orphanHours: orphanHours, batch: 5000, maxBatches: 20}
}

// reconcileRepairs is every statement the reconciler writes with, at a given
// batch limit.
func reconcileRepairs(limit int) map[string]string {
	return map[string]string{
		"orphan close": chschema.CorrOrphanCloseSQL(24, limit),
		"drift":        chschema.CorrDriftRepairSQL(7, limit),
		"state drift":  chschema.CorrStateDriftRepairSQL(limit),
	}
}

// Every write is bounded: a repair over a 56k backlog as one statement could
// overrun the 10 s exec budget on every pass and stay permanent. The LIMIT
// must bound the DRIFT set (after the latest-row fold and the drift filter),
// never the open set feeding the fold — a LIMIT there could pick N genuinely
// open objects and repair nothing, forever.
func TestCorrRepairStatementsAreBoundedOldestFirst(t *testing.T) {
	for name, sql := range reconcileRepairs(1234) {
		if !strings.HasSuffix(strings.TrimSpace(sql), "LIMIT 1234)") {
			t.Errorf("%s: repair must end with the batch LIMIT closing the picked-key IN (...):\n%s", name, sql)
			continue
		}
		order := strings.LastIndex(sql, "ORDER BY")
		lim := strings.LastIndex(sql, "LIMIT 1234")
		fold := strings.LastIndex(sql, "LIMIT 1 BY tenant_id, correlation_id")
		filter := max(strings.LastIndex(sql, "WHERE state"), strings.LastIndex(sql, "WHERE c.created_at < l.created_at"))
		if fold == -1 || filter == -1 || fold >= filter || filter >= order || order >= lim {
			t.Errorf("%s: batch LIMIT must follow the latest-row fold and the drift filter (fold=%d filter=%d order=%d limit=%d):\n%s",
				name, fold, filter, order, lim, sql)
		}
		// Oldest first, deterministic (tenant, id) tie-break.
		tail := sql[order:]
		if !strings.Contains(tail, "created_at, ") || !strings.Contains(tail, "tenant_id, ") || !strings.Contains(tail, "correlation_id") {
			t.Errorf("%s: batch must be ordered oldest-first with a (tenant, id) tie-break:\n%s", name, tail)
		}
		if n := strings.Count(sql, "LIMIT "); n != 2 {
			t.Errorf("%s: exactly one latest-row fold and one batch LIMIT expected, got %d LIMITs", name, n)
		}
	}
}

// A non-positive limit is raised to the floor, never dropped: bounded is the
// only shape.
func TestCorrRepairBatchNeverUnbounded(t *testing.T) {
	for _, limit := range []int{0, -1, -5000} {
		for name, sql := range reconcileRepairs(limit) {
			if !strings.HasSuffix(strings.TrimSpace(sql), "LIMIT 1)") {
				t.Errorf("%s at limit %d: want LIMIT %d, got:\n%s", name, limit, chschema.CorrRepairBatchFloor, sql)
			}
		}
	}
}

// The gauges must report the WHOLE backlog, not one batch of it.
func TestCorrReconcileCountsStayUnbounded(t *testing.T) {
	for name, sql := range map[string]string{
		"orphan":      chschema.CorrOrphanCountSQL(24),
		"drift":       chschema.CorrDriftCountSQL(7),
		"state drift": chschema.CorrStateDriftCountSQL(),
	} {
		if n := strings.Count(sql, "LIMIT "); n != 1 || !strings.Contains(sql, "LIMIT 1 BY tenant_id, correlation_id") {
			t.Errorf("%s count: only the latest-row fold may carry a LIMIT, found %d:\n%s", name, n, sql)
		}
	}
}

// The tracker-328 shapes, as SQL properties: a terminal version written more
// than 7 days ago is repaired (no age bound anywhere in the state pick), and a
// genuinely open object is never closed by it (only objects whose NEWEST
// history row is terminal are picked), nor by the orphan sweep inside the
// liveness horizon. Behaviour was proven against a throwaway ClickHouse 24.8
// with the lab DDL (PR description).
func TestCorrStateRepairCoversOldClosesAndSparesOpen(t *testing.T) {
	sel := chschema.CorrStateDriftSelect()
	for _, sql := range []string{sel, chschema.CorrStateDriftRepairSQL(5000)} {
		if strings.Contains(sql, "INTERVAL") || strings.Contains(sql, "now() -") {
			t.Errorf("state repair must not be age-bounded (a close older than any window is the bug):\n%s", sql)
		}
	}
	// The terminal filter applies to the newest row (after the created_at DESC
	// fold), so an object whose newest row is open is never selected.
	fold := strings.Index(sel, "LIMIT 1 BY tenant_id, correlation_id")
	term := strings.Index(sel, "WHERE state != 'open'")
	if fold == -1 || term == -1 || term < fold || !strings.Contains(sel, "created_at DESC") {
		t.Errorf("terminal filter must apply to the NEWEST history row (fold %d, filter %d):\n%s", fold, term, sel)
	}
	// The orphan sweep closes only open-in-history rows past the horizon.
	op := chschema.CorrOrphanClosePickSQL(24)
	if !strings.Contains(op, "created_at < now() - INTERVAL 24 HOUR") || !strings.HasSuffix(strings.TrimSpace(op), "WHERE state = 'open'") {
		t.Errorf("orphan pick must spare live objects (horizon) and terminal ones (state filter):\n%s", op)
	}
}

// §3a: the reconciler is a cross-tenant worker (it runs at tenant_scope
// __all__ by design), so its isolation is STRUCTURAL: every key it matches on
// carries tenant_id with correlation_id, so a repaired row is always copied
// from the SAME tenant's own history row. A correlation_id-only key would let
// one tenant's history overwrite another tenant's projection row for a
// colliding id.
func TestCorrReconcileSQLIsTenantKeyed(t *testing.T) {
	all := map[string]string{
		"orphan count":      chschema.CorrOrphanCountSQL(24),
		"drift count":       chschema.CorrDriftCountSQL(7),
		"state drift count": chschema.CorrStateDriftCountSQL(),
	}
	for k, v := range reconcileRepairs(5000) {
		all[k] = v
	}
	for name, sql := range all {
		keys := 0
		for i := 0; ; {
			j := strings.Index(sql[i:], ") IN (")
			if j == -1 {
				break
			}
			at := i + j
			tuple := sql[strings.LastIndex(sql[:at], "(")+1 : at]
			if !strings.HasPrefix(tuple, "tenant_id, correlation_id") && !strings.HasPrefix(tuple, "o.tenant_id, o.correlation_id") {
				t.Errorf("%s: IN key (%s) does not lead with (tenant_id, correlation_id)", name, tuple)
			}
			keys++
			i = at + len(") IN (")
		}
		if strings.Contains(sql, " JOIN ") {
			keys++
			if !strings.Contains(sql, "c.tenant_id = l.tenant_id AND c.correlation_id = l.correlation_id") {
				t.Errorf("%s: join must match on tenant AND id", name)
			}
		}
		if keys == 0 {
			t.Errorf("%s: no tenant-keyed match found — the test no longer sees the statement's keys", name)
		}
		if !strings.Contains(sql, "LIMIT 1 BY tenant_id, correlation_id") {
			t.Errorf("%s: the latest-row fold must be per (tenant, id)", name)
		}
		// No statement names or rescopes a tenant.
		for _, bad := range []string{"tenant_scope", "tenant_id = '", "'global'"} {
			if strings.Contains(sql, bad) {
				t.Errorf("%s: reconciler SQL must not hard-code tenant scope (%q)", name, bad)
			}
		}
	}
}

// Batching: a backlog drains in ceil(found/batch) bounded statements; the claim
// never exceeds what was found.
func TestCorrReconcileRepairsInBatches(t *testing.T) {
	ch := &fakeReconcileCH{counts: map[string]int{"state_drifted": 12001}}
	var st corrReconcileStats
	corrReconcilePass(context.Background(), ch, &st, testReconcileCfg(0))
	if len(ch.execs) != 3 {
		t.Fatalf("12001 rows at batch 5000: execs = %d, want 3", len(ch.execs))
	}
	for i, sql := range ch.execs {
		if sql != chschema.CorrStateDriftRepairSQL(5000) {
			t.Errorf("exec %d is not the bounded state repair", i)
		}
	}
	if st.repairedTotal.Load() != 12001 || st.stateDrifted.Load() != 12001 || st.failuresTotal.Load() != 0 {
		t.Errorf("repaired=%d gauge=%d failures=%d, want 12001/12001/0", st.repairedTotal.Load(), st.stateDrifted.Load(), st.failuresTotal.Load())
	}
}

// The per-pass cap bounds one pass's work; the residue waits for the next pass
// and the gauge still reports the whole backlog.
func TestCorrReconcileBatchCapLeavesResidueForNextPass(t *testing.T) {
	ch := &fakeReconcileCH{counts: map[string]int{"state_drifted": 56397}}
	var st corrReconcileStats
	cfg := testReconcileCfg(0)
	cfg.maxBatches = 4
	corrReconcilePass(context.Background(), ch, &st, cfg)
	if len(ch.execs) != 4 {
		t.Fatalf("execs = %d, want the cap (4)", len(ch.execs))
	}
	if st.repairedTotal.Load() != 20000 || st.stateDrifted.Load() != 56397 {
		t.Errorf("repaired=%d gauge=%d, want 20000 claimed and the full 56397 backlog reported", st.repairedTotal.Load(), st.stateDrifted.Load())
	}
}

// failingNthExec fails the nth exec (1-based) and records every attempt.
type failingNthExec struct {
	fakeReconcileCH
	n, calls int
}

func (f *failingNthExec) exec(_ context.Context, sql string) error {
	f.calls++
	f.execs = append(f.execs, sql)
	if f.calls == f.n {
		return errors.New("budget exceeded")
	}
	return nil
}

// A failed batch stops that step (no hot loop against a sick server), claims
// only the batches that succeeded, is counted, and the next step still runs.
func TestCorrReconcileFailedBatchStopsStepNotPass(t *testing.T) {
	ch := &failingNthExec{fakeReconcileCH: fakeReconcileCH{counts: map[string]int{"drifted": 15000, "state_drifted": 10}}, n: 2}
	var st corrReconcileStats
	corrReconcilePass(context.Background(), ch, &st, testReconcileCfg(0))
	if len(ch.execs) != 3 {
		t.Fatalf("execs = %d, want 3 (drift batch ok, drift batch fails, state repair still runs)", len(ch.execs))
	}
	if ch.execs[2] != chschema.CorrStateDriftRepairSQL(5000) {
		t.Error("state repair must still run after the drift step failed")
	}
	if st.repairedTotal.Load() != 5010 || st.failuresTotal.Load() != 1 {
		t.Errorf("repaired=%d failures=%d, want 5010 (one drift batch + state) / 1", st.repairedTotal.Load(), st.failuresTotal.Load())
	}
}

// Shutdown abandons the pass without writing and without counting a failure
// (a restart must not trip CorrCurrentReconcileFailing).
func TestCorrReconcileCancelledPassWritesNothingCountsNoFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := &fakeReconcileCH{counts: map[string]int{"orphaned": 3, "drifted": 3, "state_drifted": 3}}
	var st corrReconcileStats
	corrReconcilePass(ctx, ch, &st, testReconcileCfg(24))
	if len(ch.execs) != 0 {
		t.Errorf("a cancelled pass must not write; execs=%d", len(ch.execs))
	}
	if st.failuresTotal.Load() != 0 || st.repairedTotal.Load() != 0 {
		t.Errorf("failures=%d repaired=%d, want 0/0", st.failuresTotal.Load(), st.repairedTotal.Load())
	}
}

func TestCorrReconcileConfigFromEnv(t *testing.T) {
	want := corrReconcileConfig{lookbackDays: 7, orphanHours: corrOrphanOpenCloseHoursDefault,
		batch: corrReconcileBatchDefault, maxBatches: corrReconcileMaxBatchesDefault}
	if got := corrReconcileConfigFromEnv(); got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
	for raw, want := range map[string]int{
		"2000":    2000,
		"0":       corrReconcileBatchDefault, // never unbounded, never zero
		"-1":      corrReconcileBatchDefault,
		"lots":    corrReconcileBatchDefault,
		"9999999": corrReconcileBatchCeiling, // clamped
	} {
		t.Setenv("CORR_CURRENT_RECONCILE_BATCH", raw)
		if b := corrReconcileConfigFromEnv().batch; b != want {
			t.Errorf("CORR_CURRENT_RECONCILE_BATCH=%q: got %d, want %d", raw, b, want)
		}
	}
	t.Setenv("CORR_CURRENT_RECONCILE_MAX_BATCHES", "100000")
	if m := corrReconcileConfigFromEnv().maxBatches; m != corrReconcileMaxBatchesCeiling {
		t.Errorf("max batches not clamped: %d", m)
	}
	t.Setenv("CORR_CURRENT_RECONCILE_LOOKBACK_DAYS", "0")
	if d := corrReconcileConfigFromEnv().lookbackDays; d != 7 {
		t.Errorf("lookback 0 must fall back to 7, got %d", d)
	}
}
