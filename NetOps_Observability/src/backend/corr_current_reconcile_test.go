// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"netops/backend/internal/chschema"
	"strings"
	"testing"
)

// corr_current_reconcile_test.go — #101 projection-repair guardrails. The
// reconciler reads history, so it must obey the #100 bounded-IO shape rules:
// narrow folds only; the wide hypotheses blob is touched exclusively in the
// outer SELECT keyed by an already-picked (tenant, id, version) set.

func TestCorrCurrentRepairSQLStaysNarrow(t *testing.T) {
	for name, sql := range map[string]string{
		"backfill":    chschema.CorrCurrentBackfillSQL(),
		"drift":       chschema.CorrDriftRepairSQL(7),
		"state drift": chschema.CorrStateDriftRepairSQL(),
	} {
		// Exact-row keying: engine restarts reset version counters, so
		// (tenant, id, version) alone can match two history rows (tracker 328).
		at := strings.Index(sql, "WHERE (o.tenant_id, o.correlation_id, o.version, o.created_at) IN (")
		if at == -1 {
			t.Fatalf("%s: repair is not keyed by (tenant, id, version, created_at):\n%s", name, sql)
		}
		inner := sql[at:]
		// "Latest" is the newest row, never the highest version number.
		if strings.Contains(inner, "version DESC") || !strings.Contains(inner, "created_at DESC") {
			t.Errorf("%s: latest-row pick must order by created_at DESC, not version", name)
		}
		// The picking subquery (fold) must never reference a wide column.
		for _, wide := range []string{"hypotheses", "layer_coverage", "app_impact"} {
			if strings.Contains(inner, wide) {
				t.Errorf("%s: wide column %q inside the picking fold", name, wide)
			}
		}
		if !strings.Contains(sql, "LIMIT 1 BY tenant_id, correlation_id") {
			t.Errorf("%s: latest-version pick must be a narrow LIMIT 1 BY fold", name)
		}
		if strings.Contains(sql, "SELECT *") {
			t.Errorf("%s: SELECT * is banned on corr tables", name)
		}
	}
}

// TestCorrOrphanOpenCloseHours: the liveness horizon is ONE value, shared by
// the sweep that force-closes stale open rows and by every reader that asks
// "is this problem still live?" (aiDataSource.ListActiveProblems). A bad env
// value must fall back to the default, never to zero — zero means "sweep
// disabled", a materially different posture.
func TestCorrOrphanOpenCloseHours(t *testing.T) {
	if got := corrOrphanOpenCloseHours(); got != corrOrphanOpenCloseHoursDefault {
		t.Errorf("unset: got %d, want %d", got, corrOrphanOpenCloseHoursDefault)
	}
	for raw, want := range map[string]int{
		"48":    48,
		"0":     0, // explicit disable
		"":      corrOrphanOpenCloseHoursDefault,
		"soon":  corrOrphanOpenCloseHoursDefault, // unparseable → default, not 0
		"-1":    corrOrphanOpenCloseHoursDefault, // negative → default, not 0
		"1.5":   corrOrphanOpenCloseHoursDefault,
		" 24 ":  corrOrphanOpenCloseHoursDefault,
		"99999": 99999,
	} {
		t.Setenv("CORR_ORPHAN_OPEN_CLOSE_HOURS", raw)
		if got := corrOrphanOpenCloseHours(); got != want {
			t.Errorf("CORR_ORPHAN_OPEN_CLOSE_HOURS=%q: got %d, want %d", raw, got, want)
		}
	}
}

func TestCorrCurrentDriftScanIsTimeBounded(t *testing.T) {
	sql := chschema.CorrDriftSelect(7)
	if !strings.Contains(sql, "created_at >= now() - INTERVAL 7 DAY") {
		t.Error("drift scan must prefilter corr_objects by created_at window")
	}
	// Drift is decided by created_at, NOT version: engine restarts reset
	// in-memory versions to 1, and ReplacingMergeTree(created_at) already
	// encodes latest-write-wins.
	if !strings.Contains(sql, "c.created_at < l.created_at") {
		t.Error("drift comparison must be created_at-based (restart-safe)")
	}
	if !strings.Contains(sql, "corr_current FINAL") {
		t.Error("projection side must read FINAL (collapse re-persists)")
	}
}

func TestCorrCurrentBackfillIsIdempotent(t *testing.T) {
	if !strings.Contains(chschema.CorrCurrentBackfillSQL(), "NOT IN") {
		t.Error("backfill must be idempotent via NOT IN")
	}
}

// Orphaned-open sweep (2026-07-15 Command Center pollution): engine restarts
// abandon open objects forever; the janitor closes them through HISTORY
// (auditable), wide columns never crossing the narrow fold.
func TestOrphanClosePickIsNarrowAndBounded(t *testing.T) {
	sql := chschema.CorrOrphanClosePickSQL(24)
	if !strings.Contains(sql, "LIMIT 1 BY tenant_id, correlation_id") {
		t.Fatal("orphan pick lost its latest-version fold")
	}
	for _, wide := range []string{"hypotheses", "layer_coverage", "app_impact"} {
		if strings.Contains(sql, wide) {
			t.Errorf("orphan pick folds wide column %q — narrow keys only (#100)", wide)
		}
	}
	if !strings.Contains(sql, "FROM netops.corr_current FINAL") ||
		!strings.Contains(sql, "state = 'open'") ||
		!strings.Contains(sql, "INTERVAL 24 HOUR") {
		t.Fatalf("orphan pick must be keyed to stale OPEN projection rows:\n%s", sql)
	}
	// The fold must be bounded to the orphan set, never a whole-history scan.
	foldAt := strings.Index(sql, "ORDER BY")
	inAt := strings.Index(sql, "IN (")
	if inAt == -1 || foldAt == -1 || inAt > foldAt {
		t.Fatal("orphan pick's history fold is not pre-keyed by the projection orphan set")
	}
}

func TestOrphanCloseWritesAuditableHistoryVersion(t *testing.T) {
	sql := chschema.CorrOrphanCloseSQL(24)
	for _, want := range []string{
		"INSERT INTO netops.corr_objects",
		"version + 1, 'closed'",
		chschema.CorrOrphanCloseMarker,
		"now64(3)",
		// exact-row keying: version-counter resets after engine restarts mean
		// (tenant,id,version) alone can match two rows — created_at disambiguates.
		"(tenant_id, correlation_id, version, created_at) IN (",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("orphan close SQL missing %q:\n%s", want, sql)
		}
	}
	// Every history column must be carried into the closing version (a dropped
	// column silently zeroes data on the object's terminal row).
	for _, col := range []string{"trigger_signal", "hypotheses", "layer_coverage",
		"app_impact", "merged_into", "topology_version", "catalog_version"} {
		if !strings.Contains(sql, col) {
			t.Errorf("closing version drops history column %q", col)
		}
	}
}

func TestOrphanCountMatchesPick(t *testing.T) {
	if !strings.Contains(chschema.CorrOrphanCountSQL(6), "INTERVAL 6 HOUR") {
		t.Fatal("orphan count does not honor the configured threshold")
	}
}

func TestCHWorkloadProfileRouting(t *testing.T) {
	cases := map[string]string{
		"api:/api/correlations":         "hot_ui",
		"api:/api/correlations/abc":     "hot_ui",
		"api:/api/reliability/paths":    "hot_ui",
		"api:/api/cloud/app-rca":        "hot_ui",
		"api:/api/flows/top-talkers":    "", // analytics keeps default (spill allowed)
		"worker:corr-current-reconcile": "background",
		"worker:ticket-sweeper":         "background",
		"api:/api/health":               "",
	}
	for tag, want := range cases {
		if got := chWorkloadProfile(tag); got != want {
			t.Errorf("chWorkloadProfile(%q) = %q, want %q", tag, got, want)
		}
	}
	t.Setenv("CH_WORKLOAD_PROFILES", "off")
	if got := chWorkloadProfile("api:/api/correlations"); got != "" {
		t.Errorf("kill-switch must disable profile routing, got %q", got)
	}
}

// Tracker 328: the projection said 'open' for 56,397 objects that history had
// closed — drift older than the lookback, or a stale row NEWER than history (a
// heartbeat touch after the close). The state repair decides by STATE, at any
// age, keyed to the projection's open set, and restamps so it wins the fold.
// (Behaviour was proven against a throwaway ClickHouse with the lab DDL: the old
// SQL left all three shapes open, the new one closed them and kept a genuinely
// open control open.)
func TestCorrStateDriftRepairIsStateKeyedUnboundedAndRestamped(t *testing.T) {
	sel := chschema.CorrStateDriftSelect()
	if strings.Contains(sel, "INTERVAL") {
		t.Errorf("state drift must not be age-bounded — drift older than any window is exactly the bug:\n%s", sel)
	}
	for _, want := range []string{
		"FROM netops.corr_current FINAL",
		"WHERE state = 'open'",
		"LIMIT 1 BY tenant_id, correlation_id",
		"WHERE state != 'open'",
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("state drift pick missing %q:\n%s", want, sel)
		}
	}
	// Pre-keyed by the projection's open set, never a whole-history fold.
	if in, fold := strings.Index(sel, "IN ("), strings.Index(sel, "ORDER BY"); in == -1 || fold == -1 || in > fold {
		t.Error("state drift's history fold is not pre-keyed by the projection's open set")
	}
	for _, wide := range []string{"hypotheses", "layer_coverage", "app_impact"} {
		if strings.Contains(sel, wide) {
			t.Errorf("state drift pick folds wide column %q (#100)", wide)
		}
	}
	rep := chschema.CorrStateDriftRepairSQL()
	if !strings.HasPrefix(rep, chschema.CorrCurrentRestampedInsertPrefix) || !strings.Contains(rep, "now64(3),") {
		t.Error("state repair must restamp created_at, or a newer stale row keeps winning the fold")
	}
	if strings.Contains(chschema.CorrDriftRepairSQL(7), "now64(3),") || strings.Contains(chschema.CorrCurrentBackfillSQL(), "now64(3),") {
		t.Error("drift repair and backfill must keep history's own created_at")
	}
	if !strings.Contains(chschema.CorrStateDriftCountSQL(), "AS state_drifted") {
		t.Error("state drift count must expose the state_drifted column the reconciler reads")
	}
}

// fakeReconcileCH scripts count results and records execs.
type fakeReconcileCH struct {
	counts   map[string]int   // keyed by the count column
	countErr map[string]error // keyed by the count column
	execErr  error
	execs    []string
}

func (f *fakeReconcileCH) count(_ context.Context, _ string, column string) (int, error) {
	if err := f.countErr[column]; err != nil {
		return 0, err
	}
	return f.counts[column], nil
}

func (f *fakeReconcileCH) exec(_ context.Context, sql string) error {
	f.execs = append(f.execs, sql)
	return f.execErr
}

func TestCorrReconcilePassRepairsEveryKindAndCounts(t *testing.T) {
	ch := &fakeReconcileCH{counts: map[string]int{"orphaned": 2, "drifted": 3, "state_drifted": 5}}
	var st corrReconcileStats
	corrReconcilePass(context.Background(), ch, &st, 7, 24)
	want := []string{chschema.CorrOrphanCloseSQL(24), chschema.CorrDriftRepairSQL(7), chschema.CorrStateDriftRepairSQL()}
	if len(ch.execs) != len(want) {
		t.Fatalf("execs = %d, want %d (orphan close, drift repair, state repair in that order)", len(ch.execs), len(want))
	}
	for i := range want {
		if ch.execs[i] != want[i] {
			t.Errorf("exec %d is not the expected statement", i)
		}
	}
	if st.orphaned.Load() != 2 || st.drifted.Load() != 3 || st.stateDrifted.Load() != 5 {
		t.Errorf("gauges = %d/%d/%d, want 2/3/5", st.orphaned.Load(), st.drifted.Load(), st.stateDrifted.Load())
	}
	if st.repairedTotal.Load() != 8 || st.orphanClosedTotal.Load() != 2 || st.failuresTotal.Load() != 0 {
		t.Errorf("counters repaired=%d orphanClosed=%d failures=%d, want 8/2/0",
			st.repairedTotal.Load(), st.orphanClosedTotal.Load(), st.failuresTotal.Load())
	}
	if st.lastRunUnix.Load() == 0 {
		t.Error("a completed pass must stamp its time")
	}
}

// A failing step must not stop the next one: the old loop `continue`d on a
// drift-count error, so one broken step silenced every repair after it.
func TestCorrReconcilePassStepsAreIndependent(t *testing.T) {
	ch := &fakeReconcileCH{
		counts:   map[string]int{"state_drifted": 4},
		countErr: map[string]error{"orphaned": errors.New("boom"), "drifted": errors.New("boom")},
	}
	var st corrReconcileStats
	corrReconcilePass(context.Background(), ch, &st, 7, 24)
	if len(ch.execs) != 1 || ch.execs[0] != chschema.CorrStateDriftRepairSQL() {
		t.Fatalf("state repair must still run after earlier steps fail; execs=%d", len(ch.execs))
	}
	if st.failuresTotal.Load() != 2 || st.repairedTotal.Load() != 4 {
		t.Errorf("failures=%d repaired=%d, want 2/4", st.failuresTotal.Load(), st.repairedTotal.Load())
	}
}

func TestCorrReconcilePassFailedRepairIsCountedNotClaimed(t *testing.T) {
	ch := &fakeReconcileCH{counts: map[string]int{"drifted": 3, "state_drifted": 1}, execErr: errors.New("ch down")}
	var st corrReconcileStats
	corrReconcilePass(context.Background(), ch, &st, 7, 0) // orphan sweep disabled
	if len(ch.execs) != 2 {
		t.Fatalf("execs = %d, want 2 (orphan sweep disabled)", len(ch.execs))
	}
	if st.repairedTotal.Load() != 0 || st.failuresTotal.Load() != 2 {
		t.Errorf("a failed repair must not count as repaired: repaired=%d failures=%d", st.repairedTotal.Load(), st.failuresTotal.Load())
	}
	if st.drifted.Load() != 3 || st.stateDrifted.Load() != 1 {
		t.Error("the gauges still report what was found when the repair fails")
	}
}

func TestCorrReconcileMetricsRender(t *testing.T) {
	var st corrReconcileStats
	st.stateDrifted.Store(7)
	st.failuresTotal.Store(1)
	var b strings.Builder
	st.WriteMetrics(&b)
	out := b.String()
	for _, want := range []string{
		`netops_corr_current_drift_rows{kind="state_drifted"} 7`,
		`netops_corr_current_drift_rows{kind="drifted"} 0`,
		`netops_corr_current_drift_rows{kind="orphaned"} 0`,
		"netops_corr_current_reconcile_failures_total 1",
		"netops_corr_current_repaired_rows_total 0",
		"# TYPE netops_corr_current_reconcile_failures_total counter",
		"netops_corr_current_reconcile_last_run_timestamp_seconds 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}
