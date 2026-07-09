package main

import (
	"strings"
	"testing"
)

// corr_current_reconcile_test.go — #101 projection-repair guardrails. The
// reconciler reads history, so it must obey the #100 bounded-IO shape rules:
// narrow folds only; the wide hypotheses blob is touched exclusively in the
// outer SELECT keyed by an already-picked (tenant, id, version) set.

func TestCorrCurrentRepairSQLStaysNarrow(t *testing.T) {
	for name, sql := range map[string]string{
		"backfill": corrCurrentBackfillSQL(),
		"drift":    corrCurrentDriftRepairSQL(7),
	} {
		inner := sql[strings.Index(sql, "WHERE (o.tenant_id, o.correlation_id, o.version) IN ("):]
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

func TestCorrCurrentDriftScanIsTimeBounded(t *testing.T) {
	sql := corrCurrentDriftSelect(7)
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
	if !strings.Contains(corrCurrentBackfillSQL(), "NOT IN") {
		t.Error("backfill must be idempotent via NOT IN")
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
