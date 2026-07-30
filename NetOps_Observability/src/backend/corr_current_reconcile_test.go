package backend

import (
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
		"backfill": chschema.CorrCurrentBackfillSQL(),
		"drift":    chschema.CorrDriftRepairSQL(7),
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
