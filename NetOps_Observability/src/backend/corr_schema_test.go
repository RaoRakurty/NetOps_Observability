package main

import (
	"strings"
	"testing"
)

// corr_schema_test.go — freeze contract for the Correlation Engine v2 schema
// (build step ①). These are not style checks: each assertion pins a design
// decision that later build steps (episodes, verdicts, replay) depend on.
// If a change legitimately needs to break one, the design doc §2 freeze note
// must be amended in the same commit.

func corrStmt(t *testing.T, table string) string {
	t.Helper()
	for _, s := range corrSchemaDDL() {
		if strings.Contains(s, "CREATE TABLE IF NOT EXISTS netops."+table+"\n") ||
			strings.Contains(s, "CREATE TABLE IF NOT EXISTS netops."+table+" ") {
			return s
		}
	}
	t.Fatalf("no CREATE TABLE statement for %s", table)
	return ""
}

func TestCorrSchemaIdempotent(t *testing.T) {
	for _, s := range corrSchemaDDL() {
		if !strings.Contains(s, "IF NOT EXISTS") {
			t.Errorf("statement not idempotent (missing IF NOT EXISTS): %.80s", s)
		}
	}
}

func TestCorrSchemaTenantPartitioned(t *testing.T) {
	// House rule (#20 Phase 3): tenant_id leads every PARTITION BY for at-rest
	// per-tenant separation.
	for _, table := range []string{"corr_signals", "corr_objects", "corr_edges", "corr_evidence"} {
		s := corrStmt(t, table)
		if !strings.Contains(s, "PARTITION BY (tenant_id,") {
			t.Errorf("%s: PARTITION BY must lead with tenant_id", table)
		}
		if !strings.Contains(s, "tenant_id      LowCardinality(String) DEFAULT ''") &&
			!strings.Contains(s, "tenant_id       LowCardinality(String) DEFAULT ''") &&
			!strings.Contains(s, "tenant_id        LowCardinality(String) DEFAULT ''") {
			t.Errorf("%s: missing tenant_id column with '' default", table)
		}
	}
}

func TestCorrSchemaRowPoliciesCoverAllTables(t *testing.T) {
	all := strings.Join(corrSchemaDDL(), "\n")
	for _, table := range []string{"corr_signals", "corr_objects", "corr_edges", "corr_evidence"} {
		if !strings.Contains(all, "tenant_iso_"+table) {
			t.Errorf("missing row policy for %s", table)
		}
	}
}

func TestCorrSignalsIndependenceGate(t *testing.T) {
	// Pre-freeze amendment (owner): observer_id powers the evidence-independence
	// gate — confirmed verdicts need >=2 modality classes from >=2 observers.
	if !strings.Contains(corrStmt(t, "corr_signals"), "observer_id") {
		t.Fatal("corr_signals: observer_id missing (evidence-independence gate)")
	}
}

func TestCorrObjectsReplayContract(t *testing.T) {
	s := corrStmt(t, "corr_objects")
	// Replay = same inputs + same versions => same object. All three version
	// pins are required (research C6 added catalog_version).
	for _, col := range []string{"engine_version", "topology_version", "catalog_version"} {
		if !strings.Contains(s, col) {
			t.Errorf("corr_objects: %s missing (replay contract)", col)
		}
	}
	// Pre-freeze amendments: rank != verdict (verdict_tier is its own column),
	// and 'undetermined' carries machine-derived evidence_missing.
	if !strings.Contains(s, "verdict_tier") || !strings.Contains(s, "'undetermined'=0") {
		t.Error("corr_objects: verdict_tier with 'undetermined' tier missing")
	}
	if !strings.Contains(s, "evidence_missing") {
		t.Error("corr_objects: evidence_missing missing")
	}
	if strings.Contains(s, "TTL ") {
		t.Error("corr_objects: must have NO TTL (objects queryable forever)")
	}
}

func TestCorrEdgesGroundedByConstruction(t *testing.T) {
	s := corrStmt(t, "corr_edges")
	// The grounded-edges HARD constraint. Non-Nullable alone is NOT sufficient:
	// ClickHouse coerces inserted NULLs to the column default ('') via
	// input_format_null_as_default — verified live at freeze time. The CHECK
	// constraint is what actually rejects an ungrounded edge at the DB layer.
	for _, col := range []string{"grounding_kind", "grounding_ref"} {
		if !strings.Contains(s, col) {
			t.Fatalf("corr_edges: %s missing", col)
		}
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, col) && strings.Contains(line, "Nullable") {
				t.Errorf("corr_edges: %s must not be Nullable (grounded-edges constraint)", col)
			}
		}
	}
	if !strings.Contains(s, "CONSTRAINT grounding_ref_nonempty CHECK grounding_ref != ''") {
		t.Error("corr_edges: CHECK grounding_ref != '' missing — non-Nullable alone does not reject NULL inserts")
	}
}

func TestCorrSchemaNoMaterializedViews(t *testing.T) {
	// Row policies error MV inserts in the writer's context (the flows_hourly
	// lesson) — the corr tables must never gain one.
	for _, s := range corrSchemaDDL() {
		if strings.Contains(strings.ToUpper(s), "MATERIALIZED VIEW") {
			t.Errorf("materialized view in corr schema is forbidden: %.80s", s)
		}
	}
}
