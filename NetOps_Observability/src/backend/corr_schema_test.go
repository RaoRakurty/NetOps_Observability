package main

import (
	"os"
	"regexp"
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
		// MODIFY COLUMN re-applies an identical column definition (an additive enum
		// value-add for the cloud signal plane, #81 P3G): idempotent by nature — a
		// no-op once applied — and ClickHouse has no "IF NOT EXISTS" form for it.
		if strings.Contains(s, "MODIFY COLUMN") {
			continue
		}
		// MODIFY SETTING sets a table setting to a fixed value (Phase 3 dedup
		// window): re-running writes the same value — a no-op — and there is no
		// "IF NOT EXISTS" form. Idempotent by nature, same as MODIFY COLUMN.
		if strings.Contains(s, "MODIFY SETTING") {
			continue
		}
		// CREATE OR REPLACE VIEW is idempotent (re-runnable) AND, unlike CREATE VIEW
		// IF NOT EXISTS, refreshes a SELECT * view's columns when the base table gains
		// one (#81 P5 app_impact) — so a stale view can't shadow a new column.
		//
		// Row policies express the same "replace in place" intent with a DIFFERENT
		// clause order — ClickHouse puts the modifier AFTER the object type:
		// `CREATE ROW POLICY OR REPLACE name ON …`. Both spellings are idempotent;
		// only the row-policy one is valid for a policy (see F-50, 2026-07-21:
		// the `CREATE OR REPLACE ROW POLICY` spelling parsed as CREATE OR REPLACE
		// TABLE and failed 1,560 times without ever succeeding).
		if strings.Contains(s, "CREATE OR REPLACE") || strings.Contains(s, "OR REPLACE ROW POLICY") ||
			strings.Contains(s, "ROW POLICY OR REPLACE") {
			continue
		}
		// The corr_current backfill INSERT is idempotent by construction: its
		// NOT IN predicate makes any re-run a no-op (#100 hardening).
		if strings.Contains(s, "INSERT INTO netops.corr_current") {
			if !strings.Contains(s, "NOT IN") {
				t.Errorf("corr_current backfill must be idempotent via NOT IN: %.80s", s)
			}
			continue
		}
		if !strings.Contains(s, "IF NOT EXISTS") {
			t.Errorf("statement not idempotent (missing IF NOT EXISTS): %.80s", s)
		}
	}
}

func TestCorrSchemaTenantPartitioned(t *testing.T) {
	// House rule (#20 Phase 3): tenant_id leads every PARTITION BY for at-rest
	// per-tenant separation.
	for _, table := range []string{"corr_signals", "corr_signals_archive", "corr_objects", "corr_edges", "corr_evidence"} {
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
	for _, table := range []string{"corr_signals", "corr_signals_archive", "corr_objects", "corr_edges", "corr_evidence", "corr_current"} {
		if !strings.Contains(all, "tenant_iso_"+table) {
			t.Errorf("missing row policy for %s", table)
		}
	}
}

// #100 hardening freeze: corr_current is the HOT current-state projection.
// Its whole reason to exist is bounded reads — one narrow row per object.
func TestCorrCurrentIsNarrowAndReplacing(t *testing.T) {
	s := corrStmt(t, "corr_current")
	// Wide blob columns are BANNED here: a list page must never be able to drag
	// them through a scan. They live in corr_objects and are fetched keyed.
	for _, banned := range []string{"hypotheses", "layer_coverage", "app_impact"} {
		if strings.Contains(s, banned) {
			t.Errorf("corr_current: wide column %q is banned from the hot projection", banned)
		}
	}
	// Latest WRITE wins (created_at), not highest version: in-memory versions
	// reset to 1 on an engine restart, and a version-keyed fold would resurrect
	// the stale pre-restart row.
	if !strings.Contains(s, "ReplacingMergeTree(created_at)") {
		t.Error("corr_current: must be ReplacingMergeTree keyed on created_at")
	}
	// The dedup key (tenant_id, correlation_id) must never span partitions or
	// FINAL cannot collapse re-persists of the same object — tenant-only.
	if !strings.Contains(s, "PARTITION BY (tenant_id)") {
		t.Error("corr_current: must be partitioned by tenant_id ONLY (dedup key may not span partitions)")
	}
	if !strings.Contains(s, "ORDER BY (tenant_id, correlation_id)") {
		t.Error("corr_current: ORDER BY must be (tenant_id, correlation_id)")
	}
}

func TestCorrSignalsIndependenceGate(t *testing.T) {
	// Owner review 2026-06-11: the observer block is MANDATORY on every signal —
	// confirmation depends on observer independence (>=2 modality classes from
	// >=2 observers), and fate-sharing analysis needs the collection path (two
	// signals via the same SD-WAN controller are not independent).
	for _, table := range []string{"corr_signals", "corr_signals_archive"} {
		s := corrStmt(t, table)
		for _, col := range []string{
			"observer_id", "observer_type", "observer_location",
			"observer_trust_domain", "collection_path", "modality_class",
			"source_clock_quality",
		} {
			if !strings.Contains(s, col) {
				t.Errorf("%s: observer-block column %s missing", table, col)
			}
		}
		if !strings.Contains(s, "CONSTRAINT observer_required CHECK observer_id != ''") {
			t.Errorf("%s: CHECK observer_id != '' missing (observer block is mandatory)", table)
		}
	}
}

func TestCorrReplayRetentionTiering(t *testing.T) {
	// Owner review 2026-06-11 (replay gap): corr_objects are forever, but replay
	// re-runs over signals — so every persisted object's FULL window slice is
	// archived without TTL, while the hot spine keeps its 30-day TTL.
	hot := corrStmt(t, "corr_signals")
	if !strings.Contains(hot, "TTL toDateTime(ts) + INTERVAL 30 DAY") {
		t.Error("corr_signals: hot spine must keep its 30-day TTL")
	}
	arch := corrStmt(t, "corr_signals_archive")
	if strings.Contains(arch, "TTL ") {
		t.Error("corr_signals_archive: must have NO TTL (replay input, forever)")
	}
	for _, col := range []string{"archived_for", "archived_at"} {
		if !strings.Contains(arch, col) {
			t.Errorf("corr_signals_archive: %s missing (archiving provenance)", col)
		}
	}
	// Structural identity: every signal column must exist in the archive too,
	// or replay reads (archive ∪ hot) would diverge.
	for _, line := range strings.Split(hot, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "CREATE") || strings.HasPrefix(l, "(") ||
			strings.HasPrefix(l, ")") || strings.HasPrefix(l, "--") ||
			strings.HasPrefix(l, "ENGINE") || strings.HasPrefix(l, "PARTITION") ||
			strings.HasPrefix(l, "ORDER") || strings.HasPrefix(l, "TTL") ||
			strings.HasPrefix(l, "SETTINGS") || strings.HasPrefix(l, "CONSTRAINT") ||
			strings.HasPrefix(l, "'") {
			continue
		}
		col := strings.Fields(l)[0]
		if !strings.Contains(arch, col) {
			t.Errorf("corr_signals_archive: column %q missing (must mirror corr_signals)", col)
		}
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

// TestCorrSignalEnumsConsistent — 2026-07-09 outage guard. Every Enum8
// definition for a signal-spine column must be IDENTICAL everywhere it appears:
// the Go CREATEs, the Go converge ALTERs, and init.sql's fresh-install blocks.
// When a new signal class lands in one place only, live tables drift ahead of
// the code's ALTER; ClickHouse then refuses the (now value-dropping) ALTER on a
// key column on every boot, and the converge list stalls behind it — this is
// exactly how corr_current failed to be created ('controller'=11 existed live
// and in init.sql, but not in the corrSchemaDDL ALTER).
func TestCorrSignalEnumsConsistent(t *testing.T) {
	initSQL, err := os.ReadFile("../../deployment/docker/clickhouse/init.sql")
	if err != nil {
		t.Fatalf("read init.sql: %v", err)
	}
	goDDL := strings.Join(corrSchemaDDL(), "\n")
	norm := regexp.MustCompile(`\s+`)
	for _, col := range []string{"source", "observer_type", "entity_type", "modality_class"} {
		// Multi-line bodies are fine: enum bodies contain no ')'.
		re := regexp.MustCompile(col + `\s+Enum8\(([^)]*)\)`)
		defs := map[string][]string{}
		for src, text := range map[string]string{"corr_schema.go": goDDL, "init.sql": string(initSQL)} {
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				body := norm.ReplaceAllString(m[1], "")
				defs[body] = append(defs[body], src)
			}
		}
		if len(defs) == 0 {
			t.Errorf("%s: no Enum8 definition found in either source", col)
		}
		if len(defs) > 1 {
			t.Errorf("%s: enum definitions diverge across corr_schema.go/init.sql (stale converge ALTER breaks every boot): %v", col, defs)
		}
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
