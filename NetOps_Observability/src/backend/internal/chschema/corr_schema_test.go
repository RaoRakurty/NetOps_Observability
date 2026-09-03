package chschema

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
	for _, s := range CorrSchemaDDL() {
		if strings.Contains(s, "CREATE TABLE IF NOT EXISTS netops."+table+"\n") ||
			strings.Contains(s, "CREATE TABLE IF NOT EXISTS netops."+table+" ") {
			return s
		}
	}
	t.Fatalf("no CREATE TABLE statement for %s", table)
	return ""
}

func TestCorrSchemaIdempotent(t *testing.T) {
	for _, s := range CorrSchemaDDL() {
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
	all := strings.Join(CorrSchemaDDL(), "\n")
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
// and in init.sql, but not in the CorrSchemaDDL ALTER).
func TestCorrSignalEnumsConsistent(t *testing.T) {
	initSQL, err := os.ReadFile(repoFile(t, "deployment/docker/clickhouse/init.sql"))
	if err != nil {
		t.Fatalf("read init.sql: %v", err)
	}
	goDDL := strings.Join(CorrSchemaDDL(), "\n")
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
	for _, s := range CorrSchemaDDL() {
		if strings.Contains(strings.ToUpper(s), "MATERIALIZED VIEW") {
			t.Errorf("materialized view in corr schema is forbidden: %.80s", s)
		}
	}
}

// ── boot-reconcile decision for the `source` enum ───────────────────────────
// The reconcile mechanism for an ALREADY-INSTALLED stack is the unconditional
// `ALTER TABLE … MODIFY COLUMN source Enum8(<full superset>)` in CorrSchemaDDL,
// applied on every API boot by ensureCHRowPolicies → ConvergeStmts. init.sql
// runs only on a fresh data dir, so the ALTER is the ONLY thing that carries a
// new signal class onto an upgraded deployment. ClickHouse has no
// `MODIFY COLUMN IF NOT EXISTS`, so idempotence is structural rather than
// syntactic: the statement always names the full superset, therefore
//
//	live enum LACKS the value  → the ALTER WIDENS it (value learned)
//	live enum HAS the value    → the ALTER is type-identical (metadata no-op)
//
// and it can never DROP a value (which ClickHouse refuses on a key column, and
// which is how the 2026-07-09 outage stalled the whole converge list).
// These are the two arms of that decision, asserted over the exact strings the
// boot path emits — no ClickHouse needed, and no live ALTER is ever run here.

var enum8ValueRe = regexp.MustCompile(`'([^']+)'\s*=\s*(-?\d+)`)

// parseEnum8 renders an Enum8 body as value→number, the shape ClickHouse
// compares when it decides whether a MODIFY COLUMN is a widening or a drop.
func parseEnum8(t *testing.T, body string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range enum8ValueRe.FindAllStringSubmatch(body, -1) {
		if prev, dup := out[m[1]]; dup {
			t.Fatalf("enum body lists %q twice (=%s and =%s)", m[1], prev, m[2])
		}
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatalf("no Enum8 values parsed from %q", body)
	}
	return out
}

// sourceEnumOf pulls the `source` Enum8 body out of one DDL statement.
func sourceEnumOf(t *testing.T, stmt string) map[string]string {
	t.Helper()
	m := regexp.MustCompile(`source\s+Enum8\(([^)]*)\)`).FindStringSubmatch(stmt)
	if m == nil {
		t.Fatalf("no `source` Enum8 in statement: %.120s", stmt)
	}
	return parseEnum8(t, m[1])
}

func TestCorrSignalSourceEnumConvergeDecision(t *testing.T) {
	// The pre-bgp shape: what a deployment installed before this change is
	// running live right now. Frozen literal on purpose — reading it back out
	// of the code under test would assert nothing.
	live := map[string]string{
		"flow": "1", "probe": "2", "metric": "3", "alert": "4", "topology": "5",
		"syslog": "6", "sot_drift": "7", "trap": "8", "cloud": "9",
		"app_identity": "10", "controller": "11", "verification": "12",
		"audit": "13", "security": "14",
	}

	for _, table := range []string{"corr_signals", "corr_signals_archive"} {
		var alter string
		for _, s := range CorrSchemaDDL() {
			if strings.HasPrefix(s, "ALTER TABLE netops."+table+" MODIFY COLUMN source ") {
				if alter != "" {
					t.Fatalf("%s: more than one source MODIFY COLUMN in the converge list", table)
				}
				alter = s
			}
		}
		if alter == "" {
			t.Fatalf("%s: no `MODIFY COLUMN source` in the converge list — an upgraded stack would never learn a new signal class (init.sql runs only on a fresh data dir)", table)
		}
		converge := sourceEnumOf(t, alter)

		// ARM 1 — value ABSENT live → the ALTER widens, and widens ONLY.
		if converge["bgp"] != "15" {
			t.Errorf("%s: converge ALTER must carry 'bgp'=15 (got %q) — signals.py Source.BGP cannot be persisted without it", table, converge["bgp"])
		}
		for name, num := range live {
			got, ok := converge[name]
			if !ok {
				t.Errorf("%s: converge ALTER DROPS '%s' — ClickHouse refuses a value-dropping enum ALTER on a key column and the whole converge list stalls behind it (2026-07-09)", table, name)
				continue
			}
			if got != num {
				t.Errorf("%s: '%s' remapped %s → %s; an existing row's stored ordinal would change meaning", table, name, num, got)
			}
		}

		// ARM 2 — value PRESENT live → re-applying is a type-identical no-op.
		// "Live" here is the state ARM 1 leaves behind: the converge enum itself.
		alreadyConverged := sourceEnumOf(t, alter)
		if len(alreadyConverged) != len(converge) {
			t.Fatalf("%s: enum parse is not deterministic", table)
		}
		for name, num := range converge {
			if alreadyConverged[name] != num {
				t.Errorf("%s: re-applying the converge ALTER would change '%s' (%s → %s) — it must be a metadata no-op on an already-converged table", table, name, num, alreadyConverged[name])
			}
		}

		// The CREATE (fresh install) and the ALTER (upgrade) must land the same
		// type, or the two install paths diverge on the very next boot.
		if fresh := sourceEnumOf(t, corrStmt(t, table)); len(fresh) != len(converge) {
			t.Errorf("%s: CREATE has %d source values, converge ALTER %d", table, len(fresh), len(converge))
		} else {
			for name, num := range fresh {
				if converge[name] != num {
					t.Errorf("%s: CREATE and converge ALTER disagree on '%s' (%s vs %s)", table, name, num, converge[name])
				}
			}
		}
	}
}

// TestCorrSignalSourceEnumMatchesEvidenceClasses — the Go half of the enum-trio
// lockstep (correlation-data-contract.md §6a): every registered evidence class's
// Source value must exist in the ClickHouse `source` enum, or that lane grounds
// and reaches a verdict in process but cannot PERSIST. The Python half is
// src/correlation/test_bgp_grounding.py::
// test_every_registered_evidence_source_is_in_the_clickhouse_enum.
func TestCorrSignalSourceEnumMatchesEvidenceClasses(t *testing.T) {
	src, err := os.ReadFile(repoFile(t, "src/correlation/signals.py"))
	if err != nil {
		t.Skipf("correlation source not available: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "class Source(str, Enum):")
	if start < 0 {
		t.Fatal("signals.py: `class Source(str, Enum)` not found")
	}
	rest := body[start+len("class Source(str, Enum):"):]
	if end := strings.Index(rest, "\nclass "); end >= 0 {
		rest = rest[:end]
	}
	want := regexp.MustCompile(`(?m)^\s{4}[A-Z0-9_]+\s*=\s*"([a-z0-9_]+)"`).FindAllStringSubmatch(rest, -1)
	if len(want) == 0 {
		t.Fatal("signals.py: no Source members parsed")
	}
	have := sourceEnumOf(t, corrStmt(t, "corr_signals"))
	for _, m := range want {
		if _, ok := have[m[1]]; !ok {
			t.Errorf("signals.py Source has %q but the ClickHouse `source` enum does not — that lane cannot persist a signal", m[1])
		}
	}
}
