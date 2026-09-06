// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

// corr_repartition_test.go — the guard for the P2 storage-shape fix.
//
// Two classes of assertion:
//
//  1. SCHEMA CONTRACT — every corr_* history table is partitioned DAILY on the
//     very column its TTL is keyed on, and the hypotheses blob carries the
//     MEASURED codec. These are cheap to break by editing a CREATE and
//     expensive to notice: a monthly partition key does not fail anything, it
//     just quietly re-opens the 241x merge amplification and makes
//     ttl_only_drop_parts overshoot the retention horizon by a month.
//
//  2. MIGRATION BEHAVIOUR — the size gate, the batching, the resume, the
//     verification and the swap ordering, driven against a fake ClickHouse that
//     actually models per-partition row counts. The lab's 48.9 GiB corr_objects
//     must be SKIPPED, not rewritten, and a source that is still being written
//     to must ABORT rather than swap a short copy into place.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── helpers over the real DDL ───────────────────────────────────────────────

// createStmt returns the CREATE TABLE statement CorrSchemaDDL emits for a table.
func createStmt(t *testing.T, table string) string {
	t.Helper()
	want := "CREATE TABLE IF NOT EXISTS netops." + table + "\n"
	for _, s := range CorrSchemaDDL() {
		if strings.HasPrefix(s, want) {
			return s
		}
	}
	t.Fatalf("CorrSchemaDDL has no CREATE for netops.%s", table)
	return ""
}

var reClause = regexp.MustCompile(`(?m)^(PARTITION BY|ORDER BY|TTL) (.+)$`)

func clause(stmt, name string) string {
	for _, m := range reClause.FindAllStringSubmatch(stmt, -1) {
		if m[1] == name {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

func corrTablesInDDL(t *testing.T) []string {
	t.Helper()
	re := regexp.MustCompile(`CREATE TABLE IF NOT EXISTS netops\.(corr_\w+)`)
	var out []string
	for _, s := range CorrSchemaDDL() {
		if m := re.FindStringSubmatch(s); m != nil {
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		t.Fatal("no corr_* CREATE statements in CorrSchemaDDL — parser drift")
	}
	return out
}

// ── 1. schema contract ──────────────────────────────────────────────────────

// TestEveryCorrTableIsPartitionedDaily is coverage, not a fixed list: a corr_*
// table added with a monthly key would otherwise reproduce the 1.86 GiB /
// level-1,568 accumulated part this whole change exists to remove.
func TestEveryCorrTableIsPartitionedDaily(t *testing.T) {
	want := CorrDailyPartitionKeys()
	got := corrTablesInDDL(t)
	if len(got) != len(want) {
		t.Fatalf("corr_* tables in CorrSchemaDDL (%v) differ from the partition-key "+
			"contract (%d entries) — a new table needs a daily partition key", got, len(want))
	}
	for _, table := range got {
		expr, ok := want[table]
		if !ok {
			t.Errorf("netops.%s has no entry in CorrDailyPartitionKeys", table)
			continue
		}
		if got := clause(createStmt(t, table), "PARTITION BY"); got != expr {
			t.Errorf("netops.%s PARTITION BY %s, want %s", table, got, expr)
		}
	}
}

// TestNoCorrTableIsPartitionedMonthly is the blunt form of the same rule: the
// substring toYYYYMM( must not survive anywhere in the correlation schema.
func TestNoCorrTableIsPartitionedMonthly(t *testing.T) {
	monthly := regexp.MustCompile(`toYYYYMM\(`)
	for _, table := range corrTablesInDDL(t) {
		if monthly.MatchString(createStmt(t, table)) {
			t.Errorf("netops.%s still carries a MONTHLY partition/TTL expression; a "+
				"month-long partition is never finished, so "+
				"min_age_to_force_merge_on_partition_only can never fire", table)
		}
	}
}

// TestCorrCurrentStaysTenantOnly pins the ONE documented exception. Giving
// corr_current a date in its partition key would split its ReplacingMergeTree
// dedup key (tenant_id, correlation_id) across partitions, and FINAL cannot
// collapse a re-persist that spans partitions.
func TestCorrCurrentStaysTenantOnly(t *testing.T) {
	if got := clause(createStmt(t, "corr_current"), "PARTITION BY"); got != "(tenant_id)" {
		t.Errorf("corr_current PARTITION BY %s, want (tenant_id) — its dedup key may "+
			"not span partitions", got)
	}
	for _, tbl := range corrRepartitionTables() {
		if tbl.Name == "corr_current" {
			t.Error("corr_current must not be in the repartition set")
		}
	}
}

// TestPartitionColumnIsTheTTLColumn is the load-bearing invariant. With
// ttl_only_drop_parts = 1 a part is dropped only when EVERY row in it has
// expired, so a partition keyed on a different column than the TTL drops late —
// which is exactly what corr_objects did (partition on window_start, TTL on
// created_at, overshoot up to a month).
func TestPartitionColumnIsTheTTLColumn(t *testing.T) {
	ttlOf := map[string]string{}
	for _, s := range CorrRetentionDDL(corrRetentionProfiles["production"]) {
		m := regexp.MustCompile(`ALTER TABLE netops\.(\w+) MODIFY TTL toDateTime\((\w+)\)`).
			FindStringSubmatch(s)
		if m != nil {
			ttlOf[m[1]] = m[2]
		}
	}
	for _, tbl := range corrRepartitionTables() {
		if got := CorrDailyPartitionExpr(tbl.TimeCol); clause(createStmt(t, tbl.Name), "PARTITION BY") != got {
			t.Errorf("%s: descriptor TimeCol %q does not match the CREATE", tbl.Name, tbl.TimeCol)
		}
		// Tables whose TTL the retention profile owns.
		if col, ok := ttlOf[tbl.Name]; ok && col != tbl.TimeCol {
			t.Errorf("%s: TTL is keyed on %q but the partition is keyed on %q — "+
				"ttl_only_drop_parts = 1 would drop parts late", tbl.Name, col, tbl.TimeCol)
		}
		// Tables with a fixed TTL in the CREATE itself.
		if ttl := clause(createStmt(t, tbl.Name), "TTL"); ttl != "" {
			if !strings.HasPrefix(ttl, "toDateTime("+tbl.TimeCol+")") {
				t.Errorf("%s: CREATE TTL %q is not keyed on the partition column %q",
					tbl.Name, ttl, tbl.TimeCol)
			}
		}
	}
}

// TestRepartitionDescriptorsMatchTheSchema: the shadow table is built from these
// descriptors, so an ORDER BY that drifts from the CREATE would silently produce
// a differently sorted table at swap time.
func TestRepartitionDescriptorsMatchTheSchema(t *testing.T) {
	for _, tbl := range corrRepartitionTables() {
		if got := clause(createStmt(t, tbl.Name), "ORDER BY"); got != tbl.OrderBy {
			t.Errorf("%s: descriptor ORDER BY %s, schema %s", tbl.Name, tbl.OrderBy, got)
		}
	}
}

// TestHypothesesCarriesTheMeasuredCodec. MEASURED on 3,000 live blobs through
// clickhouse-local: LZ4 13.94x, ZSTD(1) 64.59x, ZSTD(3) 89.70x, ZSTD(6) 104.41x.
func TestHypothesesCarriesTheMeasuredCodec(t *testing.T) {
	if !strings.Contains(createStmt(t, "corr_objects"), "hypotheses       String CODEC(ZSTD(3))") {
		t.Error("corr_objects.hypotheses is not CODEC(ZSTD(3)) — it is 94 % of the " +
			"table's uncompressed bytes and LZ4 compresses it 6.4x worse")
	}
	want := "ALTER TABLE netops.corr_objects MODIFY COLUMN hypotheses String CODEC(ZSTD(3))"
	var found bool
	for _, s := range CorrSchemaDDL() {
		if s == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the boot converge does not carry %q — live deployments would keep LZ4", want)
	}
}

// TestCorrCurrentCarriesNoBlob: the #100 narrow projection must never grow a
// hypotheses column, or the codec decision has to be made twice.
func TestCorrCurrentCarriesNoBlob(t *testing.T) {
	if strings.Contains(createStmt(t, "corr_current"), "hypotheses") {
		t.Error("corr_current grew a hypotheses column — it is by design the NARROW " +
			"projection; the blob is fetched keyed from corr_objects")
	}
}

// ── 2. SQL builders ─────────────────────────────────────────────────────────

// TestEveryCorrReadCarriesTenantScope. The STRICT row policies filter SELECT on
// `tenant_scope`. A migration statement that read a corr table without it would
// copy ZERO rows and then "verify" zero against zero — a silent, total data loss
// at swap time. CLAUDE.md §3a rule 4.
func TestEveryCorrReadCarriesTenantScope(t *testing.T) {
	tbl := corrRepartitionTables()[0]
	reads := []string{
		CorrPartitionKeysSQL(tbl),
		CorrShadowPartitionKeysSQL(tbl),
		CorrPartitionCountSQL(tbl.Name, tbl, "acme", 20260803),
		CorrTotalCountSQL(tbl.Name),
	}
	reads = append(reads, CorrCopyPartitionStmts(tbl, "acme", 20260803, 10, 500000)...)
	for _, s := range reads {
		if !strings.Contains(s, "tenant_scope = '__all__'") {
			t.Errorf("statement reads a corr table without an explicit cross-tenant "+
				"scope and would copy zero rows: %s", s)
		}
	}
	// system.* statements must NOT carry it (custom settings on a system read are
	// noise, and system tables have no row policy).
	for _, s := range []string{CorrPartitionKeySQL("corr_objects"),
		CorrTableSizeSQL("corr_objects"), CorrColumnsSQL("corr_objects"),
		CorrTableExistsSQL("corr_objects")} {
		if !strings.Contains(s, "FROM system.") {
			t.Errorf("expected a system.* read: %s", s)
		}
	}
}

// TestShadowGetsItsPolicyBeforeAnyData — §3a rule 4 has no grace period.
func TestShadowGetsItsPolicyBeforeAnyData(t *testing.T) {
	tbl := corrRepartitionTables()[0]
	stmts := CorrShadowCreateStmts(tbl)
	if len(stmts) < 2 || !strings.HasPrefix(stmts[0], "CREATE TABLE IF NOT EXISTS netops.corr_objects__daily") {
		t.Fatalf("unexpected shadow create sequence: %v", stmts)
	}
	if !strings.Contains(stmts[1], "CREATE ROW POLICY OR REPLACE tenant_iso_corr_objects__daily") {
		t.Errorf("the shadow table's STRICT row policy is not the statement right after "+
			"its CREATE: %q", stmts[1])
	}
	if !strings.Contains(stmts[0], CorrDailyPartitionExpr("created_at")) {
		t.Error("shadow table is not created with the daily partition key")
	}
	// The merge budget must be on the shadow from birth: it becomes the live
	// table at swap time, and CorrMergeBudgetDDL only runs on the next boot.
	if !strings.Contains(stmts[0], "max_bytes_to_merge_at_max_space_in_pool = 2147483648") {
		t.Error("the corr_objects shadow is created outside the 2 GiB merge budget")
	}
	// And the codec, so the copy itself is the one-time ZSTD(3) rewrite.
	if !strings.Contains(strings.Join(stmts, "\n"), "MODIFY COLUMN hypotheses String CODEC(ZSTD(3))") {
		t.Error("the corr_objects shadow does not restate the ZSTD(3) codec")
	}
}

// TestCopyIsBatchedBySizeCap: a day bigger than the cap is copied in hourly
// sub-batches so no single statement's memory is a function of table size.
func TestCopyIsBatchedBySizeCap(t *testing.T) {
	tbl := corrRepartitionTables()[0]
	if got := CorrCopyPartitionStmts(tbl, "acme", 20260803, 100, 500000); len(got) != 1 {
		t.Errorf("a small partition should copy in ONE statement, got %d", len(got))
	}
	big := CorrCopyPartitionStmts(tbl, "acme", 20260803, 5_000_000, 500_000)
	if len(big) != 24 {
		t.Fatalf("an oversized partition should split into 24 hourly sub-batches, got %d", len(big))
	}
	for h, s := range big {
		if !strings.Contains(s, "toHour(created_at) = "+strconv.Itoa(h)) {
			t.Errorf("sub-batch %d does not bound its hour: %s", h, s)
		}
		if !strings.Contains(s, "max_insert_block_size = 100000") {
			t.Errorf("sub-batch %d has no insert-block bound", h)
		}
	}
}

// TestShadowTTLIsMetadataOnlyAndKeyedRight.
func TestShadowTTLIsMetadataOnlyAndKeyedRight(t *testing.T) {
	ret := corrRetentionProfiles["production"]
	for _, tbl := range corrRepartitionTables() {
		s := CorrShadowTTLStmt(tbl, ret)
		if s == "" {
			t.Errorf("%s: no shadow TTL for the production profile", tbl.Name)
			continue
		}
		if !strings.Contains(s, "MODIFY TTL toDateTime("+tbl.TimeCol+")") {
			t.Errorf("%s: shadow TTL is not keyed on the partition column: %s", tbl.Name, s)
		}
		if !strings.Contains(s, "materialize_ttl_after_modify = 0") {
			t.Errorf("%s: shadow TTL would launch a table-rewriting mutation: %s", tbl.Name, s)
		}
		if !strings.Contains(s, "netops."+tbl.Name+corrRepartitionShadowSuffix) {
			t.Errorf("%s: shadow TTL targets the LIVE table: %s", tbl.Name, s)
		}
	}
	// 0 days = explicit keep-forever: emit nothing rather than a 0-day TTL.
	keepForever := corrRetentionDays{History: 0, Archive: 0, Closed: 0}
	if got := CorrShadowTTLStmt(corrRepartitionTables()[0], keepForever); got != "" {
		t.Errorf("a keep-forever tier must emit no TTL, got %q", got)
	}
}

// TestShadowTTLMatchesTheLiveRetentionTTL is the anti-drift pin for tracker 208a
// (ultra-review #42).
//
// The shadow table the daily-repartition migration builds has to carry the SAME
// retention the live table carries — it BECOMES the live table at the swap. Both
// statements used to be written out longhand in two files, so a change to the
// expression's shape in corr_retention.go (the toDateTime() wrap, the INTERVAL
// unit, the materialize_ttl_after_modify setting) would leave the shadow
// rendering the old shape and nothing would notice until a table came out of a
// migration with a retention contract nobody wrote down.
//
// The assertion is deliberately EXACT-STRING and not "contains": the shadow TTL
// must be byte-identical to the live one for the same table and horizon, modulo
// the shadow suffix on the table name and nothing else. Rendering both through
// corrModifyTTLStmt is what makes that true; this test is what keeps it true.
func TestShadowTTLMatchesTheLiveRetentionTTL(t *testing.T) {
	for _, profile := range []string{"lab", "demo", "production"} {
		ret := corrRetentionProfiles[profile]
		live := CorrRetentionDDL(ret)
		for _, tbl := range corrRepartitionTables() {
			shadow := CorrShadowTTLStmt(tbl, ret)
			// Find the live MODIFY TTL for exactly this table (not a prefix
			// match: corr_signals_archive must not match corr_signals).
			var want string
			for _, stmt := range live {
				if strings.HasPrefix(stmt, "ALTER TABLE netops."+tbl.Name+" MODIFY TTL ") {
					want = stmt
					break
				}
			}
			if want == "" {
				// This table's horizon is not profile-resolved — it is written
				// into its own CREATE TABLE (corr_path_edges,
				// corr_tenant_write_amp). corr_schema.go is then the single
				// source, and the shadow must reproduce that clause exactly.
				schemaTTL := clause(createStmt(t, tbl.Name), "TTL")
				if schemaTTL == "" {
					// Genuinely keep-forever: the shadow must emit nothing.
					if shadow != "" {
						t.Errorf("%s/%s: neither the retention profile nor the schema sets a TTL, "+
							"but the shadow renders one: %q", profile, tbl.Name, shadow)
					}
					continue
				}
				wantShadow := corrModifyTTLStmt(tbl.Name+corrRepartitionShadowSuffix,
					tbl.TimeCol, ttlDaysFromClause(t, schemaTTL))
				if shadow != wantShadow {
					t.Errorf("%s/%s: shadow TTL has DRIFTED from the CREATE TABLE TTL in corr_schema.go\n"+
						" shadow: %s\n schema: %s", profile, tbl.Name, shadow, schemaTTL)
				}
				// And the clause the schema states must be the one the shadow
				// carries, expression and all.
				if !strings.Contains(shadow, schemaTTL) {
					t.Errorf("%s/%s: shadow TTL %q does not carry the schema's clause %q",
						profile, tbl.Name, shadow, schemaTTL)
				}
				continue
			}
			got := strings.Replace(shadow, "netops."+tbl.Name+corrRepartitionShadowSuffix,
				"netops."+tbl.Name, 1)
			if got != want {
				t.Errorf("%s/%s: shadow TTL has DRIFTED from the live retention TTL\n shadow: %s\n   live: %s",
					profile, tbl.Name, got, want)
			}
		}
	}
}

// ttlDaysFromClause pulls N out of "... + INTERVAL N DAY".
func ttlDaysFromClause(t *testing.T, clause string) int {
	t.Helper()
	_, rest, ok := strings.Cut(clause, "INTERVAL ")
	if !ok {
		t.Fatalf("TTL clause %q has no INTERVAL", clause)
	}
	numStr, _, ok := strings.Cut(rest, " DAY")
	if !ok {
		t.Fatalf("TTL clause %q is not expressed in DAY units", clause)
	}
	n, err := strconv.Atoi(numStr)
	if err != nil {
		t.Fatalf("TTL clause %q: %v", clause, err)
	}
	return n
}

// TestSwapOrdering: exchange, then rename the old data aside, then re-emit the
// STRICT policies. The pre-migration table is KEPT — it is the rollback.
func TestSwapOrdering(t *testing.T) {
	got := CorrSwapStmts(corrRepartitionTables()[0])
	want := []string{
		"EXCHANGE TABLES netops.corr_objects AND netops.corr_objects__daily",
		"RENAME TABLE netops.corr_objects__daily TO netops.corr_objects__premigration",
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("swap step %d = %q, want %q", i, got[i], w)
		}
	}
	rest := strings.Join(got[2:], "\n")
	for _, name := range []string{"tenant_iso_corr_objects ", "tenant_iso_corr_objects__premigration "} {
		if !strings.Contains(rest, "CREATE ROW POLICY OR REPLACE "+name) {
			t.Errorf("the swap does not re-emit the STRICT policy %q", name)
		}
	}
	for _, s := range got {
		if strings.Contains(s, "DROP TABLE") {
			t.Errorf("the swap must not destroy the pre-migration data: %q", s)
		}
	}
}

func TestChQuoteEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"acme":       `'acme'`,
		"":           `''`,
		"o'brien":    `'o\'brien'`,
		`back\slash`: `'back\\slash'`,
	} {
		if got := chQuote(in); got != want {
			t.Errorf("chQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestChIntAcceptsBothJSONShapes. ClickHouse's JSON format renders UInt64
// (count(), byte sums) as a STRING and smaller integers as numbers; a reader
// that handled only one would have seen every count as zero and "verified" a
// zero-row copy.
func TestChIntAcceptsBothJSONShapes(t *testing.T) {
	cases := []struct {
		in   any
		want int64
	}{{float64(12), 12}, {"12", 12}, {nil, 0}, {"", 0}, {int64(7), 7}}
	for _, c := range cases {
		got, err := chInt(c.in)
		if err != nil || got != c.want {
			t.Errorf("chInt(%#v) = %d, %v; want %d, nil", c.in, got, err, c.want)
		}
	}
	if _, err := chInt([]any{1}); err == nil {
		t.Error("chInt accepted an unreadable shape instead of reporting it")
	}
}

func TestNormalizeKeyIgnoresSpacing(t *testing.T) {
	if normalizeKey("(tenant_id,toYYYYMMDD(created_at))") !=
		normalizeKey("(tenant_id, toYYYYMMDD(created_at))") {
		t.Error("partition-key comparison is spacing sensitive — a live table would be " +
			"re-migrated on every boot")
	}
}

// ── 3. configuration ────────────────────────────────────────────────────────

func TestRepartitionConfigDefaults(t *testing.T) {
	t.Setenv("CORR_REPARTITION", "")
	t.Setenv("CORR_REPARTITION_MAX_GIB", "")
	t.Setenv("CORR_REPARTITION_BATCH_ROWS", "")
	t.Setenv("CORR_REPARTITION_CATCHUP_PASSES", "")
	t.Setenv("CORR_REPARTITION_DROP_OLD", "")
	cfg := CorrRepartitionConfig(func(string, ...any) {})
	// The default is CHECK, and that is an incident finding: on 2026-08-29 an
	// UNDER-gate table (corr_edges, 3.74 GiB) was rewritten automatically at api
	// boot while the stack was in use. The size gate cannot answer "is this a
	// good moment to rewrite a table" — only an operator can.
	if cfg.Mode != CorrRepartitionCheck {
		t.Errorf("default mode = %q, want %q — an under-gate table must not be "+
			"rewritten at boot without an operator asking for it", cfg.Mode, CorrRepartitionCheck)
	}
	if cfg.MaxUncompressedBytes != 4*1024*1024*1024 {
		t.Errorf("default gate = %d, want 4 GiB", cfg.MaxUncompressedBytes)
	}
	// The gate exists so the MEASURED lab table is not rewritten at boot.
	const labUncompressed = labUncompressedBytes // MEASURED, see the constant
	if labUncompressed <= cfg.MaxUncompressedBytes {
		t.Error("the default gate no longer skips the measured 48.9 GiB corr_objects")
	}
	if cfg.BatchRows != corrRepartitionDefaultBatchRows || cfg.CatchUpPasses != corrRepartitionDefaultCatchUp {
		t.Errorf("unexpected batching defaults: %+v", cfg)
	}
	if cfg.DropOld {
		t.Error("DropOld must default to false — the pre-migration table is the rollback")
	}
	if cfg.ReapPollInterval <= 0 || cfg.ReapPollAttempts <= 0 {
		t.Errorf("the orphaned-copy reaper has no cadence: %+v", cfg)
	}
	// Every mode still parses, so the incident default did not remove the
	// operator's ability to ask for the old behaviour.
	for _, mode := range []string{CorrRepartitionOff, CorrRepartitionCheck,
		CorrRepartitionAuto, CorrRepartitionForce} {
		t.Setenv("CORR_REPARTITION", strings.ToUpper(mode)) // and case-insensitively
		if got := CorrRepartitionConfig(func(string, ...any) {}).Mode; got != mode {
			t.Errorf("CORR_REPARTITION=%q resolved to %q", mode, got)
		}
	}
}

func TestRepartitionConfigRejectsGarbageWithoutWidening(t *testing.T) {
	t.Setenv("CORR_REPARTITION", "yes-please")
	t.Setenv("CORR_REPARTITION_MAX_GIB", "-3")
	t.Setenv("CORR_REPARTITION_BATCH_ROWS", "abc")
	t.Setenv("CORR_REPARTITION_CATCHUP_PASSES", "0")
	var logged []string
	cfg := CorrRepartitionConfig(func(f string, a ...any) { logged = append(logged, f) })
	if cfg.Mode != CorrRepartitionCheck {
		t.Errorf("an unknown mode must fall back to the REPORT-ONLY default, got %q — "+
			"a typo must never be the thing that rewrites a table", cfg.Mode)
	}
	if cfg.MaxUncompressedBytes != 4*1024*1024*1024 || cfg.BatchRows != corrRepartitionDefaultBatchRows ||
		cfg.CatchUpPasses != corrRepartitionDefaultCatchUp {
		t.Errorf("a garbage value widened the blast radius: %+v", cfg)
	}
	if len(logged) != 4 {
		t.Errorf("expected 4 log lines naming the rejected values, got %d", len(logged))
	}
}

// labUncompressedBytes is the MEASURED size of netops.corr_objects on the lab
// box: 48.9 GiB uncompressed (3.51 GiB on disk, 1,958,952 rows, ONE month
// partition). It is a constant here because the whole point of the size gate is
// that THIS table is skipped rather than rewritten at boot.
const labUncompressedBytes int64 = 52_506_192_281 // 48.9 * 2^30

// ── 4. migration behaviour against a fake ClickHouse ────────────────────────

// fakeCH models exactly what the migration observes: a partition key per table,
// per-(tenant, day) row counts for the source and the shadow, and the effects of
// CREATE / DROP PARTITION / INSERT SELECT / EXCHANGE / RENAME.
type fakeCH struct {
	stmts   []string
	keys    map[string]string           // table -> partition key
	rows    map[string]map[string]int64 // table -> "tenant|day" -> rows
	unc     map[string]int64            // table -> uncompressed bytes
	cols    map[string][]string
	growBy  int64  // rows appended to the source on every SOURCE partition read
	growKey string // which (tenant|day) grows
	grown   int

	// ── tracker 206: a source that MOVES under the copy ────────────────────────
	// Every read of the source's partition list is a chance for the source to
	// have changed since the last one — that is the whole failure mode. srcReads
	// counts them and onSourceRead lets a test mutate the SOURCE between passes
	// (expire a day under its TTL, delete rows inside a day) exactly the way
	// ClickHouse would, so the migration observes a genuinely shifting table
	// rather than a scripted one.
	srcReads     int
	onSourceRead func(f *fakeCH, read int)
	// onCopy fires the instant a partition lands in the shadow — the moment the
	// TTL-shrink wedge is made of. A test uses it to expire rows out of the
	// SOURCE mid-copy, which is the one ordering a whole-table row-count
	// comparison can never recover from.
	onCopy func(f *fakeCH, key string)

	// ── the orphaned-copy guard (incident 2026-08-29) ──────────────────────────
	// The fake models the ONE thing that made the incident possible: a copy whose
	// CLIENT call has returned is not a copy that has stopped.
	long        []fakeLong     // every ExecLong, in order
	failLong    map[int]error  // 1-based ExecLong index -> client error to return
	partialRows int64          // rows a failed copy has already written server-side
	orphanPolls int            // how many system.processes polls it stays RUNNING for
	running     map[string]int // query_id -> polls remaining before it is gone
	killed      []string       // query_ids KILLed
	dropLeaves  int64          // rows a DROP PARTITION leaves behind (a live writer)
}

// fakeLong is one recorded ExecLong call.
type fakeLong struct {
	sql     string
	queryID string
	budget  time.Duration
}

func newFakeCH() *fakeCH {
	return &fakeCH{
		keys: map[string]string{"corr_objects": "(tenant_id, toYYYYMM(window_start))"},
		rows: map[string]map[string]int64{"corr_objects": {
			"acme|20260801": 10, "acme|20260802": 20, "globex|20260802": 5,
		}},
		unc:  map[string]int64{"corr_objects": 1 << 20},
		cols: map[string][]string{"corr_objects": {"tenant_id", "correlation_id", "hypotheses"}},
	}
}

var (
	reInsert  = regexp.MustCompile(`INSERT INTO netops\.(\S+) SELECT \* FROM netops\.(\S+) WHERE tenant_id = '([^']*)' AND toYYYYMMDD\(\w+\) = (\d+)`)
	reDropPar = regexp.MustCompile(`ALTER TABLE netops\.(\S+) DROP PARTITION \('([^']*)', (\d+)\)`)
	reCreate  = regexp.MustCompile(`CREATE TABLE IF NOT EXISTS netops\.(\S+) AS netops\.(\S+)`)
	reExch    = regexp.MustCompile(`EXCHANGE TABLES netops\.(\S+) AND netops\.(\S+)`)
	reRename  = regexp.MustCompile(`RENAME TABLE netops\.(\S+) TO netops\.(\S+)`)
	reCount   = regexp.MustCompile(`SELECT count\(\) AS n FROM netops\.(\S+) WHERE tenant_id = '([^']*)' AND toYYYYMMDD\(\w+\) = (\d+)`)
	reTotal   = regexp.MustCompile(`SELECT count\(\) AS n FROM netops\.(\S+) SETTINGS`)
	reKeysQ   = regexp.MustCompile(`FROM netops\.(\S+) GROUP BY t, d`)
	reNameQ   = regexp.MustCompile(`name = '([^']*)'`)
	reHour    = regexp.MustCompile(`toHour\(\w+\) = (\d+)`)
	reQueryID = regexp.MustCompile(`query_id = '([^']*)'`)
)

func (f *fakeCH) total(table string) int64 {
	var n int64
	for _, v := range f.rows[table] {
		n += v
	}
	return n
}

func (f *fakeCH) Exec(_ context.Context, sql string) error {
	f.stmts = append(f.stmts, sql)
	f.apply(sql)
	return nil
}

// ExecLong models the long-copy seam, including the failure that started all of
// this: the client call returns an error, the server keeps writing, and the
// statement stays in system.processes under its query_id until it is killed.
func (f *fakeCH) ExecLong(ctx context.Context, sql string, opt CHLongOpts) error {
	f.long = append(f.long, fakeLong{sql: sql, queryID: opt.QueryID, budget: opt.Budget})
	if err, bad := f.failLong[len(f.long)]; bad {
		f.stmts = append(f.stmts, sql)
		one := strings.Join(strings.Fields(sql), " ")
		if m := reInsert.FindStringSubmatch(one); m != nil && f.partialRows > 0 {
			f.rows[m[1]][m[3]+"|"+m[4]] += f.partialRows // rows already written
		}
		if f.running == nil {
			f.running = map[string]int{}
		}
		f.running[opt.QueryID] = f.orphanPolls
		return err
	}
	return f.Exec(ctx, sql)
}

func (f *fakeCH) apply(sql string) {
	one := strings.Join(strings.Fields(sql), " ")
	switch {
	case strings.HasPrefix(one, "KILL QUERY WHERE query_id = "):
		qid := reQueryID.FindStringSubmatch(one)[1]
		delete(f.running, qid)
		f.killed = append(f.killed, qid)
	case reCreate.MatchString(one):
		m := reCreate.FindStringSubmatch(one)
		if f.rows[m[1]] == nil {
			f.rows[m[1]] = map[string]int64{}
			f.cols[m[1]] = append([]string(nil), f.cols[m[2]]...)
			f.keys[m[1]] = CorrDailyPartitionExpr("created_at")
		}
	case strings.HasPrefix(one, "DROP TABLE IF EXISTS netops."):
		name := strings.TrimPrefix(one, "DROP TABLE IF EXISTS netops.")
		delete(f.rows, name)
		delete(f.cols, name)
		delete(f.keys, name)
	case reDropPar.MatchString(one):
		m := reDropPar.FindStringSubmatch(one)
		if f.dropLeaves > 0 {
			// A live writer (an orphaned copy) refills the partition we just
			// dropped: the migration must notice and refuse to copy on top of it.
			f.rows[m[1]][m[2]+"|"+m[3]] = f.dropLeaves
			return
		}
		delete(f.rows[m[1]], m[2]+"|"+m[3])
	case reInsert.MatchString(one):
		m := reInsert.FindStringSubmatch(one)
		key := m[3] + "|" + m[4]
		src := f.rows[m[2]][key]
		if h := reHour.FindStringSubmatch(one); h != nil {
			// Hourly sub-batch: an even 24-way split of the day, remainder on hour 0.
			hour, _ := strconv.Atoi(h[1])
			share := src / 24
			if hour == 0 {
				share += src % 24
			}
			f.rows[m[1]][key] += share
		} else {
			f.rows[m[1]][key] += src
		}
		if f.onCopy != nil {
			f.onCopy(f, key)
		}
	case reExch.MatchString(one):
		m := reExch.FindStringSubmatch(one)
		f.rows[m[1]], f.rows[m[2]] = f.rows[m[2]], f.rows[m[1]]
		f.keys[m[1]], f.keys[m[2]] = f.keys[m[2]], f.keys[m[1]]
	case reRename.MatchString(one):
		m := reRename.FindStringSubmatch(one)
		f.rows[m[2]], f.cols[m[2]], f.keys[m[2]] = f.rows[m[1]], f.cols[m[1]], f.keys[m[1]]
		delete(f.rows, m[1])
		delete(f.cols, m[1])
		delete(f.keys, m[1])
	}
}

func (f *fakeCH) Query(_ context.Context, sql string) ([]map[string]any, error) {
	f.stmts = append(f.stmts, sql)
	one := strings.Join(strings.Fields(sql), " ")
	switch {
	case strings.HasPrefix(one, "SELECT partition_key"):
		name := reNameQ.FindStringSubmatch(one)[1]
		k, ok := f.keys[name]
		if !ok {
			return nil, nil
		}
		return []map[string]any{{"k": k}}, nil
	case strings.HasPrefix(one, "SELECT sum(rows)"):
		tbl := regexp.MustCompile(`table = '([^']*)'`).FindStringSubmatch(one)[1]
		return []map[string]any{{
			"n": strconv.FormatInt(f.total(tbl), 10), "unc": strconv.FormatInt(f.unc[tbl], 10),
			"cmp": "1024",
		}}, nil
	case strings.HasPrefix(one, "SELECT count() AS n FROM system.processes"):
		// system.processes holds only RUNNING queries. Each poll burns one of the
		// orphan's remaining lives, so a copy can be modelled as "finishes on its
		// own after N polls" or "never stops until killed".
		qid := reQueryID.FindStringSubmatch(one)[1]
		if n := f.running[qid]; n > 0 {
			f.running[qid] = n - 1
			return []map[string]any{{"n": "1"}}, nil
		}
		return []map[string]any{{"n": "0"}}, nil
	case strings.HasPrefix(one, "SELECT count() AS n FROM system.tables"):
		name := reNameQ.FindStringSubmatch(one)[1]
		n := "0"
		if _, ok := f.rows[name]; ok {
			n = "1"
		}
		return []map[string]any{{"n": n}}, nil
	case strings.HasPrefix(one, "SELECT name FROM system.columns"):
		tbl := regexp.MustCompile(`table = '([^']*)'`).FindStringSubmatch(one)[1]
		var out []map[string]any
		for _, c := range f.cols[tbl] {
			out = append(out, map[string]any{"name": c})
		}
		return out, nil
	case reKeysQ.MatchString(one):
		tbl := reKeysQ.FindStringSubmatch(one)[1]
		if !strings.HasSuffix(tbl, corrRepartitionShadowSuffix) {
			// Simulate the correlation engine writing THROUGH the copy: the SOURCE
			// changes every time the migration re-reads its partition list, so the
			// shadow can never catch up and the swap must be refused.
			f.srcReads++
			if f.growBy > 0 {
				f.grown++
				f.rows[tbl][f.growKey] += f.growBy
			}
			if f.onSourceRead != nil {
				f.onSourceRead(f, f.srcReads)
			}
		}
		var out []map[string]any
		for k, v := range f.rows[tbl] {
			parts := strings.SplitN(k, "|", 2)
			day, _ := strconv.ParseInt(parts[1], 10, 64)
			out = append(out, map[string]any{
				"t": parts[0], "d": float64(day), "n": strconv.FormatInt(v, 10),
			})
		}
		return out, nil
	case reCount.MatchString(one):
		m := reCount.FindStringSubmatch(one)
		return []map[string]any{{"n": strconv.FormatInt(f.rows[m[1]][m[2]+"|"+m[3]], 10)}}, nil
	case reTotal.MatchString(one):
		// Whole-table counts are CONTEXT in the abort message now, not the
		// verification (tracker 206) — the source only moves on a partition read.
		m := reTotal.FindStringSubmatch(one)
		return []map[string]any{{"n": strconv.FormatInt(f.total(m[1]), 10)}}, nil
	}
	return nil, nil
}

func (f *fakeCH) sawAny(sub string) bool {
	for _, s := range f.stmts {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// testCfg is AUTO (the pre-2026-08-29 default) because most of these tests
// assert what a migration DOES; the mode matrix below covers check/off/force.
// The reaper cadence is compressed so the orphan path runs without sleeping.
func testCfg() CorrRepartitionSettings {
	return CorrRepartitionSettings{
		Mode: CorrRepartitionAuto, MaxUncompressedBytes: 4 << 30,
		BatchRows: 500000, CatchUpPasses: 3,
		ReapPollInterval: time.Millisecond, ReapPollAttempts: 3,
	}
}

func runOne(t *testing.T, f *fakeCH, cfg CorrRepartitionSettings) (CorrRepartitionOutcome, []string) {
	t.Helper()
	var logs []string
	logf := func(format string, args ...any) {
		logs = append(logs, strings.Join(strings.Fields(fmt.Sprintf(format, args...)), " "))
	}
	out := migrateOne(context.Background(), f, cfg, corrRetentionProfiles["production"],
		corrRepartitionTables()[0], logf)
	return out, logs
}

// TestSizeGateSkipsTheMeasuredLabTable — the headline safety property. 48.9 GiB
// uncompressed must produce a LOUD skip and touch nothing.
func TestSizeGateSkipsTheMeasuredLabTable(t *testing.T) {
	f := newFakeCH()
	f.unc["corr_objects"] = labUncompressedBytes
	out, logs := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionSkippedBig {
		t.Fatalf("status = %q, want %q", out.Status, CorrRepartitionSkippedBig)
	}
	for _, forbidden := range []string{"CREATE TABLE", "INSERT INTO", "EXCHANGE TABLES", "DROP"} {
		if f.sawAny(forbidden) {
			t.Errorf("a skipped table must not be touched, but the migration ran %q", forbidden)
		}
	}
	joined := strings.Join(logs, " ")
	for _, want := range []string{"SKIPPED netops.corr_objects", "48.90 GiB",
		"CORR_REPARTITION_MAX_GIB", "CORR_REPARTITION=force"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the skip log line does not mention %q — an operator cannot act on it:\n%s",
				want, joined)
		}
	}
}

func TestForceModeIgnoresTheSizeGate(t *testing.T) {
	f := newFakeCH()
	f.unc["corr_objects"] = labUncompressedBytes
	cfg := testCfg()
	cfg.Mode = CorrRepartitionForce
	out, _ := runOne(t, f, cfg)
	if out.Status != CorrRepartitionDone {
		t.Fatalf("force mode status = %q (%s), want %q", out.Status, out.Detail, CorrRepartitionDone)
	}
	if !f.sawAny("EXCHANGE TABLES netops.corr_objects AND netops.corr_objects__daily") {
		t.Error("force mode did not swap")
	}
}

func TestOffModeTouchesNothing(t *testing.T) {
	f := newFakeCH()
	cfg := testCfg()
	cfg.Mode = CorrRepartitionOff
	res := RunCorrRepartition(context.Background(), f, cfg,
		corrRetentionProfiles["production"], func(string, ...any) {})
	if len(f.stmts) != 0 {
		t.Errorf("off mode issued %d statements", len(f.stmts))
	}
	for _, r := range res {
		if r.Status != CorrRepartitionSkippedOff {
			t.Errorf("%s: status %q", r.Table, r.Status)
		}
	}
}

// TestMigrationCopiesEveryRowThenSwaps.
func TestMigrationCopiesEveryRowThenSwaps(t *testing.T) {
	f := newFakeCH()
	before := f.total("corr_objects")
	out, _ := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q (%s)", out.Status, out.Detail)
	}
	if got := f.total("corr_objects"); got != before {
		t.Errorf("live table holds %d rows after the swap, want %d", got, before)
	}
	if f.keys["corr_objects"] != CorrDailyPartitionExpr("created_at") {
		t.Errorf("live partition key = %q", f.keys["corr_objects"])
	}
	if _, ok := f.rows["corr_objects__premigration"]; !ok {
		t.Error("the pre-migration table was not retained — there is no rollback")
	}
	if _, ok := f.rows["corr_objects__daily"]; ok {
		t.Error("the shadow name is still occupied; a re-run would append to it")
	}
}

// TestMigrationIsIdempotent — a second run is a no-op, not a second rewrite.
func TestMigrationIsIdempotent(t *testing.T) {
	f := newFakeCH()
	if out, _ := runOne(t, f, testCfg()); out.Status != CorrRepartitionDone {
		t.Fatalf("first run: %q (%s)", out.Status, out.Detail)
	}
	f.stmts = nil
	out, _ := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionAlready {
		t.Fatalf("second run status = %q, want %q", out.Status, CorrRepartitionAlready)
	}
	for _, s := range f.stmts {
		if !strings.HasPrefix(s, "SELECT partition_key") {
			t.Errorf("an already-daily table should cost ONE metadata read, but ran: %s", s)
		}
	}
}

// TestResumeSkipsCompleteAndRedoesPartialPartitions. The resume unit is one
// destination partition: complete ones are skipped, a partial one is DROPped
// and redone, so an interrupted migration never double-counts rows.
func TestResumeSkipsCompleteAndRedoesPartialPartitions(t *testing.T) {
	f := newFakeCH()
	// Simulate a crashed earlier attempt: one day complete, one half-copied.
	f.rows["corr_objects__daily"] = map[string]int64{"acme|20260801": 10, "acme|20260802": 7}
	f.cols["corr_objects__daily"] = append([]string(nil), f.cols["corr_objects"]...)
	f.keys["corr_objects__daily"] = CorrDailyPartitionExpr("created_at")
	out, _ := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q (%s)", out.Status, out.Detail)
	}
	if got := f.total("corr_objects"); got != 35 {
		t.Errorf("resumed copy holds %d rows, want 35 — a partial partition was appended "+
			"to instead of redone", got)
	}
	if !f.sawAny("DROP PARTITION ('acme', 20260802)") {
		t.Error("the half-copied partition was not dropped before being redone")
	}
	if f.sawAny("DROP PARTITION ('acme', 20260801)") {
		t.Error("a COMPLETE partition was re-copied — the migration is not resumable, " +
			"it just restarts")
	}
}

// TestDriftedShadowIsRebuilt: `INSERT ... SELECT *` is positional, so a shadow
// left from before a converge ADD COLUMN must be dropped, never appended to.
func TestDriftedShadowIsRebuilt(t *testing.T) {
	f := newFakeCH()
	f.rows["corr_objects__daily"] = map[string]int64{"acme|20260801": 10}
	f.cols["corr_objects__daily"] = []string{"tenant_id", "correlation_id"} // missing hypotheses
	f.keys["corr_objects__daily"] = CorrDailyPartitionExpr("created_at")
	if out, _ := runOne(t, f, testCfg()); out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q (%s)", out.Status, out.Detail)
	}
	if !f.sawAny("DROP TABLE IF EXISTS netops.corr_objects__daily") {
		t.Error("a column-drifted shadow was reused instead of rebuilt")
	}
	if got := f.total("corr_objects"); got != 35 {
		t.Errorf("live table holds %d rows, want 35", got)
	}
}

// TestSwapIsRefusedWhileTheSourceIsStillWritten — the property that makes an
// automatic migration safe at all: a short copy is ABORTED, never swapped.
func TestSwapIsRefusedWhileTheSourceIsStillWritten(t *testing.T) {
	f := newFakeCH()
	f.growBy, f.growKey = 3, "acme|20260802"
	out, logs := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionUnstable {
		t.Fatalf("status = %q (%s), want %q", out.Status, out.Detail, CorrRepartitionUnstable)
	}
	if f.sawAny("EXCHANGE TABLES") {
		t.Error("a table that never converged was swapped in — rows written during the " +
			"copy would be lost")
	}
	if _, ok := f.rows["corr_objects__daily"]; !ok {
		t.Error("the partial copy was discarded; the next run cannot resume it")
	}
	joined := strings.Join(logs, " ")
	if !strings.Contains(joined, "ABORTED") || !strings.Contains(joined, "live table is untouched") {
		t.Errorf("the abort is not legible to an operator:\n%s", joined)
	}
}

// TestBackupCollisionBlocksInsteadOfOverwriting.
func TestBackupCollisionBlocksInsteadOfOverwriting(t *testing.T) {
	f := newFakeCH()
	f.rows["corr_objects__premigration"] = map[string]int64{"acme|20260701": 1}
	out, logs := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionBlocked {
		t.Fatalf("status = %q, want %q", out.Status, CorrRepartitionBlocked)
	}
	if f.sawAny("DROP TABLE") || f.sawAny("EXCHANGE") {
		t.Error("an existing pre-migration table was silently destroyed")
	}
	if !strings.Contains(strings.Join(logs, " "), "DROP TABLE netops.corr_objects__premigration") {
		t.Error("the block does not tell the operator how to clear it")
	}
}

func TestAbsentTableIsNotAnError(t *testing.T) {
	f := newFakeCH()
	delete(f.keys, "corr_objects")
	out, _ := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionAbsent {
		t.Errorf("status = %q, want %q", out.Status, CorrRepartitionAbsent)
	}
}

// TestDropOldRemovesTheBackupOnlyWhenAsked.
func TestDropOldRemovesTheBackupOnlyWhenAsked(t *testing.T) {
	f := newFakeCH()
	cfg := testCfg()
	cfg.DropOld = true
	if out, _ := runOne(t, f, cfg); out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q", out.Status)
	}
	if !f.sawAny("DROP TABLE IF EXISTS netops.corr_objects__premigration") {
		t.Error("CORR_REPARTITION_DROP_OLD=true did not drop the pre-migration table")
	}
}

// TestOversizedPartitionCopiesEveryRowInSubBatches — the batching must not lose
// the remainder when a day's row count is not divisible by 24.
func TestOversizedPartitionCopiesEveryRowInSubBatches(t *testing.T) {
	f := newFakeCH()
	f.rows["corr_objects"] = map[string]int64{"acme|20260801": 1_000_001}
	cfg := testCfg()
	cfg.BatchRows = 1000
	if out, _ := runOne(t, f, cfg); out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q", out.Status)
	}
	if got := f.total("corr_objects"); got != 1_000_001 {
		t.Errorf("sub-batched copy holds %d rows, want 1000001", got)
	}
}

// ── 5. the orphaned-copy guard (incident 2026-08-29) ────────────────────────
//
// The incident in one line: the copy's CLIENT call failed, the migration
// correctly refused to swap, and the INSERT ... SELECT went on running
// server-side with 121,495 rows already written — found minutes later in
// system.processes and killed by hand. These tests pin the three properties
// that make that unrepresentable.

// TestCopyQueryIDIsDeterministic — the id is the only handle that can find a
// copy in system.processes or address it to KILL, so it must be reproducible
// from the unit of work alone, and different for every distinct unit.
func TestCopyQueryIDIsDeterministic(t *testing.T) {
	a := CorrCopyQueryID("corr_edges", "global", 20260821, 1, 0)
	if b := CorrCopyQueryID("corr_edges", "global", 20260821, 1, 0); a != b {
		t.Errorf("the same copy produced two ids: %q vs %q", a, b)
	}
	for _, want := range []string{"corr-repartition", "corr_edges", "global", "20260821", ".p1", ".b0"} {
		if !strings.Contains(a, want) {
			t.Errorf("query_id %q does not name %q — it is unusable in a log or a KILL", a, want)
		}
	}
	// Every coordinate must move the id: two units of work sharing one id would
	// let a reaper kill the wrong statement.
	seen := map[string]string{}
	for _, c := range []struct {
		label         string
		table, tenant string
		day           int64
		pass, batch   int
	}{
		{"base", "corr_edges", "global", 20260821, 1, 0},
		{"table", "corr_objects", "global", 20260821, 1, 0},
		{"tenant", "corr_edges", "acme", 20260821, 1, 0},
		{"day", "corr_edges", "global", 20260822, 1, 0},
		{"pass", "corr_edges", "global", 20260821, 2, 0},
		{"batch", "corr_edges", "global", 20260821, 1, 1},
	} {
		id := CorrCopyQueryID(c.table, c.tenant, c.day, c.pass, c.batch)
		if prev, dup := seen[id]; dup {
			t.Errorf("%s and %s collide on query_id %q", c.label, prev, id)
		}
		seen[id] = c.label
	}
}

// TestCopyQueryIDSanitisesTheTenant. A tenant id is tenant-controlled data (§3):
// it must not be able to inject quotes into a KILL statement, blow up the id's
// length, or collapse two tenants onto one id.
func TestCopyQueryIDSanitisesTheTenant(t *testing.T) {
	for _, tenant := range []string{"a'; KILL QUERY WHERE 1 --", strings.Repeat("x", 200), "tenant one", ""} {
		id := CorrCopyQueryID("corr_edges", tenant, 20260821, 1, 0)
		if strings.ContainsAny(id, "'\" \t\n;") {
			t.Errorf("query_id %q for tenant %q carries quoting/whitespace", id, tenant)
		}
		if len(id) > 160 {
			t.Errorf("query_id for tenant %q is %d chars", tenant, len(id))
		}
	}
	// Two tenants that sanitise to the same text keep DIFFERENT ids.
	if a, b := corrIDSafe("a b"), corrIDSafe("a-b"); a == b {
		t.Errorf("distinct tenants collapsed onto one id component: %q", a)
	}
	// An already-safe tenant id is left alone — the id stays greppable.
	if got := corrIDSafe("acme-1_2"); got != "acme-1_2" {
		t.Errorf("corrIDSafe mangled a safe id: %q", got)
	}
}

// TestCopyBudgetIsDerivedFromRowsAndClamped. The budget is what makes the
// ordinary case "the client waits" instead of "the client gives up and the
// server keeps going".
func TestCopyBudgetIsDerivedFromRowsAndClamped(t *testing.T) {
	if got := CorrCopyBudget(0); got != corrCopyBudgetMin {
		t.Errorf("CorrCopyBudget(0) = %s, want the %s floor", got, corrCopyBudgetMin)
	}
	if got := CorrCopyBudget(1); got != corrCopyBudgetMin {
		t.Errorf("CorrCopyBudget(1) = %s, want the %s floor", got, corrCopyBudgetMin)
	}
	if got, want := CorrCopyBudget(240_000), 20*time.Minute; got != want {
		t.Errorf("CorrCopyBudget(240000) = %s, want %s (200 rows/s floor)", got, want)
	}
	if got := CorrCopyBudget(1 << 40); got != corrCopyBudgetMax {
		t.Errorf("CorrCopyBudget(2^40) = %s, want the %s cap (and never a negative "+
			"Duration from nanosecond overflow)", got, corrCopyBudgetMax)
	}
	// The incident's partition: >600 s of server time had produced 121,495 rows.
	// A copy of that size must be given minutes, not the 12 s the client allowed.
	if got := CorrCopyBudget(121_495); got < 10*time.Minute {
		t.Errorf("the incident's partition would get only %s", got)
	}
}

// TestEveryCopyCarriesItsQueryIDAndBudget — asserted on a real migration run,
// not on the builder, so a copy issued through some other path fails here.
func TestEveryCopyCarriesItsQueryIDAndBudget(t *testing.T) {
	f := newFakeCH()
	if out, _ := runOne(t, f, testCfg()); out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q (%s)", out.Status, out.Detail)
	}
	if len(f.long) != 3 {
		t.Fatalf("expected 3 partition copies, got %d", len(f.long))
	}
	seen := map[string]bool{}
	for _, l := range f.long {
		if l.queryID == "" {
			t.Errorf("a copy ran with no query_id — it could never be found or killed: %s", l.sql)
		}
		if seen[l.queryID] {
			t.Errorf("two copies share query_id %q", l.queryID)
		}
		seen[l.queryID] = true
		if l.budget <= 0 {
			t.Errorf("copy %q ran with no server-side bound", l.queryID)
		}
		if l.budget != CorrCopyBudget(10) && l.budget != CorrCopyBudget(20) && l.budget != CorrCopyBudget(5) {
			t.Errorf("copy %q budget %s is not derived from its row count", l.queryID, l.budget)
		}
	}
	// The copies must go through ExecLong, never the plain Exec path.
	for _, s := range f.stmts {
		if strings.HasPrefix(strings.TrimSpace(s), "INSERT INTO") {
			var viaLong bool
			for _, l := range f.long {
				if l.sql == s {
					viaLong = true
				}
			}
			if !viaLong {
				t.Errorf("an INSERT ran outside the long-statement seam: %s", s)
			}
		}
	}
}

// TestClientTimeoutPollsThenKillsTheOrphan — THE incident path. The client call
// fails, the server keeps writing; the migration must poll for the query_id and
// KILL it before it declares the partition failed.
func TestClientTimeoutPollsThenKillsTheOrphan(t *testing.T) {
	f := newFakeCH()
	f.rows["corr_objects"] = map[string]int64{"global|20260821": 200_000}
	f.failLong = map[int]error{1: errors.New(
		`clickhouse repartition: transport: Post "https://clickhouse:8443?...": timeout`)}
	f.partialRows = 121_495 // what the orphan had already written, as measured
	f.orphanPolls = 99      // it never stops on its own
	out, logs := runOne(t, f, testCfg())

	if out.Status != CorrRepartitionFailed {
		t.Fatalf("status = %q (%s), want %q", out.Status, out.Detail, CorrRepartitionFailed)
	}
	qid := CorrCopyQueryID("corr_objects", "global", 20260821, 1, 0)
	if len(f.killed) != 1 || f.killed[0] != qid {
		t.Fatalf("killed = %v, want exactly [%s] — the copy was left running server-side, "+
			"which is the 2026-08-29 incident", f.killed, qid)
	}
	if _, still := f.running[qid]; still {
		t.Error("the orphan is still in system.processes after the reap")
	}
	if !strings.Contains(out.Detail, "orphan killed") || !strings.Contains(out.Detail, qid) {
		t.Errorf("the failure detail does not report the reap: %q", out.Detail)
	}
	joined := strings.Join(logs, " ")
	for _, want := range []string{"STILL RUNNING", "poll 1/3", "KILLed orphaned copy", qid} {
		if !strings.Contains(joined, want) {
			t.Errorf("the reap is not legible to an operator (missing %q):\n%s", want, joined)
		}
	}
	// Nothing was swapped, and the partial rows are still there for the redo.
	if f.sawAny("EXCHANGE TABLES") {
		t.Error("a failed copy was swapped in")
	}
	if got := f.rows["corr_objects__daily"]["global|20260821"]; got != 121_495 {
		t.Errorf("shadow partition holds %d rows, want the 121495 the orphan wrote", got)
	}
}

// TestCopyThatStopsOnItsOwnIsNotKilled — the reaper must not fire a KILL at a
// statement that already finished; polling is what tells the difference.
func TestCopyThatStopsOnItsOwnIsNotKilled(t *testing.T) {
	f := newFakeCH()
	f.rows["corr_objects"] = map[string]int64{"global|20260821": 10}
	f.failLong = map[int]error{1: errors.New("transport: connection reset")}
	f.orphanPolls = 1 // running at the first poll, gone by the second
	out, logs := runOne(t, f, testCfg())

	if out.Status != CorrRepartitionFailed {
		t.Fatalf("status = %q, want %q", out.Status, CorrRepartitionFailed)
	}
	if len(f.killed) != 0 {
		t.Errorf("KILLed %v — the copy had already stopped", f.killed)
	}
	if !strings.Contains(out.Detail, "left nothing running") {
		t.Errorf("the detail does not say the server was clean: %q", out.Detail)
	}
	if !strings.Contains(strings.Join(logs, " "), "STILL RUNNING") {
		t.Error("the reaper did not poll before concluding")
	}
}

// TestReapSurvivesACancelledMigrationContext. The ctx that failed the copy is
// often the ctx that expired; reaping on it would skip the KILL and leave the
// orphan — the exact failure the reaper exists for.
func TestReapSurvivesACancelledMigrationContext(t *testing.T) {
	f := newFakeCH()
	qid := "corr-repartition.corr_objects.global.20260821.p1.b0"
	f.running = map[string]int{qid: 99}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	verdict := reapCopy(ctx, f, testCfg(), qid, func(string, ...any) {})
	if len(f.killed) != 1 || f.killed[0] != qid {
		t.Fatalf("killed = %v on a cancelled context, want [%s]", f.killed, qid)
	}
	if !strings.Contains(verdict, "orphan killed") {
		t.Errorf("verdict = %q", verdict)
	}
}

// TestPartialPartitionIsDroppedBeforeItIsRecopied. The incident left 121,495
// rows in the shadow's (global, 20260821); the next attempt must DROP that
// partition BEFORE re-copying, or the redo doubles the rows.
func TestPartialPartitionIsDroppedBeforeItIsRecopied(t *testing.T) {
	f := newFakeCH()
	f.rows["corr_objects"] = map[string]int64{"global|20260821": 200_000}
	f.rows["corr_objects__daily"] = map[string]int64{"global|20260821": 121_495}
	f.cols["corr_objects__daily"] = append([]string(nil), f.cols["corr_objects"]...)
	f.keys["corr_objects__daily"] = CorrDailyPartitionExpr("created_at")

	out, _ := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q (%s)", out.Status, out.Detail)
	}
	if got := f.total("corr_objects"); got != 200_000 {
		t.Errorf("live table holds %d rows, want 200000 — the partial copy was appended to", got)
	}
	var dropAt, copyAt = -1, -1
	for i, s := range f.stmts {
		one := strings.Join(strings.Fields(s), " ")
		if dropAt < 0 && strings.Contains(one, "DROP PARTITION ('global', 20260821)") {
			dropAt = i
		}
		if copyAt < 0 && strings.HasPrefix(one, "INSERT INTO netops.corr_objects__daily") {
			copyAt = i
		}
	}
	if dropAt < 0 {
		t.Fatal("the partial partition was never dropped")
	}
	if copyAt < 0 || dropAt > copyAt {
		t.Errorf("DROP PARTITION at %d but the copy at %d — the redo copies on top of the "+
			"partial rows", dropAt, copyAt)
	}
	// And the drop is CONFIRMED before the copy: a re-count of the destination
	// partition has to sit between them.
	var confirmed bool
	for _, s := range f.stmts[dropAt+1 : copyAt] {
		if reCount.MatchString(strings.Join(strings.Fields(s), " ")) {
			confirmed = true
		}
	}
	if !confirmed {
		t.Error("the drop is not verified before the re-copy; an orphaned writer refilling " +
			"the partition would go unnoticed")
	}
}

// TestRefusesToCopyOverALiveWriter — if the destination partition still holds
// rows after DROP PARTITION, something else is writing to it (an orphan). The
// migration must stop, not copy on top of it.
func TestRefusesToCopyOverALiveWriter(t *testing.T) {
	f := newFakeCH()
	f.rows["corr_objects"] = map[string]int64{"global|20260821": 200_000}
	f.rows["corr_objects__daily"] = map[string]int64{"global|20260821": 121_495}
	f.cols["corr_objects__daily"] = append([]string(nil), f.cols["corr_objects"]...)
	f.keys["corr_objects__daily"] = CorrDailyPartitionExpr("created_at")
	f.dropLeaves = 130_000 // the orphan keeps writing through our DROP

	out, _ := runOne(t, f, testCfg())
	if out.Status != CorrRepartitionFailed {
		t.Fatalf("status = %q (%s), want %q", out.Status, out.Detail, CorrRepartitionFailed)
	}
	if !strings.Contains(out.Detail, "refusing to re-copy") {
		t.Errorf("detail = %q, want the refusal to name itself", out.Detail)
	}
	if len(f.long) != 0 {
		t.Errorf("%d copies ran on top of a live writer", len(f.long))
	}
	if f.sawAny("EXCHANGE TABLES") {
		t.Error("the table was swapped despite the refusal")
	}
}

// ── 6. the mode matrix ──────────────────────────────────────────────────────

// TestModeMatrix pins what each CORR_REPARTITION mode does to an under-gate and
// an over-gate table. `check` — the default since the incident — must touch
// NOTHING in either case.
func TestModeMatrix(t *testing.T) {
	const small = 1 << 20
	cases := []struct {
		mode    string
		unc     int64
		want    string
		touches bool
	}{
		{CorrRepartitionCheck, small, CorrRepartitionWouldMigrate, false},
		{CorrRepartitionCheck, labUncompressedBytes, CorrRepartitionWouldSkip, false},
		{CorrRepartitionAuto, small, CorrRepartitionDone, true},
		{CorrRepartitionAuto, labUncompressedBytes, CorrRepartitionSkippedBig, false},
		{CorrRepartitionForce, small, CorrRepartitionDone, true},
		{CorrRepartitionForce, labUncompressedBytes, CorrRepartitionDone, true},
	}
	for _, c := range cases {
		t.Run(c.mode+"/"+gib(c.unc), func(t *testing.T) {
			f := newFakeCH()
			f.unc["corr_objects"] = c.unc
			cfg := testCfg()
			cfg.Mode = c.mode
			out, _ := runOne(t, f, cfg)
			if out.Status != c.want {
				t.Fatalf("status = %q (%s), want %q", out.Status, out.Detail, c.want)
			}
			if c.touches {
				return
			}
			for _, forbidden := range []string{"CREATE TABLE", "INSERT INTO", "EXCHANGE TABLES",
				"DROP", "ALTER TABLE"} {
				if f.sawAny(forbidden) {
					t.Errorf("mode %q ran %q on a table it was not supposed to touch", c.mode, forbidden)
				}
			}
			if len(f.long) != 0 {
				t.Errorf("mode %q issued %d copies", c.mode, len(f.long))
			}
		})
	}
}

// TestCheckModeTellsTheOperatorExactlyWhatWouldHappen. A report nobody can act
// on is not a report: the line must name the table, its size, the gate and the
// mode that would migrate it.
func TestCheckModeTellsTheOperatorExactlyWhatWouldHappen(t *testing.T) {
	f := newFakeCH()
	cfg := testCfg()
	cfg.Mode = CorrRepartitionCheck
	_, logs := runOne(t, f, cfg)
	joined := strings.Join(logs, " ")
	for _, want := range []string{"CHECK netops.corr_objects", "1.0 MiB", "gate of 4.00 GiB",
		"CORR_REPARTITION=auto", "2026-08-29"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the check line does not mention %q:\n%s", want, joined)
		}
	}

	// Over the gate, the actionable command is `force`, not `auto`.
	f = newFakeCH()
	f.unc["corr_objects"] = labUncompressedBytes
	_, logs = runOne(t, f, cfg)
	joined = strings.Join(logs, " ")
	for _, want := range []string{"OVER the", "48.90 GiB", "CORR_REPARTITION=force"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the over-gate check line does not mention %q:\n%s", want, joined)
		}
	}
}

// TestBootLineNamesTheMode — the 2026-08-29 rewrite surprised an operator; the
// mode it ran under was never in the log to be seen.
func TestBootLineNamesTheMode(t *testing.T) {
	for _, mode := range []string{CorrRepartitionOff, CorrRepartitionCheck,
		CorrRepartitionAuto, CorrRepartitionForce} {
		f := newFakeCH()
		cfg := testCfg()
		cfg.Mode = mode
		var logs []string
		RunCorrRepartition(context.Background(), f, cfg, corrRetentionProfiles["production"],
			func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) })
		if len(logs) == 0 {
			t.Fatalf("mode %q logged nothing at boot", mode)
		}
		if !strings.Contains(logs[0], "mode="+mode) {
			t.Errorf("the first boot line for mode %q does not name it: %q", mode, logs[0])
		}
		if mode != CorrRepartitionOff && !strings.Contains(logs[0], "gate 4.00 GiB") {
			t.Errorf("the boot line for mode %q does not state the gate: %q", mode, logs[0])
		}
	}
}

// ── 7. the mid-copy TTL-shrink wedge (tracker 206, ultra-review #10) ─────────
//
// THE WEDGE, in one ordering. The shadow deliberately carries NO TTL while the
// copy runs (CorrShadowTTLStmt), so the source can lose rows the shadow already
// holds. Verification used to compare WHOLE-TABLE counts: source 25, shadow 35
// is a delta, a delta means "the engine is still writing", and the answer to
// that is "copy more" — which can never close a gap made of rows that no longer
// exist. After CatchUpPasses the run aborted errSourceUnstable, and because the
// shadow is CREATE IF NOT EXISTS and reused on every boot, the orphaned excess
// persisted and every later auto/force attempt re-wedged on it.
//
// TestTTLShrinkMidCopyReconcilesInsteadOfWedging is the REGRESSION PIN: it fails
// on the pre-change code (status "aborted-source-still-writing") and passes only
// because verification is now bounded by the source-visible partition set and
// each pass reconciles orphans away first.

// seedShadow gives the fake a pre-existing shadow table with the source's
// columns and the daily key — the CREATE IF NOT EXISTS state a previous boot
// leaves behind.
func seedShadow(f *fakeCH, rows map[string]int64) {
	f.rows["corr_objects__daily"] = rows
	f.cols["corr_objects__daily"] = append([]string(nil), f.cols["corr_objects"]...)
	f.keys["corr_objects__daily"] = CorrDailyPartitionExpr("created_at")
}

// runAll drives the whole RunCorrRepartition entrypoint (not just migrateOne),
// which is where the CORR_REPARTITION_RESET_SHADOW path lives.
func runAll(f *fakeCH, cfg CorrRepartitionSettings) ([]CorrRepartitionOutcome, []string) {
	var logs []string
	logf := func(format string, args ...any) {
		logs = append(logs, strings.Join(strings.Fields(fmt.Sprintf(format, args...)), " "))
	}
	out := RunCorrRepartition(context.Background(), f, cfg,
		corrRetentionProfiles["production"], logf)
	return out, logs
}

// TestTTLShrinkMidCopyReconcilesInsteadOfWedging — (i). The source's TTL expires
// a WHOLE DAY the instant that day lands in the shadow. Pass 1 therefore ends
// with a shadow partition the source no longer has; pass 2 must recognise it as
// an ORPHAN, drop it, and converge. Under the old whole-table comparison this
// run aborted errSourceUnstable, and the next boot did it again.
func TestTTLShrinkMidCopyReconcilesInsteadOfWedging(t *testing.T) {
	f := newFakeCH() // acme|20260801: 10, acme|20260802: 20, globex|20260802: 5
	expired := false
	f.onCopy = func(f *fakeCH, key string) {
		// The moment 20260801 is copied, the source's TTL drops the day. The
		// partition list read up-front still names it, so the rest of the pass
		// proceeds exactly as it does in production.
		if key == "acme|20260801" && !expired {
			expired = true
			delete(f.rows["corr_objects"], "acme|20260801")
		}
	}

	out, logs := runOne(t, f, testCfg())

	if out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q (%s), want %q — a source that SHRANK mid-copy wedged the "+
			"migration instead of being reconciled (tracker 206)",
			out.Status, out.Detail, CorrRepartitionDone)
	}
	if out.OrphanPartitions != 1 || out.OrphanRows != 10 {
		t.Errorf("run report says %d orphan partition(s) / %d rows, want 1 / 10 — the "+
			"reconciliation is not in the report", out.OrphanPartitions, out.OrphanRows)
	}
	if !f.sawAny("DROP PARTITION ('acme', 20260801)") {
		t.Error("the expired day was never dropped from the shadow")
	}
	// The migrated table holds exactly what the source still had: 20 + 5.
	if got := f.total("corr_objects"); got != 25 {
		t.Errorf("live table holds %d rows after the swap, want 25 (the expired day must "+
			"not be resurrected by the migration)", got)
	}
	if _, ok := f.rows["corr_objects__premigration"]; !ok {
		t.Error("the pre-migration table was not retained")
	}
	joined := strings.Join(logs, " ")
	for _, want := range []string{
		"ORPHAN shadow partition (acme, 20260801) held 10 rows",
		"the source no longer has",
		"copy verified against the source's own partitions",
		"2 partitions",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the reconciliation is not legible to an operator (missing %q):\n%s",
				want, joined)
		}
	}
}

// TestSourceShrinksWithinADayAndTheDayIsRedone — (ii). Rows are deleted INSIDE a
// day, so the partition still exists in the source: this is not an orphan, it is
// a shadow partition that no longer matches, and the EXISTING partial-redo path
// (drop the day, copy it again) must close it.
func TestSourceShrinksWithinADayAndTheDayIsRedone(t *testing.T) {
	f := newFakeCH()
	shrunk := false
	f.onCopy = func(f *fakeCH, key string) {
		if key == "acme|20260802" && !shrunk {
			shrunk = true
			f.rows["corr_objects"][key] = 12 // 20 -> 12 while the copy ran
		}
	}

	out, logs := runOne(t, f, testCfg())

	if out.Status != CorrRepartitionDone {
		t.Fatalf("status = %q (%s), want %q", out.Status, out.Detail, CorrRepartitionDone)
	}
	if out.OrphanPartitions != 0 {
		t.Errorf("a partition that still EXISTS in the source was treated as an orphan "+
			"(%d dropped) — orphan handling must be bounded to partitions the source lost",
			out.OrphanPartitions)
	}
	if !f.sawAny("DROP PARTITION ('acme', 20260802)") {
		t.Error("the stale day was appended to instead of being redone")
	}
	if got := f.total("corr_objects"); got != 27 {
		t.Errorf("live table holds %d rows, want 27 (10 + 12 + 5)", got)
	}
	if !strings.Contains(strings.Join(logs, " "), "dropped and redone") {
		t.Error("the redo of the shrunken day is not in the log")
	}
}

// TestUnstableAbortNamesThePerPartitionDeltas — (iii). A source that is written
// on EVERY pass still aborts, but the abort now has to say WHICH partitions
// differ and by how much: "5 rows short" reads identically whether the engine is
// writing, a day expired, or a copy silently failed, and those are three
// different operator actions.
func TestUnstableAbortNamesThePerPartitionDeltas(t *testing.T) {
	f := newFakeCH()
	f.growBy, f.growKey = 3, "acme|20260802"

	out, logs := runOne(t, f, testCfg())

	if out.Status != CorrRepartitionUnstable {
		t.Fatalf("status = %q (%s), want %q", out.Status, out.Detail, CorrRepartitionUnstable)
	}
	for _, want := range []string{"partition(s) still differ", "(acme, 20260802) source ",
		" shadow ", "whole-table context"} {
		if !strings.Contains(out.Detail, want) {
			t.Errorf("the abort detail does not name %q — an operator cannot tell "+
				"'still being written' from anything else:\n%s", want, out.Detail)
		}
	}
	// The shadow is KEPT: reconciliation makes reuse safe, and a large copy's
	// progress is worth hours.
	if _, ok := f.rows["corr_objects__daily"]; !ok {
		t.Error("the partial copy was discarded — a multi-hour copy's progress is lost " +
			"and the next run starts from empty")
	}
	if f.sawAny("EXCHANGE TABLES") {
		t.Error("a table that never converged was swapped in")
	}
	joined := strings.Join(logs, " ")
	for _, want := range []string{"ABORTED netops.corr_objects", "is KEPT and is resumable",
		"CORR_REPARTITION_RESET_SHADOW=true"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the abort log does not mention %q:\n%s", want, joined)
		}
	}
}

// TestOrphanDropThatLeavesRowsIsRefused — (iv). Same refusal semantics as the
// partial-redo guard: a shadow partition that still holds rows after DROP
// PARTITION means something is writing into it (an orphaned copy from an earlier
// attempt is exactly that shape), and continuing would race a live writer.
func TestOrphanDropThatLeavesRowsIsRefused(t *testing.T) {
	f := newFakeCH()
	seedShadow(f, map[string]int64{"acme|20260731": 7}) // a day the source no longer has
	f.dropLeaves = 7                                    // the writer refills it through our DROP

	out, _ := runOne(t, f, testCfg())

	if out.Status != CorrRepartitionFailed {
		t.Fatalf("status = %q (%s), want %q", out.Status, out.Detail, CorrRepartitionFailed)
	}
	for _, want := range []string{"orphan partition (acme, 20260731)", "still holds 7 rows",
		"still writing to it", "refusing to reconcile against a live writer"} {
		if !strings.Contains(out.Detail, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, out.Detail)
		}
	}
	if len(f.long) != 0 {
		t.Errorf("%d copies ran while a live writer held the shadow", len(f.long))
	}
	if f.sawAny("EXCHANGE TABLES") {
		t.Error("the table was swapped despite the refusal")
	}
}

// TestResetShadowDropsShadowsFirstInForceMode — (v), the mutating half.
// CORR_REPARTITION_RESET_SHADOW is the operator's deliberate "throw the partial
// copy away", so every shadow must be dropped BEFORE anything is created.
func TestResetShadowDropsShadowsFirstInForceMode(t *testing.T) {
	f := newFakeCH()
	seedShadow(f, map[string]int64{"acme|20260801": 4}) // a partial copy to discard
	cfg := testCfg()
	cfg.Mode = CorrRepartitionForce
	cfg.ResetShadow = true

	out, logs := runAll(f, cfg)

	if out[0].Status != CorrRepartitionDone {
		t.Fatalf("corr_objects status = %q (%s)", out[0].Status, out[0].Detail)
	}
	// Every corr_* shadow, not just the first table's.
	for _, tbl := range corrRepartitionTables() {
		if !f.sawAny(CorrDropShadowStmt(tbl)) {
			t.Errorf("the reset did not drop netops.%s%s", tbl.Name, corrRepartitionShadowSuffix)
		}
	}
	dropAt, createAt := -1, -1
	for i, s := range f.stmts {
		if dropAt < 0 && s == CorrDropShadowStmt(corrRepartitionTables()[0]) {
			dropAt = i
		}
		if createAt < 0 && strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS netops.corr_objects__daily") {
			createAt = i
		}
	}
	if dropAt < 0 || createAt < 0 || dropAt > createAt {
		t.Errorf("the shadow was dropped at %d but created at %d — a reset must precede "+
			"the run, not interrupt it", dropAt, createAt)
	}
	// The discarded partial rows must not survive into the migrated table.
	if got := f.total("corr_objects"); got != 35 {
		t.Errorf("live table holds %d rows, want 35 — the discarded partial copy leaked "+
			"into the swap", got)
	}
	joined := strings.Join(logs, " ")
	for _, want := range []string{"CORR_REPARTITION_RESET_SHADOW=true", "DISCARDED",
		"RESET — dropped netops.corr_objects__daily"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the reset is not legible to an operator (missing %q):\n%s", want, joined)
		}
	}
}

// TestResetShadowIsIgnoredInCheckMode — (v), the load-bearing half. `check` is
// the default mode and its contract is that it mutates NOTHING. A reset knob is
// not an exception to that; it must be refused, in the log, with no DDL.
func TestResetShadowIsIgnoredInCheckMode(t *testing.T) {
	f := newFakeCH()
	seedShadow(f, map[string]int64{"acme|20260801": 4})
	cfg := testCfg()
	cfg.Mode = CorrRepartitionCheck
	cfg.ResetShadow = true

	_, logs := runAll(f, cfg)

	for _, forbidden := range []string{"DROP TABLE", "DROP PARTITION", "CREATE TABLE",
		"INSERT INTO", "EXCHANGE TABLES", "ALTER TABLE"} {
		if f.sawAny(forbidden) {
			t.Errorf("check mode ran %q — CORR_REPARTITION_RESET_SHADOW must never make "+
				"the report-only mode mutate ClickHouse", forbidden)
		}
	}
	if got := f.rows["corr_objects__daily"]["acme|20260801"]; got != 4 {
		t.Errorf("check mode changed the shadow (partition now %d rows, was 4)", got)
	}
	joined := strings.Join(logs, " ")
	for _, want := range []string{"CORR_REPARTITION_RESET_SHADOW=true is IGNORED in mode=check",
		"CORR_REPARTITION=auto"} {
		if !strings.Contains(joined, want) {
			t.Errorf("check mode did not SAY it was ignoring the reset (missing %q):\n%s",
				want, joined)
		}
	}
}

// TestResetShadowIsOptInFromTheEnvironment — the knob defaults to false, because
// the shadow is normally the valuable thing: a resumable, partially finished copy
// of a table that can take hours.
func TestResetShadowIsOptInFromTheEnvironment(t *testing.T) {
	t.Setenv("CORR_REPARTITION_RESET_SHADOW", "")
	if CorrRepartitionConfig(func(string, ...any) {}).ResetShadow {
		t.Error("ResetShadow must default to false — an unset knob must never discard a " +
			"multi-hour copy")
	}
	for _, v := range []string{"true", "TRUE", " True "} {
		t.Setenv("CORR_REPARTITION_RESET_SHADOW", v)
		if !CorrRepartitionConfig(func(string, ...any) {}).ResetShadow {
			t.Errorf("CORR_REPARTITION_RESET_SHADOW=%q did not enable the reset", v)
		}
	}
	for _, v := range []string{"false", "yes", "1", "please"} {
		t.Setenv("CORR_REPARTITION_RESET_SHADOW", v)
		if CorrRepartitionConfig(func(string, ...any) {}).ResetShadow {
			t.Errorf("CORR_REPARTITION_RESET_SHADOW=%q enabled a destructive reset — only "+
				"an explicit 'true' may", v)
		}
	}
}

// TestShadowPartitionKeysSQLIsBytePinned — (vi). The two enumerations are
// compared as SETS, so they must be the same shape over two tables: same
// projection, same aliases, same GROUP BY / ORDER BY, same cross-tenant scope.
// Byte-pinned like the other builders, because a drift between them would turn
// the reconciliation into a silent no-op (nothing ever looks like an orphan) or
// a silent data-loss (everything does).
func TestShadowPartitionKeysSQLIsBytePinned(t *testing.T) {
	tbl := corrRepartitionTables()[0]

	const wantShadow = "SELECT tenant_id AS t, toYYYYMMDD(created_at) AS d, count() AS n " +
		"FROM netops.corr_objects__daily GROUP BY t, d ORDER BY d, t " +
		"SETTINGS tenant_scope = '__all__' FORMAT JSON"
	if got := CorrShadowPartitionKeysSQL(tbl); got != wantShadow {
		t.Errorf("CorrShadowPartitionKeysSQL =\n%q\nwant\n%q", got, wantShadow)
	}
	// Identical to the source enumeration modulo the table name and NOTHING else.
	src := CorrPartitionKeysSQL(tbl)
	if got := strings.Replace(CorrShadowPartitionKeysSQL(tbl),
		"netops.corr_objects__daily", "netops.corr_objects", 1); got != src {
		t.Errorf("the shadow enumeration differs from the source's by more than the table "+
			"name:\nshadow: %s\nsource: %s", got, src)
	}
	// §3a rule 4: it READS a corr table, so it carries the cross-tenant scope.
	if !strings.Contains(CorrShadowPartitionKeysSQL(tbl), "tenant_scope = '__all__'") {
		t.Error("the shadow enumeration would run under a scoped row policy and see zero " +
			"partitions — every shadow partition would then look like a non-orphan")
	}
	const wantDrop = "DROP TABLE IF EXISTS netops.corr_objects__daily"
	if got := CorrDropShadowStmt(tbl); got != wantDrop {
		t.Errorf("CorrDropShadowStmt = %q, want %q", got, wantDrop)
	}
}

// TestDeltaSummaryRanksAndTruncates — the abort message has to stay readable in
// a boot log while still being exact about HOW MANY partitions differ.
func TestDeltaSummaryRanksAndTruncates(t *testing.T) {
	if got := deltaSummary(nil); got != "no partition differs" {
		t.Errorf("deltaSummary(nil) = %q", got)
	}
	var deltas []corrPartDelta
	for i := 0; i < corrUnstableTopParts+3; i++ {
		deltas = append(deltas, corrPartDelta{
			corrPart: corrPart{tenant: "t", day: int64(20260801 + i)},
			src:      int64(i), dst: 0,
		})
	}
	sortDeltas(deltas)
	got := deltaSummary(deltas)
	if !strings.HasPrefix(got, fmt.Sprintf("%d partition(s) still differ", len(deltas))) {
		t.Errorf("the summary does not state the exact count: %s", got)
	}
	if !strings.Contains(got, "(+3 more)") {
		t.Errorf("the summary does not say what it truncated: %s", got)
	}
	// Largest gap first, so the truncation keeps the partitions that matter.
	if !strings.Contains(got, fmt.Sprintf("(t, %d) source %d shadow 0",
		20260801+len(deltas)-1, len(deltas)-1)) {
		t.Errorf("the largest delta is not named first: %s", got)
	}
	if strings.Contains(got, "(t, 20260801) source 0") {
		t.Errorf("a zero-gap partition displaced a real one in the top-N: %s", got)
	}
}
