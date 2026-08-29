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
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
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
	if cfg.Mode != CorrRepartitionAuto {
		t.Errorf("default mode = %q, want %q", cfg.Mode, CorrRepartitionAuto)
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
}

func TestRepartitionConfigRejectsGarbageWithoutWidening(t *testing.T) {
	t.Setenv("CORR_REPARTITION", "yes-please")
	t.Setenv("CORR_REPARTITION_MAX_GIB", "-3")
	t.Setenv("CORR_REPARTITION_BATCH_ROWS", "abc")
	t.Setenv("CORR_REPARTITION_CATCHUP_PASSES", "0")
	var logged []string
	cfg := CorrRepartitionConfig(func(f string, a ...any) { logged = append(logged, f) })
	if cfg.Mode != CorrRepartitionAuto {
		t.Errorf("an unknown mode must fall back to auto, got %q", cfg.Mode)
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
	growBy  int64  // rows appended to the source after each full copy pass
	growKey string // which (tenant|day) grows
	grown   int
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
	one := strings.Join(strings.Fields(sql), " ")
	switch {
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
			return nil
		}
		f.rows[m[1]][key] += src
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
	return nil
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
		m := reTotal.FindStringSubmatch(one)
		// Simulate the correlation engine writing THROUGH the copy: the SOURCE
		// grows again every time the migration re-reads it to verify, so the
		// shadow can never catch up and the swap must be refused.
		if f.growBy > 0 && !strings.HasSuffix(m[1], corrRepartitionShadowSuffix) {
			f.grown++
			f.rows[m[1]][f.growKey] += f.growBy
		}
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

func testCfg() CorrRepartitionSettings {
	return CorrRepartitionSettings{
		Mode: CorrRepartitionAuto, MaxUncompressedBytes: 4 << 30,
		BatchRows: 500000, CatchUpPasses: 3,
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
