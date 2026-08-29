package chschema

// corr_repartition.go — the LIVE-deployment half of the P2 storage-shape fix
// (docs/scale/P2_STEP5_2P5K_VERDICT_2026-08-29.md §3, P2_CLICKHOUSE_MEMFLAT_
// 2026-08-29.md "structural fix").
//
// WHAT WAS MEASURED
//
//	netops.corr_objects .......... 1,958,952 rows in ONE partition
//	                               ('global', 202608), 11 active parts,
//	                               3.51 GiB on disk / 48.9 GiB uncompressed
//	`hypotheses` ................. 46.01 of those 48.9 GiB (94 %), LZ4 13.77x
//	worst accumulated part ....... 1.86 GiB at merge LEVEL 1,568
//	merge write amplification .... ~241x (1.40 GiB in -> 337.6 GiB merged)
//
// Two structural causes, both fixed in corr_schema.go / init.sql:
//
//  1. the blob was LZ4. Replaying 3,000 live blobs through clickhouse-local:
//     LZ4 13.94x · ZSTD(1) 64.59x · ZSTD(3) 89.70x · ZSTD(6) 104.41x. ZSTD(3)
//     is 6.4x better than LZ4 at the knee of the CPU curve. That change is an
//     `ALTER ... MODIFY COLUMN ... CODEC`, which is METADATA-ONLY (verified on
//     24.8: zero rows in system.mutations, existing parts byte-identical) and
//     therefore lives in the ordinary boot converge list.
//
//  2. the tables were partitioned by MONTH. A month-long partition is never
//     "finished", so its parts stay merge candidates for a month and
//     min_age_to_force_merge_on_partition_only can never fire; and because the
//     TTL is keyed on `created_at` while the partition was keyed on
//     `window_start`, ttl_only_drop_parts = 1 could only drop a part once its
//     NEWEST row expired — retention overshoot of up to a whole month.
//     Daily partitions on the TTL's own column fix both.
//
// A partition-key change is NOT an ALTER. It requires a new table, a copy, and
// a swap — a full rewrite of the table's bytes. This file owns that rewrite and
// treats it as what it is: a bounded, gated, resumable, verified data migration
// that must never run by surprise on a live 48 GiB table at API boot.
//
// SAFETY CONTRACT (each property has a test in corr_repartition_test.go)
//
//   - GATED. A table whose uncompressed size exceeds CORR_REPARTITION_MAX_GIB
//     (default 4 GiB) is SKIPPED with a loud, actionable log line naming the
//     table, its size, the gate, and the exact env to run it deliberately.
//     The lab's corr_objects (48.9 GiB) is therefore never silently rewritten.
//   - DELIBERATE. CORR_REPARTITION=force ignores the size gate;
//     CORR_REPARTITION=off does nothing at all.
//   - BOUNDED. The copy runs one DESTINATION day-partition at a time, and a
//     day holding more than CORR_REPARTITION_BATCH_ROWS rows is copied in
//     hourly sub-batches. No statement ever reads the whole table.
//   - RESUMABLE + IDEMPOTENT. The resume unit is one destination partition: a
//     partition whose row count already matches the source is skipped, and a
//     PARTIALLY copied one is DROPped and redone. A crash at any point leaves
//     the live table untouched and the next boot continues.
//   - VERIFIED. The swap happens only when the shadow table's total row count
//     equals the source's, re-read after the copy. If the source is still
//     growing (the correlation engine is writing), the migration retries the
//     delta up to CORR_REPARTITION_CATCHUP_PASSES times and then ABORTS
//     without swapping rather than silently losing the rows written during the
//     copy. Nothing is destroyed: the pre-migration table is kept as
//     netops.<table>__premigration until an operator drops it (or
//     CORR_REPARTITION_DROP_OLD=true).
//   - TENANT-ISOLATED (CLAUDE.md §3a rule 4). The shadow table gets its STRICT
//     row policy BEFORE the first row is copied into it, so no window exists in
//     which correlation history is queryable without a tenant policy; the
//     policy is re-emitted on the live name after the swap and on the retained
//     pre-migration table. Every statement that READS a corr table carries an
//     explicit `SETTINGS tenant_scope = '__all__'` — a copy that ran under a
//     scoped policy would silently copy ZERO rows and then "verify" against a
//     count read under the same policy.
//
// The swap itself is `EXCHANGE TABLES a AND b`, which is atomic on the Atomic
// database engine netops uses. Row policies and the corr_objects_latest view
// bind to the table NAME, so both keep guarding/reading the right table across
// the swap with no re-creation window.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ── the injected ClickHouse seam ────────────────────────────────────────────

// CHExec is the ClickHouse capability this migration needs, expressed as an
// interface so the package stays free of transport and env (CLAUDE.md §2/§5:
// every external dependency is injected). src/backend/clickhouse_repartition.go
// supplies the real implementation over the chhttp seam.
type CHExec interface {
	// Exec runs one statement that returns no rows.
	Exec(ctx context.Context, sql string) error
	// Query runs one SELECT and returns its rows as decoded JSON objects.
	Query(ctx context.Context, sql string) ([]map[string]any, error)
}

// ── the tables this migration owns ──────────────────────────────────────────

// corrRepartitionTable is one table's migration descriptor. TimeCol is BOTH the
// new partition column and the column the table's TTL is keyed on — that
// identity is the whole point (see the header), and
// TestPartitionColumnIsTheTTLColumn asserts it against corr_retention.go.
type corrRepartitionTable struct {
	Name     string // bare table name under netops.
	TimeCol  string // TTL column == new partition column
	OrderBy  string // must match CorrSchemaDDL's ORDER BY exactly
	Settings string // per-table SETTINGS for the shadow table
	// ttlDays resolves this table's hot horizon from the retention profile.
	// 0 means "no TTL" (explicit keep-forever contract).
	ttlDays func(corrRetentionDays) int
}

// corrRepartitionTables is every corr_* table that moves from a monthly to a
// daily partition key, in migration order (corr_objects first — it is the one
// that carries 94 % of the bytes and all of the merge cost).
//
// DELIBERATELY ABSENT:
//   - corr_signals — already toYYYYMMDD(ts).
//   - corr_current — partitioned by tenant_id ALONE and it must stay that way:
//     it is a ReplacingMergeTree whose dedup key (tenant_id, correlation_id)
//     may not span partitions or FINAL cannot collapse a re-persist. Its
//     retention is a row-level `DELETE WHERE state != 'open'` TTL, not a part
//     drop, so it gains nothing from finer partitions either.
func corrRepartitionTables() []corrRepartitionTable {
	const objSettings = "index_granularity = 8192, non_replicated_deduplication_window = 1000, " +
		"ttl_only_drop_parts = 1"
	history := func(d corrRetentionDays) int { return d.History }
	archive := func(d corrRetentionDays) int { return d.Archive }
	fixed := func(n int) func(corrRetentionDays) int { return func(corrRetentionDays) int { return n } }
	return []corrRepartitionTable{
		{
			Name: "corr_objects", TimeCol: "created_at",
			OrderBy:  "(tenant_id, correlation_id, version)",
			Settings: objSettings, ttlDays: history,
		},
		{
			Name: "corr_edges", TimeCol: "created_at",
			OrderBy:  "(tenant_id, correlation_id, version, from_node, to_node)",
			Settings: objSettings, ttlDays: history,
		},
		{
			Name: "corr_evidence", TimeCol: "created_at",
			OrderBy:  "(tenant_id, correlation_id, version, subject_kind, subject_id)",
			Settings: objSettings, ttlDays: history,
		},
		{
			Name: "corr_signals_archive", TimeCol: "ts",
			OrderBy:  "(tenant_id, ts, signal_id)",
			Settings: "index_granularity = 8192, ttl_only_drop_parts = 1", ttlDays: archive,
		},
		{
			Name: "corr_path_edges", TimeCol: "created_at",
			OrderBy:  "(tenant_id, correlation_id, version, from_node, to_node)",
			Settings: "index_granularity = 8192, ttl_only_drop_parts = 1", ttlDays: fixed(90),
		},
		{
			Name: "corr_tenant_write_amp", TimeCol: "window_start",
			OrderBy:  "(tenant_id, window_start)",
			Settings: "index_granularity = 8192, ttl_only_drop_parts = 1", ttlDays: fixed(30),
		},
	}
}

// CorrDailyPartitionExpr is the partition key every corr_* history table must
// carry. Exported so the schema guard test and the Python contract test assert
// against ONE definition instead of re-spelling it.
func CorrDailyPartitionExpr(timeCol string) string {
	return "(tenant_id, toYYYYMMDD(" + timeCol + "))"
}

// CorrDailyPartitionKeys maps table name -> the expected partition key, for
// callers that need to check the whole family (the schema guard test).
func CorrDailyPartitionKeys() map[string]string {
	out := map[string]string{
		// Already daily since the freeze; listed so the guard is complete.
		"corr_signals": CorrDailyPartitionExpr("ts"),
		// The documented exception (see corrRepartitionTables).
		"corr_current": "(tenant_id)",
	}
	for _, t := range corrRepartitionTables() {
		out[t.Name] = CorrDailyPartitionExpr(t.TimeCol)
	}
	return out
}

// ── configuration ───────────────────────────────────────────────────────────

// Repartition modes.
const (
	CorrRepartitionOff   = "off"   // never run
	CorrRepartitionAuto  = "auto"  // run below the size gate, skip loudly above it
	CorrRepartitionForce = "force" // run regardless of size (operator's decision)
)

// CorrRepartitionSettings is the resolved, env-free configuration.
type CorrRepartitionSettings struct {
	Mode string
	// MaxUncompressedBytes is the per-table size gate in AUTO mode. Measured in
	// UNCOMPRESSED bytes because that — not bytes on disk — is what the rewrite
	// has to decompress, re-serialize and recompress.
	MaxUncompressedBytes int64
	// BatchRows is the destination-partition row count above which the copy is
	// split into hourly sub-batches.
	BatchRows int64
	// CatchUpPasses bounds the "source is still being written to" retry loop.
	CatchUpPasses int
	// DropOld drops netops.<table>__premigration immediately after a verified
	// swap. Default false: keeping the pre-migration table is the rollback.
	DropOld bool
}

// Defaults. corrRepartitionDefaultMaxGiB is deliberately BELOW the lab's
// measured corr_objects (48.9 GiB uncompressed) so that table is skipped with a
// log line rather than rewritten at boot, and comfortably ABOVE a fresh or
// small install, which migrates itself in seconds.
const (
	corrRepartitionDefaultMaxGiB    = 4
	corrRepartitionDefaultBatchRows = 500_000
	corrRepartitionDefaultCatchUp   = 3
	corrRepartitionShadowSuffix     = "__daily"
	corrRepartitionBackupSuffix     = "__premigration"
)

// CorrRepartitionConfig resolves the migration knobs from the environment. An
// unparseable value falls back to the default WITH a log line — never to a
// larger blast radius.
func CorrRepartitionConfig(logf func(string, ...any)) CorrRepartitionSettings {
	cfg := CorrRepartitionSettings{
		Mode:                 CorrRepartitionAuto,
		MaxUncompressedBytes: corrRepartitionDefaultMaxGiB * 1024 * 1024 * 1024,
		BatchRows:            corrRepartitionDefaultBatchRows,
		CatchUpPasses:        corrRepartitionDefaultCatchUp,
	}
	switch mode := strings.ToLower(strings.TrimSpace(envOr("CORR_REPARTITION", CorrRepartitionAuto))); mode {
	case CorrRepartitionOff, CorrRepartitionAuto, CorrRepartitionForce:
		cfg.Mode = mode
	default:
		logf("corr-repartition: unknown CORR_REPARTITION=%q, using %q", mode, CorrRepartitionAuto)
	}
	if raw := envOr("CORR_REPARTITION_MAX_GIB", ""); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			logf("corr-repartition: invalid CORR_REPARTITION_MAX_GIB=%q, using %d",
				raw, corrRepartitionDefaultMaxGiB)
		} else {
			cfg.MaxUncompressedBytes = int64(n) * 1024 * 1024 * 1024
		}
	}
	if raw := envOr("CORR_REPARTITION_BATCH_ROWS", ""); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			logf("corr-repartition: invalid CORR_REPARTITION_BATCH_ROWS=%q, using %d",
				raw, corrRepartitionDefaultBatchRows)
		} else {
			cfg.BatchRows = n
		}
	}
	if raw := envOr("CORR_REPARTITION_CATCHUP_PASSES", ""); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			logf("corr-repartition: invalid CORR_REPARTITION_CATCHUP_PASSES=%q, using %d",
				raw, corrRepartitionDefaultCatchUp)
		} else {
			cfg.CatchUpPasses = n
		}
	}
	cfg.DropOld = strings.EqualFold(strings.TrimSpace(envOr("CORR_REPARTITION_DROP_OLD", "")), "true")
	return cfg
}

// ── SQL builders (pure — every one of these is asserted by a unit test) ─────

// corrScope is appended to EVERY statement that reads a corr_* table. The
// STRICT row policies filter SELECT on `tenant_scope`; a migration that read
// under a scoped (or unset) value would copy zero rows and then verify zero
// against zero. See CLAUDE.md §3a rule 4.
const corrScope = " SETTINGS tenant_scope = '__all__'"

// chQuote renders a string literal safe for ClickHouse SQL. Values here come
// from ClickHouse itself (tenant ids read out of the table), but a tenant id is
// tenant-controlled data and gets quoted like any external input (§3).
func chQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

// CorrPartitionKeySQL reads a table's CURRENT partition key from system.tables.
// Empty result = the table does not exist (a fresh install before init.sql, or
// a deployment that never enabled correlation).
func CorrPartitionKeySQL(table string) string {
	return "SELECT partition_key AS k FROM system.tables WHERE database = 'netops' AND name = " +
		chQuote(table) + " FORMAT JSON"
}

// CorrTableSizeSQL reads the active-part footprint used by the size gate.
func CorrTableSizeSQL(table string) string {
	return "SELECT sum(rows) AS n, sum(data_uncompressed_bytes) AS unc, " +
		"sum(data_compressed_bytes) AS cmp FROM system.parts " +
		"WHERE database = 'netops' AND table = " + chQuote(table) + " AND active FORMAT JSON"
}

// CorrColumnsSQL lists a table's columns in position order — used to detect a
// shadow table left behind by an earlier attempt whose schema has since drifted
// (a converge ADD COLUMN between boots). `INSERT ... SELECT *` is positional, so
// a drifted shadow must be dropped, not appended to.
func CorrColumnsSQL(table string) string {
	return "SELECT name FROM system.columns WHERE database = 'netops' AND table = " +
		chQuote(table) + " ORDER BY position FORMAT JSON"
}

// CorrShadowCreateStmts builds the shadow table: same columns, codecs, skip
// indices and constraints as the live table (CREATE ... AS copies all four,
// verified on 24.8), a DAILY partition key, and its STRICT tenant row policy
// before any data lands in it.
//
// TTL is deliberately NOT set here — see CorrShadowTTLStmt.
func CorrShadowCreateStmts(t corrRepartitionTable) []string {
	shadow := t.Name + corrRepartitionShadowSuffix
	stmts := []string{
		"CREATE TABLE IF NOT EXISTS netops." + shadow + " AS netops." + t.Name +
			" ENGINE = MergeTree PARTITION BY " + CorrDailyPartitionExpr(t.TimeCol) +
			" ORDER BY " + t.OrderBy +
			" SETTINGS " + t.Settings + ", " + corrMergeBudgetSettingsFor(t.Name),
		// §3a rule 4: the policy exists before the first row, not after.
		StrictRowPolicyDDL(shadow),
	}
	if t.Name == "corr_objects" {
		// CREATE ... AS inherits whatever codec the LIVE column has today, which
		// on a deployment that has not yet run the converge ALTER is still LZ4.
		// Restating it here makes the copy itself the one-time ZSTD(3) rewrite
		// that actually reclaims the bytes, instead of waiting for merges.
		stmts = append(stmts,
			"ALTER TABLE netops."+shadow+" MODIFY COLUMN hypotheses String CODEC(ZSTD(3))")
	}
	return stmts
}

// corrMergeBudgetSettingsFor renders the P2 merge budget for one table as a
// SETTINGS fragment, reading the SAME constants CorrMergeBudgetDDL uses so the
// shadow table can never be created outside the budget.
func corrMergeBudgetSettingsFor(table string) string {
	capBytes, ok := corrMergeBudgetTables()[table]
	if !ok {
		capBytes = corrMergeCapDefault
	}
	return "max_bytes_to_merge_at_max_space_in_pool = " + strconv.FormatInt(capBytes, 10) +
		", min_age_to_force_merge_seconds = " + strconv.Itoa(corrMergeForceAgeSeconds) +
		", min_age_to_force_merge_on_partition_only = 1"
}

// CorrShadowTTLStmt renders the retention TTL for the shadow table, or "" when
// the tier is configured keep-forever.
//
// It is applied AFTER the copy has been verified and BEFORE the swap, on
// purpose: a TTL on the shadow while rows are still being copied would let
// background part drops remove expired history mid-copy and make the row-count
// verification disagree with itself. materialize_ttl_after_modify = 0 keeps it
// metadata-only, exactly as corr_retention.go does.
func CorrShadowTTLStmt(t corrRepartitionTable, d corrRetentionDays) string {
	days := t.ttlDays(d)
	if days <= 0 {
		return ""
	}
	return "ALTER TABLE netops." + t.Name + corrRepartitionShadowSuffix +
		" MODIFY TTL toDateTime(" + t.TimeCol + ") + INTERVAL " + strconv.Itoa(days) +
		" DAY SETTINGS materialize_ttl_after_modify = 0"
}

// CorrPartitionKeysSQL enumerates the DESTINATION partitions and their source
// row counts — the migration's unit of work, resume and verification.
func CorrPartitionKeysSQL(t corrRepartitionTable) string {
	return "SELECT tenant_id AS t, toYYYYMMDD(" + t.TimeCol + ") AS d, count() AS n " +
		"FROM netops." + t.Name + " GROUP BY t, d ORDER BY d, t" + corrScope + " FORMAT JSON"
}

// CorrPartitionCountSQL counts what a given table already holds for one
// destination partition. Used against both source and shadow.
func CorrPartitionCountSQL(table string, t corrRepartitionTable, tenant string, day int64) string {
	return "SELECT count() AS n FROM netops." + table +
		" WHERE tenant_id = " + chQuote(tenant) +
		" AND toYYYYMMDD(" + t.TimeCol + ") = " + strconv.FormatInt(day, 10) +
		corrScope + " FORMAT JSON"
}

// CorrDropShadowPartitionStmt discards a PARTIALLY copied destination partition
// so it can be redone cleanly. This — not an insert dedup token — is what makes
// the migration resumable: the redo unit is exactly one day of one tenant.
func CorrDropShadowPartitionStmt(t corrRepartitionTable, tenant string, day int64) string {
	return "ALTER TABLE netops." + t.Name + corrRepartitionShadowSuffix +
		" DROP PARTITION (" + chQuote(tenant) + ", " + strconv.FormatInt(day, 10) + ")"
}

// CorrCopyPartitionStmts renders the copy for one destination partition. A
// partition holding more than batchRows rows is split into 24 hourly
// sub-batches so no single statement's memory is a function of table size; the
// resume unit stays the whole day (a redo drops the day and repeats it), which
// keeps the correctness argument to one sentence.
func CorrCopyPartitionStmts(t corrRepartitionTable, tenant string, day, rows, batchRows int64) []string {
	where := "WHERE tenant_id = " + chQuote(tenant) +
		" AND toYYYYMMDD(" + t.TimeCol + ") = " + strconv.FormatInt(day, 10)
	// max_insert_block_size bounds the block the INSERT materializes; max_threads
	// = 1 keeps the copy off the cores the correlation engine is using.
	const guards = ", max_insert_block_size = 100000, max_threads = 1, max_insert_threads = 1"
	head := "INSERT INTO netops." + t.Name + corrRepartitionShadowSuffix +
		" SELECT * FROM netops." + t.Name + " "
	if rows <= batchRows {
		return []string{head + where + corrScope + guards}
	}
	stmts := make([]string, 0, 24)
	for h := 0; h < 24; h++ {
		stmts = append(stmts, head+where+
			" AND toHour("+t.TimeCol+") = "+strconv.Itoa(h)+corrScope+guards)
	}
	return stmts
}

// CorrTotalCountSQL counts a whole table (source or shadow) for the pre-swap
// verification.
func CorrTotalCountSQL(table string) string {
	return "SELECT count() AS n FROM netops." + table + corrScope + " FORMAT JSON"
}

// CorrSwapStmts renders the atomic swap and everything that must be true after
// it. EXCHANGE is atomic on the Atomic database engine `netops` uses, so there
// is no window in which the name resolves to nothing.
//
// Row policies and netops.corr_objects_latest bind to the table NAME, so both
// keep guarding/reading the right data across the swap; the policy is re-emitted
// anyway (CREATE OR REPLACE, idempotent) because a §3a backstop that depends on
// an implementation detail of RENAME is not a backstop.
func CorrSwapStmts(t corrRepartitionTable) []string {
	shadow := t.Name + corrRepartitionShadowSuffix
	backup := t.Name + corrRepartitionBackupSuffix
	return []string{
		"EXCHANGE TABLES netops." + t.Name + " AND netops." + shadow,
		"RENAME TABLE netops." + shadow + " TO netops." + backup,
		StrictRowPolicyDDL(t.Name),
		StrictRowPolicyDDL(backup),
	}
}

// CorrDropBackupStmt drops the retained pre-migration table.
func CorrDropBackupStmt(t corrRepartitionTable) string {
	return "DROP TABLE IF EXISTS netops." + t.Name + corrRepartitionBackupSuffix
}

// CorrTableExistsSQL probes for a table by name.
func CorrTableExistsSQL(table string) string {
	return "SELECT count() AS n FROM system.tables WHERE database = 'netops' AND name = " +
		chQuote(table) + " FORMAT JSON"
}

// ── result reporting ────────────────────────────────────────────────────────

// CorrRepartitionOutcome is what happened to ONE table.
type CorrRepartitionOutcome struct {
	Table   string
	Status  string // see the CorrRepartition* status constants
	Rows    int64
	Bytes   int64 // uncompressed
	Detail  string
}

// Per-table outcomes.
const (
	CorrRepartitionDone       = "migrated"
	CorrRepartitionAlready    = "already-daily"
	CorrRepartitionAbsent     = "absent"
	CorrRepartitionSkippedBig = "skipped-too-big"
	CorrRepartitionSkippedOff = "skipped-disabled"
	CorrRepartitionFailed     = "failed"
	CorrRepartitionUnstable   = "aborted-source-still-writing"
	CorrRepartitionBlocked    = "blocked-backup-exists"
)

// errSourceUnstable is returned when the source kept growing through every
// catch-up pass — the one condition under which we refuse to swap.
var errSourceUnstable = errors.New("source table is still being written to")

// ── the migration ───────────────────────────────────────────────────────────

// RunCorrRepartition migrates every corr_* history table from a monthly to a
// daily partition key. It NEVER returns an error for a table it deliberately
// skipped; the outcome slice is the report.
//
// The caller supplies the ClickHouse seam, the resolved retention (so the
// shadow carries the same TTL the live table would get on the next boot) and a
// logger. Nothing here reads the environment except through
// CorrRepartitionConfig, which the caller passes in.
func RunCorrRepartition(ctx context.Context, ex CHExec, cfg CorrRepartitionSettings,
	ret corrRetentionDays, logf func(string, ...any)) []CorrRepartitionOutcome {

	tables := corrRepartitionTables()
	out := make([]CorrRepartitionOutcome, 0, len(tables))
	if cfg.Mode == CorrRepartitionOff {
		logf("corr-repartition: CORR_REPARTITION=off — daily partitioning not applied to live tables")
		for _, t := range tables {
			out = append(out, CorrRepartitionOutcome{Table: t.Name, Status: CorrRepartitionSkippedOff})
		}
		return out
	}
	for _, t := range tables {
		o := migrateOne(ctx, ex, cfg, ret, t, logf)
		out = append(out, o)
		if o.Status == CorrRepartitionFailed || o.Status == CorrRepartitionUnstable {
			// A failure here is data-shaped, not transient: stop rather than
			// churn the remaining tables under the same broken condition.
			logf("corr-repartition: stopping after %s (%s) — remaining tables left untouched",
				o.Table, o.Status)
			break
		}
	}
	return out
}

func migrateOne(ctx context.Context, ex CHExec, cfg CorrRepartitionSettings,
	ret corrRetentionDays, t corrRepartitionTable, logf func(string, ...any)) CorrRepartitionOutcome {

	res := CorrRepartitionOutcome{Table: t.Name}
	want := CorrDailyPartitionExpr(t.TimeCol)

	rows, err := ex.Query(ctx, CorrPartitionKeySQL(t.Name))
	if err != nil {
		res.Status, res.Detail = CorrRepartitionFailed, "read partition key: "+err.Error()
		logf("corr-repartition: %s — %s", t.Name, res.Detail)
		return res
	}
	if len(rows) == 0 {
		res.Status = CorrRepartitionAbsent
		return res
	}
	if normalizeKey(chString(rows[0]["k"])) == normalizeKey(want) {
		res.Status = CorrRepartitionAlready
		return res
	}

	// Size gate. UNCOMPRESSED bytes, because that is what the rewrite must
	// decompress, re-serialize and recompress — not what it reads off disk.
	n, unc, cmp, err := tableSize(ctx, ex, t.Name)
	if err != nil {
		res.Status, res.Detail = CorrRepartitionFailed, "read size: "+err.Error()
		logf("corr-repartition: %s — %s", t.Name, res.Detail)
		return res
	}
	res.Rows, res.Bytes = n, unc
	if cfg.Mode != CorrRepartitionForce && unc > cfg.MaxUncompressedBytes {
		res.Status = CorrRepartitionSkippedBig
		res.Detail = fmt.Sprintf("%s uncompressed > gate %s", gib(unc), gib(cfg.MaxUncompressedBytes))
		// LOUD, and actionable: what, how big, why skipped, how to run it.
		logf("corr-repartition: SKIPPED netops.%s — it is still partitioned MONTHLY "+
			"(%s) but holds %d rows / %s uncompressed (%s on disk), over the "+
			"CORR_REPARTITION_MAX_GIB gate of %s. Re-partitioning REWRITES the table, "+
			"so it is not done implicitly at boot. Run it deliberately with the "+
			"correlation engine stopped: CORR_REPARTITION=force (or raise "+
			"CORR_REPARTITION_MAX_GIB above %s) and restart the API. Until then this "+
			"table keeps monthly partitions: TTL part-drops lag the retention horizon "+
			"by up to a month and merges keep re-folding one accumulated part.",
			t.Name, chString(rows[0]["k"]), n, gib(unc), gib(cmp),
			gib(cfg.MaxUncompressedBytes), gib(unc))
		return res
	}

	// A backup from a PREVIOUS migration must be dealt with by an operator
	// before we can create another one — silently dropping retained history is
	// exactly the kind of quiet data loss this file exists to avoid.
	backup := t.Name + corrRepartitionBackupSuffix
	exists, err := tableExists(ctx, ex, backup)
	if err != nil {
		res.Status, res.Detail = CorrRepartitionFailed, "probe backup: "+err.Error()
		logf("corr-repartition: %s — %s", t.Name, res.Detail)
		return res
	}
	if exists {
		res.Status = CorrRepartitionBlocked
		res.Detail = "netops." + backup + " already exists"
		logf("corr-repartition: BLOCKED netops.%s — a previous migration's "+
			"pre-migration copy netops.%s still exists. Verify it, then "+
			"`DROP TABLE netops.%s` and restart the API.", t.Name, backup, backup)
		return res
	}

	logf("corr-repartition: netops.%s — %d rows / %s uncompressed, monthly -> %s; "+
		"copying via netops.%s%s", t.Name, n, gib(unc), want, t.Name, corrRepartitionShadowSuffix)

	if err := prepareShadow(ctx, ex, t); err != nil {
		res.Status, res.Detail = CorrRepartitionFailed, err.Error()
		logf("corr-repartition: %s — %s", t.Name, res.Detail)
		return res
	}

	copied, err := copyAllPasses(ctx, ex, cfg, t, logf)
	if err != nil {
		if errors.Is(err, errSourceUnstable) {
			res.Status, res.Detail = CorrRepartitionUnstable, err.Error()
			logf("corr-repartition: ABORTED netops.%s — %v. Nothing was swapped and "+
				"the live table is untouched; the partial copy in netops.%s%s is "+
				"resumable. Stop the correlation engine and restart the API to finish it.",
				t.Name, err, t.Name, corrRepartitionShadowSuffix)
			return res
		}
		res.Status, res.Detail = CorrRepartitionFailed, err.Error()
		logf("corr-repartition: %s — %s (live table untouched)", t.Name, res.Detail)
		return res
	}

	if ttl := CorrShadowTTLStmt(t, ret); ttl != "" {
		if err := ex.Exec(ctx, ttl); err != nil {
			res.Status, res.Detail = CorrRepartitionFailed, "shadow TTL: "+err.Error()
			logf("corr-repartition: %s — %s (live table untouched)", t.Name, res.Detail)
			return res
		}
	}

	for _, s := range CorrSwapStmts(t) {
		if err := ex.Exec(ctx, s); err != nil {
			res.Status, res.Detail = CorrRepartitionFailed, "swap: "+err.Error()
			logf("corr-repartition: %s — %s", t.Name, res.Detail)
			return res
		}
	}
	res.Status, res.Rows = CorrRepartitionDone, copied
	if cfg.DropOld {
		if err := ex.Exec(ctx, CorrDropBackupStmt(t)); err != nil {
			logf("corr-repartition: netops.%s migrated, but dropping netops.%s failed: %v",
				t.Name, backup, err)
		}
		logf("corr-repartition: netops.%s now %s — %d rows copied; pre-migration copy dropped "+
			"(CORR_REPARTITION_DROP_OLD=true)", t.Name, want, copied)
		return res
	}
	logf("corr-repartition: netops.%s now %s — %d rows copied. The pre-migration table is "+
		"KEPT as netops.%s (your rollback); drop it with `DROP TABLE netops.%s` once you are "+
		"satisfied, or set CORR_REPARTITION_DROP_OLD=true.", t.Name, want, copied, backup, backup)
	return res
}

// prepareShadow creates (or re-creates) the shadow table. A shadow left behind
// by an earlier attempt is reused ONLY if its column list still matches the
// source position-for-position — `INSERT ... SELECT *` is positional, so a
// shadow that predates a converge ADD COLUMN must be dropped, not appended to.
func prepareShadow(ctx context.Context, ex CHExec, t corrRepartitionTable) error {
	shadow := t.Name + corrRepartitionShadowSuffix
	exists, err := tableExists(ctx, ex, shadow)
	if err != nil {
		return fmt.Errorf("probe shadow: %w", err)
	}
	if exists {
		same, err := sameColumns(ctx, ex, t.Name, shadow)
		if err != nil {
			return fmt.Errorf("compare shadow columns: %w", err)
		}
		if !same {
			if err := ex.Exec(ctx, "DROP TABLE IF EXISTS netops."+shadow); err != nil {
				return fmt.Errorf("drop drifted shadow: %w", err)
			}
		}
	}
	for _, s := range CorrShadowCreateStmts(t) {
		if err := ex.Exec(ctx, s); err != nil {
			return fmt.Errorf("create shadow: %w", err)
		}
	}
	return nil
}

// copyAllPasses runs the per-partition copy, then re-reads the source and
// repeats for whatever arrived while it ran. It returns only when the two
// tables agree, or gives up after cfg.CatchUpPasses with errSourceUnstable —
// never by swapping a short copy into place.
func copyAllPasses(ctx context.Context, ex CHExec, cfg CorrRepartitionSettings,
	t corrRepartitionTable, logf func(string, ...any)) (int64, error) {

	shadow := t.Name + corrRepartitionShadowSuffix
	for pass := 1; pass <= cfg.CatchUpPasses; pass++ {
		if err := copyOnePass(ctx, ex, cfg, t, pass, logf); err != nil {
			return 0, err
		}
		src, err := totalCount(ctx, ex, t.Name)
		if err != nil {
			return 0, fmt.Errorf("verify source count: %w", err)
		}
		dst, err := totalCount(ctx, ex, shadow)
		if err != nil {
			return 0, fmt.Errorf("verify shadow count: %w", err)
		}
		if src == dst {
			logf("corr-repartition: netops.%s — copy verified, %d rows in both tables", t.Name, src)
			return src, nil
		}
		logf("corr-repartition: netops.%s — pass %d/%d left a delta of %d rows "+
			"(source %d, shadow %d); the engine is still writing, re-running the delta",
			t.Name, pass, cfg.CatchUpPasses, src-dst, src, dst)
	}
	return 0, fmt.Errorf("%w after %d catch-up passes", errSourceUnstable, cfg.CatchUpPasses)
}

// copyOnePass copies every destination partition whose shadow row count does
// not already match the source's.
func copyOnePass(ctx context.Context, ex CHExec, cfg CorrRepartitionSettings,
	t corrRepartitionTable, pass int, logf func(string, ...any)) error {

	shadow := t.Name + corrRepartitionShadowSuffix
	keys, err := ex.Query(ctx, CorrPartitionKeysSQL(t))
	if err != nil {
		return fmt.Errorf("enumerate partitions: %w", err)
	}
	done, skipped := 0, 0
	for _, k := range keys {
		tenant := chString(k["t"])
		day, err := chInt(k["d"])
		if err != nil {
			return fmt.Errorf("partition day %v: %w", k["d"], err)
		}
		want, err := chInt(k["n"])
		if err != nil {
			return fmt.Errorf("partition rows %v: %w", k["n"], err)
		}
		have, err := partitionCount(ctx, ex, shadow, t, tenant, day)
		if err != nil {
			return fmt.Errorf("count shadow partition (%s, %d): %w", tenant, day, err)
		}
		if have == want {
			skipped++
			continue
		}
		if have > 0 {
			// Partial from an interrupted run: redo the whole day cleanly.
			if err := ex.Exec(ctx, CorrDropShadowPartitionStmt(t, tenant, day)); err != nil {
				return fmt.Errorf("drop partial partition (%s, %d): %w", tenant, day, err)
			}
		}
		for _, s := range CorrCopyPartitionStmts(t, tenant, day, want, cfg.BatchRows) {
			if err := ex.Exec(ctx, s); err != nil {
				return fmt.Errorf("copy partition (%s, %d): %w", tenant, day, err)
			}
		}
		done++
		if done%25 == 0 {
			logf("corr-repartition: netops.%s pass %d — %d/%d partitions copied",
				t.Name, pass, done, len(keys))
		}
	}
	logf("corr-repartition: netops.%s pass %d — %d partitions copied, %d already complete",
		t.Name, pass, done, skipped)
	return nil
}

// ── small typed readers over the JSON result shape ──────────────────────────

func tableExists(ctx context.Context, ex CHExec, table string) (bool, error) {
	rows, err := ex.Query(ctx, CorrTableExistsSQL(table))
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	n, err := chInt(rows[0]["n"])
	return n > 0, err
}

func sameColumns(ctx context.Context, ex CHExec, a, b string) (bool, error) {
	ca, err := ex.Query(ctx, CorrColumnsSQL(a))
	if err != nil {
		return false, err
	}
	cb, err := ex.Query(ctx, CorrColumnsSQL(b))
	if err != nil {
		return false, err
	}
	if len(ca) != len(cb) || len(ca) == 0 {
		return false, nil
	}
	for i := range ca {
		if chString(ca[i]["name"]) != chString(cb[i]["name"]) {
			return false, nil
		}
	}
	return true, nil
}

func tableSize(ctx context.Context, ex CHExec, table string) (rows, unc, cmp int64, err error) {
	res, err := ex.Query(ctx, CorrTableSizeSQL(table))
	if err != nil {
		return 0, 0, 0, err
	}
	if len(res) == 0 {
		return 0, 0, 0, nil
	}
	// Every value is CHECKED, not discarded. An empty table yields NULL from
	// sum(), which chInt reads as 0 — that is a legitimate "nothing to copy".
	// An UNREADABLE value is not: swallowing it would report 0 uncompressed
	// bytes, and 0 passes the size gate, which is exactly how a 48.9 GiB table
	// would get rewritten at boot by accident.
	if rows, err = chInt(res[0]["n"]); err != nil {
		return 0, 0, 0, fmt.Errorf("rows: %w", err)
	}
	if unc, err = chInt(res[0]["unc"]); err != nil {
		return 0, 0, 0, fmt.Errorf("uncompressed bytes: %w", err)
	}
	if cmp, err = chInt(res[0]["cmp"]); err != nil {
		return 0, 0, 0, fmt.Errorf("compressed bytes: %w", err)
	}
	return rows, unc, cmp, nil
}

func totalCount(ctx context.Context, ex CHExec, table string) (int64, error) {
	rows, err := ex.Query(ctx, CorrTotalCountSQL(table))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return chInt(rows[0]["n"])
}

func partitionCount(ctx context.Context, ex CHExec, table string,
	t corrRepartitionTable, tenant string, day int64) (int64, error) {
	rows, err := ex.Query(ctx, CorrPartitionCountSQL(table, t, tenant, day))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return chInt(rows[0]["n"])
}

// chString reads a JSON value as a string without panicking on an unexpected
// type (§3: never trust the shape of an upstream response).
func chString(v any) string {
	s, _ := v.(string)
	return s
}

// chInt reads a JSON value as an integer. ClickHouse's JSON format renders
// UInt64 (count(), byte sums) as a STRING and smaller integers as numbers, so
// both forms must be accepted — a reader that handled only one would have
// silently seen every count as zero.
func chInt(v any) (int64, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case float64:
		return int64(x), nil
	case string:
		if x == "" {
			return 0, nil
		}
		return strconv.ParseInt(x, 10, 64)
	case int64:
		return x, nil
	default:
		return 0, fmt.Errorf("unreadable numeric value %T", v)
	}
}

// normalizeKey collapses whitespace so a partition key read back from
// system.tables compares equal to the one we render (ClickHouse re-prints the
// expression with its own spacing).
func normalizeKey(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, ",", ", ")), " ")
}

// gib renders a byte count for an operator-facing log line.
func gib(b int64) string {
	const g = 1024 * 1024 * 1024
	if b >= g {
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(g))
	}
	return fmt.Sprintf("%.1f MiB", float64(b)/(1024*1024))
}
