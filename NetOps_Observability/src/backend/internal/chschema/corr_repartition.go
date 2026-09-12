// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
//   - REPORT-ONLY BY DEFAULT. CORR_REPARTITION defaults to `check`: every boot
//     says what WOULD be migrated, with sizes and the exact command, and
//     migrates NOTHING. `auto` is the old behaviour (migrate under-gate tables
//     at boot), `force` migrates over the gate too. See the incident note on
//     CorrRepartitionCheck — the gate alone was not enough, because "under the
//     gate" is not the same question as "the box is idle enough to be rewritten
//     right now", and only an operator can answer the second one.
//   - GATED. A table whose uncompressed size exceeds CORR_REPARTITION_MAX_GIB
//     (default 4 GiB) is SKIPPED with a loud, actionable log line naming the
//     table, its size, the gate, and the exact env to run it deliberately.
//     The lab's corr_objects (48.9 GiB) is therefore never silently rewritten.
//   - DELIBERATE. CORR_REPARTITION=force ignores the size gate;
//     CORR_REPARTITION=off does nothing at all.
//   - NEVER ORPHANED. Every copy runs under a deterministic query_id and a
//     server-side execution bound; if its client call fails anyway, the copy is
//     polled in system.processes and KILLed before the partition is declared
//     failed. See "the orphaned-copy guard" below.
//   - BOUNDED. The copy runs one DESTINATION day-partition at a time, and a
//     day holding more than CORR_REPARTITION_BATCH_ROWS rows is copied in
//     hourly sub-batches. No statement ever reads the whole table.
//   - RESUMABLE + IDEMPOTENT. The resume unit is one destination partition: a
//     partition whose row count already matches the source is skipped, and a
//     PARTIALLY copied one is DROPped and redone. A crash at any point leaves
//     the live table untouched and the next boot continues.
//   - VERIFIED, BOUNDED BY THE SOURCE-VISIBLE PARTITION SET. The swap happens
//     only when (a) every partition the SOURCE still holds has exactly that many
//     rows in the shadow, and (b) the shadow holds NO partition the source no
//     longer has. If the source is still growing (the correlation engine is
//     writing), the migration retries the delta up to
//     CORR_REPARTITION_CATCHUP_PASSES times and then ABORTS without swapping
//     rather than silently losing the rows written during the copy. Nothing is
//     destroyed: the pre-migration table is kept as netops.<table>__premigration
//     until an operator drops it (or CORR_REPARTITION_DROP_OLD=true).
//   - RECONCILED, NOT WEDGED (tracker 206, ultra-review #10). The verification
//     used to compare WHOLE-TABLE counts, and that made a SHRINKING source
//     unrepresentable: the shadow deliberately carries no TTL while the copy
//     runs (CorrShadowTTLStmt), so when the source's TTL expired a day mid-copy
//     the rows already copied had no counterpart left, the delta could never
//     converge FROM ABOVE, and the run aborted errSourceUnstable. The shadow is
//     CREATE IF NOT EXISTS and reused on every boot, so the orphaned excess
//     persisted and every later attempt re-wedged on it. Now every pass STARTS
//     by reconciling: a shadow partition whose source partition is gone (TTL'd
//     away, or the day rolled out of the horizon) is an ORPHAN, is DROPped with
//     the drop CONFIRMED, is logged with (tenant, day, rows) and is counted in
//     the run report. A source that keeps shrinking therefore converges instead
//     of wedging, and the shadow stays safe to reuse across boots. The
//     last-resort escape is CORR_REPARTITION_RESET_SHADOW=true, which drops
//     every shadow table before an auto/force run (and is refused, loudly, in
//     check mode — check mutates nothing, ever).
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
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── the injected ClickHouse seam ────────────────────────────────────────────

// CHExec is the ClickHouse capability this migration needs, expressed as an
// interface so the package stays free of transport and env (CLAUDE.md §2/§5:
// every external dependency is injected). the repartition adapter in src/backend/clickhouse_client.go
// supplies the real implementation over the chhttp seam.
type CHExec interface {
	// Exec runs one SHORT statement (DDL, DROP PARTITION, KILL) that returns no
	// rows, under the adapter's own modest budget.
	Exec(ctx context.Context, sql string) error
	// Query runs one SELECT and returns its rows as decoded JSON objects.
	Query(ctx context.Context, sql string) ([]map[string]any, error)
	// ExecLong runs one LONG statement — a partition copy — under a caller-chosen
	// query_id and deadline. It is a separate method, not a flag on Exec, because
	// the two have genuinely different contracts: the caller of ExecLong must be
	// able to FIND its statement on the server after the call has returned, and
	// the transport must give the HTTP client a longer timeout than the
	// server-side bound it asks for. See "the orphaned-copy guard".
	ExecLong(ctx context.Context, sql string, opt CHLongOpts) error
}

// CHLongOpts parameterises one long statement.
type CHLongOpts struct {
	// QueryID is the server-side query_id to run under. It is the ONLY handle
	// that can locate the statement in system.processes or address it to KILL.
	QueryID string
	// Budget is the server-side execution ceiling for this one statement. The
	// transport must apply it as max_execution_time AND wait longer than it.
	Budget time.Duration
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
			OrderBy: "(tenant_id, ts, signal_id)",
			// Tracker 189 residual: the shadow BECOMES the live table at the
			// swap, so it must carry the dedup window the live one carries —
			// otherwise the archive loses its retry guarantee for the window
			// between the swap and the next boot converge, while the
			// correlation service is already re-sending on it.
			Settings: "index_granularity = 8192, non_replicated_deduplication_window = 1000, " +
				"ttl_only_drop_parts = 1", ttlDays: archive,
		},
		{
			Name: "corr_path_edges", TimeCol: "created_at",
			OrderBy:  "(tenant_id, correlation_id, version, from_node, to_node)",
			Settings: "index_granularity = 8192, ttl_only_drop_parts = 1", ttlDays: fixed(corrPathEdgesTTLDays),
		},
		{
			Name: "corr_tenant_write_amp", TimeCol: "window_start",
			OrderBy: "(tenant_id, window_start)",
			// Same reason as corr_signals_archive above.
			Settings: "index_granularity = 8192, non_replicated_deduplication_window = 1000, " +
				"ttl_only_drop_parts = 1", ttlDays: fixed(corrTenantWriteAmpTTLDays),
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
//
// CorrRepartitionCheck is the DEFAULT, and that default is an incident finding,
// not a preference.
//
// 2026-08-29 14:19, api boot after deploying c703db56: netops.corr_edges was
// 3.74 GiB uncompressed — UNDER the 4 GiB gate — so `auto` started rewriting it
// automatically, on a box that was in the middle of a scale run. The gate had
// asked the right question about SIZE and no question at all about LOAD. The
// copy's client call then timed out, the migration correctly refused to swap,
// and the INSERT ... SELECT went on running server-side (below: the orphaned-copy
// guard).
//
// The size gate cannot be made to answer "is this a good moment to rewrite a
// table" — only an operator can. So the boot default became: SAY what you would
// do, do nothing. `auto` is exactly the previous behaviour and is still the
// right setting for a fresh or small install that migrates itself in seconds;
// it is now an explicit choice rather than the thing that happens if nobody
// thought about it.
const (
	CorrRepartitionOff   = "off"   // never run, report nothing
	CorrRepartitionCheck = "check" // DEFAULT: report what WOULD migrate, change nothing
	CorrRepartitionAuto  = "auto"  // migrate below the size gate, skip loudly above it
	CorrRepartitionForce = "force" // migrate regardless of size (operator's decision)
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
	// ResetShadow DROPs every netops.<table>__daily shadow BEFORE the run, in
	// auto/force mode only. Default false, because the shadow is normally the
	// valuable thing — it is a resumable, partially finished copy of a table
	// that can take hours. This is the explicit operator escape hatch for a
	// shadow that cannot be reconciled (tracker 206): it throws that progress
	// away and starts the copy from empty. In `check` mode it is IGNORED with a
	// log line — check mutates nothing, and a reset knob is no exception.
	ResetShadow bool
	// ReapPollInterval / ReapPollAttempts bound the orphaned-copy reaper: how
	// often, and how many times, system.processes is polled for a copy whose
	// client call failed before the copy is KILLed. Zero means the default; they
	// are settings rather than constants so a test can drive the whole path
	// without sleeping (CLAUDE.md §2: no hidden environment).
	ReapPollInterval time.Duration
	ReapPollAttempts int
}

// reapCadence resolves the reaper's cadence, defaulting a zero value rather than
// polling in a tight loop or not at all.
func (c CorrRepartitionSettings) reapCadence() (time.Duration, int) {
	interval, attempts := c.ReapPollInterval, c.ReapPollAttempts
	if interval <= 0 {
		interval = corrReapPollInterval
	}
	if attempts <= 0 {
		attempts = corrReapPollAttempts
	}
	return interval, attempts
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
		Mode:                 CorrRepartitionCheck,
		MaxUncompressedBytes: corrRepartitionDefaultMaxGiB * 1024 * 1024 * 1024,
		BatchRows:            corrRepartitionDefaultBatchRows,
		CatchUpPasses:        corrRepartitionDefaultCatchUp,
		ReapPollInterval:     corrReapPollInterval,
		ReapPollAttempts:     corrReapPollAttempts,
	}
	switch mode := strings.ToLower(strings.TrimSpace(envOr("CORR_REPARTITION", CorrRepartitionCheck))); mode {
	case CorrRepartitionOff, CorrRepartitionCheck, CorrRepartitionAuto, CorrRepartitionForce:
		cfg.Mode = mode
	default:
		// Never widen the blast radius on a typo: an unreadable mode falls back to
		// the report-only default, not to the one that rewrites tables.
		logf("corr-repartition: unknown CORR_REPARTITION=%q, using %q", mode, CorrRepartitionCheck)
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
	cfg.ResetShadow = strings.EqualFold(
		strings.TrimSpace(envOr("CORR_REPARTITION_RESET_SHADOW", "")), "true")
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
// verification disagree with itself.
//
// The statement is DERIVED, not duplicated: it renders through
// corrModifyTTLStmt — the same function CorrRetentionDDL renders the live
// table's TTL with — so the shadow cannot come out of the swap carrying a
// retention shape the live table stopped using. Only the table name differs
// (ultra-review #42, tracker 208a).
func CorrShadowTTLStmt(t corrRepartitionTable, d corrRetentionDays) string {
	days := t.ttlDays(d)
	if days <= 0 {
		return ""
	}
	return corrModifyTTLStmt(t.Name+corrRepartitionShadowSuffix, t.TimeCol, days)
}

// CorrPartitionKeysSQL enumerates the DESTINATION partitions and their source
// row counts — the migration's unit of work, resume and verification.
func CorrPartitionKeysSQL(t corrRepartitionTable) string {
	return corrPartitionKeysSQLFor(t.Name, t.TimeCol, corrScope)
}

// CorrShadowPartitionKeysSQL is the SAME enumeration over the SHADOW table.
//
// It exists because the whole-table row-count verification it replaces could not
// see the one shape that wedges the migration (tracker 206): rows in the shadow
// whose SOURCE partition has expired under the source's TTL while the copy ran.
// A whole-table delta cannot distinguish "the engine wrote 3 more rows" from
// "the TTL removed a day I already copied" — the first converges by copying
// more, the second never converges at all. Enumerating BOTH sides in the same
// (tenant, day, rows) shape makes the difference a set operation: a partition
// present in the shadow and absent from the source is an ORPHAN and is dropped,
// not chased.
//
// Rendered through the SAME builder as the source enumeration, so the two can
// never drift into comparing differently-shaped keys.
func CorrShadowPartitionKeysSQL(t corrRepartitionTable) string {
	return corrPartitionKeysSQLFor(t.Name+corrRepartitionShadowSuffix, t.TimeCol, corrScope)
}

// corrPartitionKeysSQLFor is the one renderer behind both enumerations.
//
// The scope is a PARAMETER, not a constant reached from inside here, so that
// every exported migration read names corrScope in its own body: enumerating a
// corr_* table partition-by-partition is a cross-tenant maintenance read and has
// to say so on the wire (CLAUDE.md §3a rule 4), and that property is guarded by
// a source-level scan over each builder (tests/test_clickhouse_corr_storage.py,
// test_every_migration_read_carries_the_cross_tenant_scope). A shared renderer
// that hid the setting one call away would satisfy the wire and defeat the
// guard — and the guard is the thing that catches the next refactor.
func corrPartitionKeysSQLFor(table, timeCol, scope string) string {
	return "SELECT tenant_id AS t, toYYYYMMDD(" + timeCol + ") AS d, count() AS n " +
		"FROM netops." + table + " GROUP BY t, d ORDER BY d, t" + scope + " FORMAT JSON"
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

// CorrDropShadowStmt discards the WHOLE shadow table. Two callers, one
// renderer: prepareShadow uses it when a shadow's column list has drifted from
// the source (an `INSERT ... SELECT *` is positional, so a drifted shadow must
// be rebuilt, never appended to), and the CORR_REPARTITION_RESET_SHADOW path
// uses it as the operator's deliberate "throw the partial copy away".
func CorrDropShadowStmt(t corrRepartitionTable) string {
	return "DROP TABLE IF EXISTS netops." + t.Name + corrRepartitionShadowSuffix
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

// ── the orphaned-copy guard (incident 2026-08-29) ───────────────────────────
//
// WHAT HAPPENED. 14:19, api boot after deploying c703db56. netops.corr_edges
// (3.74 GiB uncompressed, under the gate) was migrated automatically while the
// stack was in use. The first partition copy, (global, 20260821), came back as
//
//	clickhouse repartition: transport: Post "https://clickhouse:8443?..."
//
// — the HTTP CLIENT's timeout, not the server's. The migration then did the
// right thing at ITS level (stopped after corr_edges (failed), swapped nothing,
// left the live table untouched) and the wrong thing at the server's: the
// INSERT ... SELECT kept running. Minutes later it was still in
// system.processes with 121,495 rows already written into corr_edges__daily,
// and had to be killed by hand.
//
// THE LESSON. A statement whose client call has returned is not a statement
// that has stopped. Nothing in "I got an error" says the server agreed. Three
// consequences, all implemented here:
//
//  1. every copy carries an explicit, DETERMINISTIC query_id — the only handle
//     that can find it in system.processes or address it to KILL;
//  2. every copy carries a server-side execution bound DERIVED FROM ITS ROW
//     COUNT (CorrCopyBudget), and the transport gives the HTTP client a longer
//     timeout than that bound, so the ordinary case is simply "the client
//     waits" (the incident's client timeout was 12 s against a 10-minute
//     server budget — see chRepartitionSlack in clickhouse_client.go);
//  3. when the client call fails anyway, the copy is REAPED before the
//     partition is declared failed: poll system.processes for that query_id
//     until it is gone or the poll budget is spent, then KILL ... SYNC. The
//     outcome is logged either way (§10: no silent failures).
//
// The determinism of the id is a second net. If a previous boot's orphan for
// the same (table, tenant, day, pass, batch) is somehow still running,
// ClickHouse refuses the new statement with QUERY_WITH_SAME_ID_IS_ALREADY_RUNNING
// instead of letting two writers append to one destination partition.

const (
	// corrCopyRowsPerSecFloor is a deliberately PESSIMISTIC floor for how fast a
	// partition copy moves rows. It exists only to size a deadline, so it must be
	// a LOWER bound on throughput, never an estimate of it. The incident is the
	// one hard measurement available: more than 600 s of server time had produced
	// 121,495 rows — under 205 rows/s — on a box simultaneously running the
	// correlation engine at scale. Being wrong in the generous direction costs a
	// longer wait; being wrong in the tight direction costs another orphan.
	corrCopyRowsPerSecFloor = 200
	// corrCopyBudgetMin/Max clamp the derived deadline. Max also bounds the
	// server-side max_execution_time, so a wedged copy dies on its own.
	corrCopyBudgetMin = 5 * time.Minute
	corrCopyBudgetMax = 60 * time.Minute
	// Reaper cadence: ~2 minutes of "is it still running?" before the KILL.
	corrReapPollInterval = 5 * time.Second
	corrReapPollAttempts = 24
	// corrIDMaxTenantLen bounds the tenant component of a query_id.
	corrIDMaxTenantLen = 48
)

// CorrCopyBudget derives the server-side deadline for a copy statement covering
// rows rows, from the pessimistic throughput floor, clamped both ends. Exported
// so the transport (which must wait longer than it) and the tests assert against
// ONE definition.
func CorrCopyBudget(rows int64) time.Duration {
	if rows <= 0 {
		return corrCopyBudgetMin
	}
	secs := rows / corrCopyRowsPerSecFloor
	if rows%corrCopyRowsPerSecFloor != 0 {
		secs++
	}
	// Clamp in SECONDS before converting: a huge row count would otherwise
	// overflow the nanosecond Duration and come back negative.
	if max := int64(corrCopyBudgetMax / time.Second); secs > max {
		return corrCopyBudgetMax
	}
	if d := time.Duration(secs) * time.Second; d > corrCopyBudgetMin {
		return d
	}
	return corrCopyBudgetMin
}

// CorrCopyQueryID renders the server-side query_id for one copy statement. It is
// deterministic in (table, tenant, day, pass, batch) — the full identity of the
// unit of work — so the same copy always has the same handle, whether it is
// being polled for, killed, or grepped out of system.query_log after the fact.
func CorrCopyQueryID(table, tenant string, day int64, pass, batch int) string {
	return "corr-repartition." + table + "." + corrIDSafe(tenant) + "." +
		strconv.FormatInt(day, 10) + ".p" + strconv.Itoa(pass) + ".b" + strconv.Itoa(batch)
}

// corrIDSafe renders an untrusted identifier into the small charset a query_id
// stays greppable in. A tenant id is tenant-controlled data (§3), so it is
// sanitised and length-bounded; when sanitising CHANGED it — or the bound cut it
// — a short digest of the ORIGINAL is appended, so two different tenants can
// never collapse onto one query_id and have their copies kill each other.
func corrIDSafe(s string) string {
	var b strings.Builder
	changed := len(s) > corrIDMaxTenantLen
	for i, r := range s {
		if i >= corrIDMaxTenantLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
			changed = true
		}
	}
	out := b.String()
	if out == "" {
		changed = true
	}
	if !changed {
		return out
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(s)) // hash.Hash's Write never returns an error
	return out + "-" + strconv.FormatUint(uint64(h.Sum32()), 16)
}

// CorrRunningCopySQL asks whether a query_id is STILL EXECUTING. system.processes
// holds only running queries, so 0 means "finished, killed, or never started" —
// exactly the question the reaper asks.
func CorrRunningCopySQL(queryID string) string {
	return "SELECT count() AS n FROM system.processes WHERE query_id = " +
		chQuote(queryID) + " FORMAT JSON"
}

// CorrKillCopyStmt kills one orphaned copy. SYNC on purpose: an asynchronous
// kill would let the caller declare the partition failed while the writer is
// still appending to it, which is the same bug one step later.
func CorrKillCopyStmt(queryID string) string {
	return "KILL QUERY WHERE query_id = " + chQuote(queryID) + " SYNC"
}

// reapCopy resolves what happened to a copy statement whose CLIENT call returned
// an error, and returns a short verdict for the caller's failure detail. It never
// returns an error of its own: the partition is already failing, and the reap's
// job is to make sure nothing is left running and to SAY what it found.
func reapCopy(ctx context.Context, ex CHExec, cfg CorrRepartitionSettings,
	queryID string, logf func(string, ...any)) string {

	interval, attempts := cfg.reapCadence()
	// The reap must survive the ctx that may itself be the reason the call
	// failed: a cancelled or expired migration context would otherwise leave the
	// orphan behind — precisely the failure this exists for. So it runs on a
	// detached, separately bounded context (still bounded: §9).
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx),
		time.Duration(attempts+1)*interval+30*time.Second)
	defer cancel()

	for attempt := 1; attempt <= attempts; attempt++ {
		running, err := copyIsRunning(rctx, ex, queryID)
		if err != nil {
			logf("corr-repartition: query_id=%s — system.processes unreadable (%v); "+
				"issuing the KILL anyway rather than assuming the copy stopped", queryID, err)
			break
		}
		if !running {
			return fmt.Sprintf("query_id=%s left nothing running (poll %d/%d)", queryID, attempt, attempts)
		}
		logf("corr-repartition: query_id=%s is STILL RUNNING server-side after its client "+
			"call failed (poll %d/%d) — waiting %s", queryID, attempt, attempts, interval)
		if !sleepCtx(rctx, interval) {
			break
		}
	}

	// Still running, or unknowable. Kill it: leaving a writer appending to a
	// destination partition we are about to declare failed is how the NEXT
	// attempt double-copies rows (it drops the partition, and the orphan keeps
	// filling it back in).
	if err := ex.Exec(rctx, CorrKillCopyStmt(queryID)); err != nil {
		logf("corr-repartition: KILL QUERY for query_id=%s FAILED: %v — the copy may still "+
			"be running server-side. Check system.processes and kill it by hand before the "+
			"next attempt, or the retry will copy on top of a live writer.", queryID, err)
		return "orphan NOT confirmed killed (query_id=" + queryID + "): " + err.Error()
	}
	logf("corr-repartition: KILLed orphaned copy query_id=%s — it outlived its client call "+
		"(the 2026-08-29 failure mode); the partition it was writing will be dropped and "+
		"redone on the next attempt", queryID)
	if running, err := copyIsRunning(rctx, ex, queryID); err == nil && running {
		return "orphan STILL RUNNING after KILL (query_id=" + queryID + ")"
	}
	return "orphan killed (query_id=" + queryID + ")"
}

// copyIsRunning reports whether queryID is currently executing on the server.
func copyIsRunning(ctx context.Context, ex CHExec, queryID string) (bool, error) {
	rows, err := ex.Query(ctx, CorrRunningCopySQL(queryID))
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	n, err := chInt(rows[0]["n"])
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// sleepCtx waits d, or returns false as soon as ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ── result reporting ────────────────────────────────────────────────────────

// CorrRepartitionOutcome is what happened to ONE table.
type CorrRepartitionOutcome struct {
	Table  string
	Status string // see the CorrRepartition* status constants
	Rows   int64
	Bytes  int64 // uncompressed
	Detail string
	// OrphanPartitions / OrphanRows count the shadow partitions reconciled away
	// during the run because the SOURCE no longer had them (tracker 206). They
	// are part of the report, not a diagnostic: a run that dropped orphans
	// copied a table that was shrinking underneath it, and an operator reading
	// the report should be told so rather than inferring it from a log line.
	OrphanPartitions int
	OrphanRows       int64
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
	// check-mode verdicts: what auto/force WOULD do. Nothing was touched.
	CorrRepartitionWouldMigrate = "check-would-migrate"
	CorrRepartitionWouldSkip    = "check-would-skip-too-big"
)

// CorrRepartitionIsCheck reports whether a status is a check-mode verdict
// (nothing happened) rather than an outcome.
func CorrRepartitionIsCheck(status string) bool {
	return status == CorrRepartitionWouldMigrate || status == CorrRepartitionWouldSkip
}

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
	// State the mode on every boot, before anything is read. A rewrite that
	// surprised an operator (2026-08-29) is a rewrite whose mode was never in the
	// log to be seen.
	logf("corr-repartition: mode=%s (CORR_REPARTITION), gate %s uncompressed per table, "+
		"batch %d rows, %d catch-up passes%s",
		cfg.Mode, gib(cfg.MaxUncompressedBytes), cfg.BatchRows, cfg.CatchUpPasses,
		corrModeNote(cfg.Mode))
	if cfg.Mode == CorrRepartitionOff {
		logf("corr-repartition: CORR_REPARTITION=off — daily partitioning not applied to live " +
			"tables, and nothing is reported either; use 'check' to see what would migrate")
		for _, t := range tables {
			out = append(out, CorrRepartitionOutcome{Table: t.Name, Status: CorrRepartitionSkippedOff})
		}
		return out
	}
	if cfg.ResetShadow {
		resetShadows(ctx, ex, cfg, tables, logf)
	}
	for _, t := range tables {
		o := migrateOne(ctx, ex, cfg, ret, t, logf)
		out = append(out, o)
		// A check-mode verdict is not an outcome: keep reporting the rest.
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

// resetShadows implements CORR_REPARTITION_RESET_SHADOW: drop every shadow
// table before the run, so the copy starts from empty.
//
// This is the operator's escape hatch, not a routine step. Ordinary shadow reuse
// is SAFE now that every pass reconciles orphan partitions away (tracker 206),
// and a shadow is a partially finished copy of a table that can take hours — so
// discarding it is only ever right when a human has decided the shadow is
// untrustworthy. Hence: opt-in, loud, and NEVER in check mode.
//
// A failed drop is logged and the run continues: reconciliation is the normal
// path and it still applies to a shadow that could not be dropped. What is not
// allowed is silence (§10).
func resetShadows(ctx context.Context, ex CHExec, cfg CorrRepartitionSettings,
	tables []corrRepartitionTable, logf func(string, ...any)) {

	if cfg.Mode != CorrRepartitionAuto && cfg.Mode != CorrRepartitionForce {
		logf("corr-repartition: CORR_REPARTITION_RESET_SHADOW=true is IGNORED in mode=%s — "+
			"check mode reads metadata and mutates NOTHING, and a reset knob is not an "+
			"exception to that. Re-run with CORR_REPARTITION=auto (or force) to actually "+
			"discard the shadow tables.", cfg.Mode)
		return
	}
	logf("corr-repartition: CORR_REPARTITION_RESET_SHADOW=true — dropping every shadow table " +
		"before this run. Any partially finished copy is DISCARDED and restarts from empty; " +
		"this is the operator reset, not the normal path (a reused shadow is reconciled " +
		"partition-by-partition against the source on every pass).")
	for _, t := range tables {
		shadow := t.Name + corrRepartitionShadowSuffix
		if err := ex.Exec(ctx, CorrDropShadowStmt(t)); err != nil {
			logf("corr-repartition: RESET — dropping netops.%s FAILED: %v. The run continues "+
				"and the shadow will be reconciled against the source instead; if it is the "+
				"thing that is wedged, drop it by hand.", shadow, err)
			continue
		}
		logf("corr-repartition: RESET — dropped netops.%s", shadow)
	}
}

// corrModeNote spells out, in the boot line itself, what this mode is about to
// do to the operator's data. "mode=auto" is only meaningful to someone who has
// read this file.
func corrModeNote(mode string) string {
	switch mode {
	case CorrRepartitionCheck:
		return " — CHECK ONLY: nothing will be migrated, this run just reports what would be"
	case CorrRepartitionAuto:
		return " — AUTO: under-gate tables WILL be rewritten now, on whatever load this box is under"
	case CorrRepartitionForce:
		return " — FORCE: every monthly table WILL be rewritten now, the size gate is ignored"
	default:
		return ""
	}
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

	// CHECK — the default mode. Everything above this point is metadata reads;
	// nothing below it is. Report the verdict and the exact command, touch
	// nothing (see the incident note on CorrRepartitionCheck).
	if cfg.Mode == CorrRepartitionCheck {
		res.Detail = fmt.Sprintf("%d rows / %s uncompressed (%s on disk)", n, gib(unc), gib(cmp))
		if unc > cfg.MaxUncompressedBytes {
			res.Status = CorrRepartitionWouldSkip
			logf("corr-repartition: CHECK netops.%s — still MONTHLY (%s), %s, OVER the "+
				"CORR_REPARTITION_MAX_GIB gate of %s. Nothing was changed. Even "+
				"CORR_REPARTITION=auto would skip it; migrating it is an explicit "+
				"decision: stop the correlation engine, then run the API once with "+
				"CORR_REPARTITION=force (or raise CORR_REPARTITION_MAX_GIB above %s).",
				t.Name, chString(rows[0]["k"]), res.Detail, gib(cfg.MaxUncompressedBytes), gib(unc))
			return res
		}
		res.Status = CorrRepartitionWouldMigrate
		logf("corr-repartition: CHECK netops.%s — still MONTHLY (%s), %s, UNDER the "+
			"CORR_REPARTITION_MAX_GIB gate of %s: it WOULD be migrated to %s. Nothing was "+
			"changed — CORR_REPARTITION defaults to 'check' since 2026-08-29, when an "+
			"under-gate table was rewritten automatically at boot while the stack was "+
			"under load and left an orphaned INSERT ... SELECT running server-side. To "+
			"migrate, pick a quiet window and run the API once with CORR_REPARTITION=auto.",
			t.Name, chString(rows[0]["k"]), res.Detail, gib(cfg.MaxUncompressedBytes), want)
		return res
	}

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

	cp, err := copyAllPasses(ctx, ex, cfg, t, logf)
	res.OrphanPartitions, res.OrphanRows = cp.OrphanPartitions, cp.OrphanRows
	if err != nil {
		if errors.Is(err, errSourceUnstable) {
			res.Status, res.Detail = CorrRepartitionUnstable, err.Error()
			// The shadow is KEPT. Reconciliation makes reusing it safe — every pass
			// drops the partitions the source no longer has — and a large copy's
			// progress is worth hours. The per-partition deltas above are what tell
			// an operator WHICH condition this is: a partition where the shadow is
			// SHORT is the engine still writing; one where the shadow is AHEAD (or
			// the source has none) is a day that expired and will be reconciled away
			// on the next run.
			logf("corr-repartition: ABORTED netops.%s — %v. Nothing was swapped and the live "+
				"table is untouched. The partial copy in netops.%s%s is KEPT and is "+
				"resumable: the next auto/force run reconciles it against the source "+
				"partition-by-partition before copying. Stop the correlation engine and "+
				"restart the API to finish it; if the shadow itself is the problem, discard "+
				"it deliberately with CORR_REPARTITION_RESET_SHADOW=true.",
				t.Name, err, t.Name, corrRepartitionShadowSuffix)
			return res
		}
		res.Status, res.Detail = CorrRepartitionFailed, err.Error()
		logf("corr-repartition: %s — %s (live table untouched)", t.Name, res.Detail)
		return res
	}
	copied := cp.Rows

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
		logf("corr-repartition: netops.%s now %s — %d rows copied%s; pre-migration copy dropped "+
			"(CORR_REPARTITION_DROP_OLD=true)", t.Name, want, copied, orphanNote(cp))
		return res
	}
	logf("corr-repartition: netops.%s now %s — %d rows copied%s. The pre-migration table is "+
		"KEPT as netops.%s (your rollback); drop it with `DROP TABLE netops.%s` once you are "+
		"satisfied, or set CORR_REPARTITION_DROP_OLD=true.",
		t.Name, want, copied, orphanNote(cp), backup, backup)
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
			if err := ex.Exec(ctx, CorrDropShadowStmt(t)); err != nil {
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

// corrPart is one destination partition's identity: (tenant, day). It is the
// unit of copy, resume, verification and orphan reconciliation alike, so there
// is exactly one type for it.
type corrPart struct {
	tenant string
	day    int64
}

// corrPartDelta is one partition on which the source and the shadow disagree.
// src == 0 with dst > 0 is the ORPHAN shape; dst < src is "not copied yet".
type corrPartDelta struct {
	corrPart
	src int64
	dst int64
}

// corrCopyResult is what one table's copy produced, including the orphan
// accounting the run report carries.
type corrCopyResult struct {
	Rows             int64 // rows the source held, per partition, at the verifying pass
	Partitions       int
	OrphanPartitions int
	OrphanRows       int64
}

// corrUnstableTopParts bounds how many per-partition deltas the unstable-abort
// message spells out. The message has to be readable in a boot log; the count of
// differing partitions is always exact, only the enumeration is truncated.
const corrUnstableTopParts = 5

// copyAllPasses reconciles, copies, and verifies — once per pass — until the
// shadow agrees with the SOURCE-VISIBLE partition set, or gives up after
// cfg.CatchUpPasses with errSourceUnstable. It never swaps a short copy into
// place, and it never chases a delta it cannot close.
//
// The order inside a pass is load-bearing:
//
//  1. RECONCILE FIRST. Drop every shadow partition the source no longer has.
//     Doing this before the copy is what makes a SHRINKING source converge: the
//     excess is removed at the top of each pass rather than accumulating into a
//     delta that can only be closed by rows that no longer exist. Before tracker
//     206 this step did not exist and the run wedged on errSourceUnstable — and
//     because the shadow is CREATE IF NOT EXISTS, every later boot re-wedged on
//     the same orphaned rows.
//  2. COPY. Unchanged: per destination partition, skip the complete ones, DROP
//     and redo a partial one.
//  3. VERIFY, BOUNDED BY THE SOURCE. Every source partition's shadow count
//     equals its source count, AND the shadow holds nothing the source does not.
func copyAllPasses(ctx context.Context, ex CHExec, cfg CorrRepartitionSettings,
	t corrRepartitionTable, logf func(string, ...any)) (corrCopyResult, error) {

	var res corrCopyResult
	var last []corrPartDelta
	for pass := 1; pass <= cfg.CatchUpPasses; pass++ {
		n, rows, err := reconcileOrphans(ctx, ex, t, pass, logf)
		res.OrphanPartitions += n
		res.OrphanRows += rows
		if err != nil {
			return res, err
		}
		if err := copyOnePass(ctx, ex, cfg, t, pass, logf); err != nil {
			return res, err
		}
		total, parts, deltas, err := verifyAgainstSource(ctx, ex, t)
		if err != nil {
			return res, err
		}
		if len(deltas) == 0 {
			res.Rows, res.Partitions = total, parts
			logf("corr-repartition: netops.%s — copy verified against the source's own "+
				"partitions: %d rows across %d partitions, every one matching, and no "+
				"shadow partition outside the source%s",
				t.Name, total, parts, orphanNote(res))
			return res, nil
		}
		last = deltas
		logf("corr-repartition: netops.%s — pass %d/%d did not converge: %s; re-running the delta",
			t.Name, pass, cfg.CatchUpPasses, deltaSummary(deltas))
	}
	return res, fmt.Errorf("%w after %d catch-up passes: %s%s",
		errSourceUnstable, cfg.CatchUpPasses, deltaSummary(last), totalsNote(ctx, ex, t))
}

// orphanNote renders the orphan accounting for an operator-facing line, or "".
func orphanNote(res corrCopyResult) string {
	if res.OrphanPartitions == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d orphan shadow partition(s) holding %d rows were reconciled away "+
		"during the copy — the source shrank underneath it, which is normal when its TTL "+
		"expires a day mid-copy)", res.OrphanPartitions, res.OrphanRows)
}

// reconcileOrphans drops every shadow partition whose SOURCE partition is gone.
//
// "Gone" means exactly one thing here — absent from CorrPartitionKeysSQL — and
// covers both ways it happens: the source's TTL expired the day while the copy
// ran, or the day rolled out of the retention horizon between boots. Either way
// the rows in the shadow have no counterpart to be verified against and would
// hold the delta open forever.
//
// The drop is CONFIRMED, with the same refusal semantics as the partial-redo
// guard in copyOnePass: a destination partition that still holds rows after
// DROP PARTITION means something else is writing into it (an orphaned copy from
// an earlier attempt is exactly that shape — incident 2026-08-29), and
// continuing would race a live writer. Refusing and saying why is the only safe
// answer.
//
// Returns the number of orphan partitions dropped and the rows they held —
// including on the error path, so a partial reconciliation is still reported.
func reconcileOrphans(ctx context.Context, ex CHExec, t corrRepartitionTable, pass int,
	logf func(string, ...any)) (int, int64, error) {

	shadow := t.Name + corrRepartitionShadowSuffix
	src, err := partitionKeyMap(ctx, ex, CorrPartitionKeysSQL(t))
	if err != nil {
		return 0, 0, fmt.Errorf("enumerate source partitions: %w", err)
	}
	dst, err := partitionKeyMap(ctx, ex, CorrShadowPartitionKeysSQL(t))
	if err != nil {
		return 0, 0, fmt.Errorf("enumerate shadow partitions: %w", err)
	}
	orphans := make([]corrPart, 0, len(dst))
	for k := range dst {
		if _, alive := src[k]; !alive {
			orphans = append(orphans, k)
		}
	}
	sortParts(orphans)

	var dropped int
	var rows int64
	for _, k := range orphans {
		had := dst[k]
		if err := ex.Exec(ctx, CorrDropShadowPartitionStmt(t, k.tenant, k.day)); err != nil {
			return dropped, rows, fmt.Errorf("drop orphan partition (%s, %d) from netops.%s: %w",
				k.tenant, k.day, shadow, err)
		}
		left, err := partitionCount(ctx, ex, shadow, t, k.tenant, k.day)
		if err != nil {
			return dropped, rows, fmt.Errorf("re-count dropped orphan partition (%s, %d): %w",
				k.tenant, k.day, err)
		}
		if left != 0 {
			return dropped, rows, fmt.Errorf("orphan partition (%s, %d) still holds %d rows after "+
				"DROP PARTITION on netops.%s — something is still writing to it (an orphaned "+
				"copy from an earlier attempt?); refusing to reconcile against a live writer",
				k.tenant, k.day, left, shadow)
		}
		dropped++
		rows += had
		logf("corr-repartition: netops.%s pass %d — ORPHAN shadow partition (%s, %d) held %d "+
			"rows the source no longer has (its TTL expired the day, or the day rolled out); "+
			"dropped from netops.%s so the copy can converge",
			t.Name, pass, k.tenant, k.day, had, shadow)
	}
	return dropped, rows, nil
}

// verifyAgainstSource is the verification rule tracker 206 replaced the
// whole-table count comparison with.
//
// The copy is verified when BOTH hold:
//
//	(a) every partition the SOURCE still has holds exactly that many rows in the
//	    shadow, and
//	(b) the shadow has NO partition the source does not have.
//
// A whole-table comparison collapses both into one number and loses the sign
// information that matters: `src != dst` cannot tell "3 rows arrived" (close it
// by copying) from "a day I already copied expired" (never closable). Returned
// deltas carry both counts per partition so the abort message can say which.
func verifyAgainstSource(ctx context.Context, ex CHExec, t corrRepartitionTable) (
	rows int64, parts int, deltas []corrPartDelta, err error) {

	src, err := partitionKeyMap(ctx, ex, CorrPartitionKeysSQL(t))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("verify: enumerate source partitions: %w", err)
	}
	dst, err := partitionKeyMap(ctx, ex, CorrShadowPartitionKeysSQL(t))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("verify: enumerate shadow partitions: %w", err)
	}
	for k, want := range src {
		rows += want
		if have := dst[k]; have != want {
			deltas = append(deltas, corrPartDelta{corrPart: k, src: want, dst: have})
		}
	}
	for k, have := range dst {
		if _, alive := src[k]; !alive {
			deltas = append(deltas, corrPartDelta{corrPart: k, src: 0, dst: have})
		}
	}
	sortDeltas(deltas)
	return rows, len(src), deltas, nil
}

// deltaSummary renders the per-partition disagreement for an operator. The
// abort used to say only "N rows short", which reads identically whether the
// engine is writing, a day expired, or a copy silently failed — three different
// operator actions. Naming the partitions and both counts is what makes them
// distinguishable from the log alone.
func deltaSummary(deltas []corrPartDelta) string {
	if len(deltas) == 0 {
		return "no partition differs"
	}
	shown := len(deltas)
	if shown > corrUnstableTopParts {
		shown = corrUnstableTopParts
	}
	items := make([]string, 0, shown)
	for _, d := range deltas[:shown] {
		items = append(items, fmt.Sprintf("(%s, %d) source %d shadow %d [%+d]",
			d.tenant, d.day, d.src, d.dst, d.src-d.dst))
	}
	out := fmt.Sprintf("%d partition(s) still differ; largest %d: %s",
		len(deltas), shown, strings.Join(items, "; "))
	if rest := len(deltas) - shown; rest > 0 {
		out += fmt.Sprintf(" (+%d more)", rest)
	}
	return out
}

// totalsNote appends whole-table counts to the unstable abort as CONTEXT — not
// as the verification, which is per-partition now. An unreadable count degrades
// the message; it never fails the run, which is already failing.
func totalsNote(ctx context.Context, ex CHExec, t corrRepartitionTable) string {
	src, err := totalCount(ctx, ex, t.Name)
	if err != nil {
		return ""
	}
	dst, err := totalCount(ctx, ex, t.Name+corrRepartitionShadowSuffix)
	if err != nil {
		return ""
	}
	return fmt.Sprintf(" [whole-table context: source %d rows, shadow %d]", src, dst)
}

// partitionKeyMap reads a (tenant, day) -> rows enumeration. Every field is
// CHECKED: an unreadable count must not be silently read as zero, which would
// look exactly like an empty partition and "verify" a lost day.
func partitionKeyMap(ctx context.Context, ex CHExec, sql string) (map[corrPart]int64, error) {
	rows, err := ex.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	out := make(map[corrPart]int64, len(rows))
	for _, k := range rows {
		day, err := chInt(k["d"])
		if err != nil {
			return nil, fmt.Errorf("partition day %v: %w", k["d"], err)
		}
		n, err := chInt(k["n"])
		if err != nil {
			return nil, fmt.Errorf("partition rows %v: %w", k["n"], err)
		}
		out[corrPart{tenant: chString(k["t"]), day: day}] = n
	}
	return out, nil
}

// sortParts orders partitions deterministically (day, then tenant) — a map
// iteration order would make the drop sequence and the log unreproducible.
func sortParts(p []corrPart) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].day != p[j].day {
			return p[i].day < p[j].day
		}
		return p[i].tenant < p[j].tenant
	})
}

// sortDeltas orders the disagreements largest-first (by absolute row gap) so the
// truncated abort message names the partitions that matter, tie-broken
// deterministically by (day, tenant).
func sortDeltas(d []corrPartDelta) {
	sort.Slice(d, func(i, j int) bool {
		a, b := absInt64(d[i].src-d[i].dst), absInt64(d[j].src-d[j].dst)
		if a != b {
			return a > b
		}
		if d[i].day != d[j].day {
			return d[i].day < d[j].day
		}
		return d[i].tenant < d[j].tenant
	})
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
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
			// CONFIRM the drop before copying on top of it. A destination partition
			// that still holds rows after DROP PARTITION means something else is
			// writing into it — an orphaned copy from an earlier attempt is exactly
			// that shape (2026-08-29) — and re-copying would duplicate rows rather
			// than redo them. Refusing is the only safe answer; the migration stops
			// and says why.
			left, err := partitionCount(ctx, ex, shadow, t, tenant, day)
			if err != nil {
				return fmt.Errorf("re-count dropped partition (%s, %d): %w", tenant, day, err)
			}
			if left != 0 {
				return fmt.Errorf("partition (%s, %d) still holds %d rows after DROP PARTITION on "+
					"netops.%s — something is still writing to it (an orphaned copy from an "+
					"earlier attempt?); refusing to re-copy on top of a live writer", tenant, day, left, shadow)
			}
			logf("corr-repartition: netops.%s pass %d — partition (%s, %d) was %d/%d rows "+
				"from an earlier attempt; dropped and redone", t.Name, pass, tenant, day, have, want)
		}
		// One copy statement, one query_id, one row-count-derived server-side
		// deadline. Both are what make an outlived copy findable and killable
		// instead of orphaned — see "the orphaned-copy guard".
		stmts := CorrCopyPartitionStmts(t, tenant, day, want, cfg.BatchRows)
		budget := CorrCopyBudget(want)
		for i, s := range stmts {
			qid := CorrCopyQueryID(t.Name, tenant, day, pass, i)
			if err := ex.ExecLong(ctx, s, CHLongOpts{QueryID: qid, Budget: budget}); err != nil {
				verdict := reapCopy(ctx, ex, cfg, qid, logf)
				return fmt.Errorf("copy partition (%s, %d) batch %d/%d: %w [%s]",
					tenant, day, i+1, len(stmts), err, verdict)
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
