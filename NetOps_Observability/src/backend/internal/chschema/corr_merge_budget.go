package chschema

// corr_merge_budget.go — bound the background-merge cost of the correlation
// family (P2, docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md, run
// p2-s04b-08290858).
//
// WHAT WAS MEASURED, over a 75-minute 2.5K leg:
//
//	1.40 GiB of rows inserted  ->  337.6 GiB merged across 69,201 merges
//	                               = ~241x merge write amplification
//	peak MergesMutationsMemoryTracking .... 3,978 MiB
//	peak MemoryTracking .................. 4,566 MiB = 95.2 % of the server cap
//
// The cause is visible in the part LEVELS (level = how many merges a part has
// already been through): ~170k one-row inserts were being folded again and
// again into ONE accumulated part per month partition — corr_objects 1.86 GiB
// at level 1,568, corr_current 37.8 MiB at level 33,082, corr_edges 29.8 MiB
// at level 11,848. corr_objects rows are 26,878 B uncompressed and its single
// `hypotheses` String column is 45.01 of the table's 48.01 GiB (94 %), so every
// re-merge rewrites that column whole.
//
// THE FIX, per table:
//
//	max_bytes_to_merge_at_max_space_in_pool  150 GB (stock) -> 2 GiB / 1 GiB
//	    Retires the accumulated part from merge selection once it crosses the
//	    cap: it stops being rewritten, and merge cost becomes bounded by the
//	    cap instead of by the table. At 2 GiB corr_objects settles at ~24 parts
//	    per month partition — far under parts_to_delay_insert (1000) and
//	    parts_to_throw_insert (3000), which stay at their DEFAULTS on purpose
//	    (peak PartsActive was 927 and the run raised no TOO_MANY_PARTS: the
//	    insert-side backpressure is not what needed changing).
//	min_age_to_force_merge_seconds = 600 + ..._on_partition_only = 1
//	    One bounded consolidation pass over a partition whose parts have ALL
//	    been idle 10 minutes, so the small parts the cap leaves behind are
//	    folded once after the write burst instead of continuously during it.
//
// The server-side half of the budget (background_pool_size 16 -> 6,
// merges_mutations_memory_usage_soft_limit 1.5 GiB, mark_cache_size 512 MiB,
// uncompressed_cache_size 0, max_server_memory_usage 4 GiB) is in
// deployment/docker/clickhouse/memory.xml and needs a server RESTART; these
// per-table settings do not.
//
// SAFETY / CONTRACT:
//   - deployment/docker/clickhouse/init.sql carries the identical values in the
//     CREATE TABLE ... SETTINGS clauses for FRESH installs; this file converges
//     LIVE deployments, exactly as corr_retention.go does for ttl_only_drop_parts.
//     tests/test_clickhouse_merge_budget.py pins the two together.
//   - ALTER TABLE ... MODIFY SETTING on a MergeTree setting is METADATA-ONLY:
//     it rewrites no part and launches no mutation. It only changes what the
//     background merge selector is allowed to pick next.
//   - Idempotent: re-applying the same values on every boot is a no-op
//     metadata write, like every other statement in ConvergeStmts.
//   - Lowering the cap NEVER splits an existing part. A part already larger
//     than the cap simply stops being a merge candidate — which is the point.

import "strconv"

// Merge-budget constants. Named so the arithmetic is readable at the call site
// and assertable from a test rather than being four magic integers.
const (
	// corrMergeCapObjects bounds corr_objects, the table that carries 86 % of
	// the family's uncompressed bytes and essentially all of the merge cost.
	corrMergeCapObjects = 2 * 1024 * 1024 * 1024 // 2 GiB = 2147483648

	// corrMergeCapDefault bounds every other corr_* table. They showed the same
	// level pathology at a smaller absolute size (levels 7,524 / 10,825 /
	// 11,848 / 33,082), so they get the same treatment one size down.
	corrMergeCapDefault = 1 * 1024 * 1024 * 1024 // 1 GiB = 1073741824

	// corrMergeForceAgeSeconds is the idle age after which a partition whose
	// parts are ALL older than it becomes eligible for one forced consolidation.
	corrMergeForceAgeSeconds = 600
)

// corrMergeBudgetTables is every correlation-family MergeTree table created by
// CorrSchemaDDL. Kept complete on purpose: a corr_* table with no merge cap is
// a table that can grow a level-30,000 part again, so the test asserts this
// list against the CREATE TABLE statements rather than trusting it.
func corrMergeBudgetTables() map[string]int64 {
	return map[string]int64{
		"corr_objects":          corrMergeCapObjects,
		"corr_signals":          corrMergeCapDefault,
		"corr_signals_archive":  corrMergeCapDefault,
		"corr_current":          corrMergeCapDefault,
		"corr_edges":            corrMergeCapDefault,
		"corr_evidence":         corrMergeCapDefault,
		"corr_tenant_write_amp": corrMergeCapDefault,
		"corr_path_edges":       corrMergeCapDefault,
	}
}

// CorrMergeBudgetDDL renders the converge statements that apply the merge
// budget to live deployments. Appended to the boot converge list AFTER
// CorrSchemaDDL — an ALTER that runs before its CREATE fails on a fresh volume
// (the F-58 ordering rule in ConvergeStmts).
//
// Table order is deterministic (not map order) so the emitted list is stable
// across boots and diffable in the converge log.
func CorrMergeBudgetDDL() []string {
	caps := corrMergeBudgetTables()
	// Deterministic order: corr_objects first (it is the one that matters), the
	// rest alphabetically.
	order := []string{
		"corr_objects",
		"corr_current",
		"corr_edges",
		"corr_evidence",
		"corr_path_edges",
		"corr_signals",
		"corr_signals_archive",
		"corr_tenant_write_amp",
	}
	stmts := make([]string, 0, len(order))
	for _, table := range order {
		capBytes, ok := caps[table]
		if !ok {
			continue
		}
		stmts = append(stmts,
			"ALTER TABLE netops."+table+" MODIFY SETTING "+
				"max_bytes_to_merge_at_max_space_in_pool = "+strconv.FormatInt(capBytes, 10)+", "+
				"min_age_to_force_merge_seconds = "+strconv.Itoa(corrMergeForceAgeSeconds)+", "+
				"min_age_to_force_merge_on_partition_only = 1")
	}
	return stmts
}
