// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

// rows_import_budget.go — how long ONE collection is allowed to take to import.
//
// THE INCIDENT (lab, 2026-09-06 15:54 UTC, the real file→Postgres cutover).
// The api's first boot with STORE_BACKEND=postgres + IMPORT_FILE_STATE_DIR=/data
// logged
//
//	store backend: file-state import: import /data/audit.json: context deadline exceeded
//
// after importing six small collections. It failed CLOSED (correct — a
// half-imported control plane that boots looks exactly like a complete one),
// the container restarted, and the second boot — with those six already marked
// done — imported /data/audit.json (5,000 rows) and the rest in ~10 s and came
// up healthy.
//
// Nothing was wrong with the audit trail. What was wrong was the SHAPE of the
// bound: ONE flat 30 s context in main's initStoreBackend covered connect +
// migrate + the legacy import + EVERY file-state collection, so the budget any
// individual collection got was "30 s minus whatever the collections before it
// happened to use". That is not a timeout, it is a race: the same install boots
// or does not depending on how loaded the host is and what order the work fell
// in. A customer with a large audit trail sees a boot loop that only clears by
// luck, one collection per restart.
//
// THE RULE: a bound must be proportional to the work it bounds. Each collection
// now gets its own deadline, derived from that collection's own size, and the
// budget is LOGGED next to the row count so an operator can see what was
// allowed and what it took.
//
//	budget = min(ceiling, base + perRecord*records + perMiB*ceil(bytes/MiB))
//
//	base      30s   fixed cost: marker lookup, the populated-target count under
//	                RLS, the transaction, the post-import verification count
//	perRecord 5ms   per decoded record. DELIBERATELY ~50x the batched-insert
//	                cost measured on the lab's 4-core host — the budget exists
//	                to catch a WEDGE, not to police throughput.
//	perMiB    2s    per MiB of file: parse + JSONB write cost that scales with
//	                bytes rather than record count (large documents, sealed
//	                blobs, the device per-record subtree).
//	ceiling   10m   an absolute upper bound so a corrupt length can never turn
//	                into an unbounded boot (§9: all IO must have a timeout).
//
// Worked example — the collection that broke: /data/audit.json, 5,000 records,
// ~3 MiB → 30s + 25s + 6s = 61s, against a measured ~1 s import after batching.
// The floor IS `base`: every other term is non-negative.
//
// The budget is a CHILD of the caller's context, so it can only ever shorten,
// never extend, the boot-wide bound.

import (
	"context"
	"time"
)

const (
	// importBudgetBase is the fixed per-collection cost (see the formula above).
	importBudgetBase = 30 * time.Second
	// importBudgetPerRecord is the per-decoded-record allowance.
	importBudgetPerRecord = 5 * time.Millisecond
	// importBudgetPerMiB is the per-MiB-of-file allowance.
	importBudgetPerMiB = 2 * time.Second
	// importBudgetCeiling is the absolute upper bound for ONE collection.
	importBudgetCeiling = 10 * time.Minute

	mib = 1 << 20
)

// importBudget returns the deadline one collection of `records` decoded records
// in `sizeBytes` on disk is allowed. Pure, so the formula is testable without a
// database and an operator can reproduce the number in the log line.
//
// Negative inputs (impossible from a file read, cheap to refuse) contribute
// nothing rather than shortening the budget.
func importBudget(sizeBytes, records int) time.Duration {
	budget := importBudgetBase
	if records > 0 {
		budget += time.Duration(records) * importBudgetPerRecord
	}
	if sizeBytes > 0 {
		// Round UP: a 1-byte file still buys its first MiB of allowance.
		budget += time.Duration((sizeBytes+mib-1)/mib) * importBudgetPerMiB
	}
	if budget > importBudgetCeiling {
		return importBudgetCeiling
	}
	return budget
}

// importWithBudget runs one collection's import under its own work-proportional
// deadline and returns the budget it chose, so the caller can log it alongside
// the row count. fn owns everything that touches the database for that
// collection — the marker lookup, the populated-target decision, the write and
// the verification — because a wedge in any of them is the same boot failure.
//
// It never extends the parent: context.WithTimeout takes the EARLIER of the two
// deadlines, so a boot-wide bound still caps the whole phase.
func importWithBudget(ctx context.Context, sizeBytes, records int, fn func(context.Context) error) (time.Duration, error) {
	budget := importBudget(sizeBytes, records)
	bctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return budget, fn(bctx)
}
