// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

// rows_import_budget_test.go — the 2026-09-06 boot-loop regression.
//
// The lab's real file→Postgres cutover failed its first boot with
//
//	file-state import: import /data/audit.json: context deadline exceeded
//
// because ONE flat 30 s context covered the whole boot, so a collection's
// budget was whatever the collections before it had left over. What is proved
// here: the budget is derived from the WORK (so a 5,000-row collection gets a
// deadline a 5,000-row collection can meet, even against a deliberately slow
// store), it GROWS with rows, and it stays inside an absolute ceiling.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestImportBudgetScalesWithRows — the property the flat constant did not have.
// A bigger collection must get a bigger budget, monotonically.
func TestImportBudgetScalesWithRows(t *testing.T) {
	small := importBudget(1024, 10)
	medium := importBudget(1024, 5_000)
	large := importBudget(1024, 50_000)
	if !(small < medium && medium < large) {
		t.Errorf("budget must grow with rows: 10=%v 5000=%v 50000=%v", small, medium, large)
	}
	// The per-row term is the formula's, not an approximation of it.
	if got, want := medium-small, time.Duration(5_000-10)*importBudgetPerRecord; got != want {
		t.Errorf("per-row growth = %v, want %v", got, want)
	}
	// And with bytes, independently of rows.
	if a, b := importBudget(1*mib, 100), importBudget(9*mib, 100); !(a < b) {
		t.Errorf("budget must grow with file size: 1MiB=%v 9MiB=%v", a, b)
	}
	if got, want := importBudget(9*mib, 100)-importBudget(1*mib, 100), 8*importBudgetPerMiB; got != want {
		t.Errorf("per-MiB growth = %v, want %v", got, want)
	}
}

// TestImportBudgetFloorAndCeiling — never shorter than the fixed per-collection
// cost, never unbounded. A corrupt length must not turn into an endless boot.
func TestImportBudgetFloorAndCeiling(t *testing.T) {
	for _, tc := range []struct{ bytes, rows int }{{0, 0}, {-1, -1}, {1, 0}, {0, 1}} {
		if got := importBudget(tc.bytes, tc.rows); got < importBudgetBase {
			t.Errorf("importBudget(%d,%d) = %v, must never be below the base %v",
				tc.bytes, tc.rows, got, importBudgetBase)
		}
	}
	if got := importBudget(1<<40, 100_000_000); got != importBudgetCeiling {
		t.Errorf("a huge collection must clamp to the ceiling %v, got %v", importBudgetCeiling, got)
	}
	// The collection that actually broke: 5,000 audit rows in ~3 MiB.
	audit := importBudget(3*mib, 5_000)
	if audit <= 30*time.Second {
		t.Errorf("the 5,000-row audit trail must get MORE than the old flat 30s, got %v", audit)
	}
	if audit > importBudgetCeiling {
		t.Errorf("budget %v exceeds the ceiling %v", audit, importBudgetCeiling)
	}
}

// slowStore is a deliberately slow fake: every batch of inserts costs real time.
// It stands in for a loaded 4-core host, which is what the lab's cutover ran on.
type slowStore struct {
	perRow    time.Duration
	batchSize int
	rows      int
}

// importRows simulates writing n rows in batches, honouring cancellation the way
// pgx does (every Exec checks the context). It returns ctx.Err() if the budget
// runs out mid-collection — which is EXACTLY the live failure.
func (s *slowStore) importRows(ctx context.Context, n int) error {
	for done := 0; done < n; {
		batch := min(s.batchSize, n-done)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(batch) * s.perRow):
		}
		done += batch
		s.rows += batch
	}
	return nil
}

// TestImportWithBudgetCompletesFiveThousandRows — the regression proper. A
// 5,000-row collection imported through a store slowed to 100 µs per row
// (500 ms of pure database time, ~50x the batched cost measured against the
// lab's Postgres) finishes inside the budget the formula chose for it, with
// room to spare.
func TestImportWithBudgetCompletesFiveThousandRows(t *testing.T) {
	const rows = 5_000
	store := &slowStore{perRow: 100 * time.Microsecond, batchSize: 500}
	var deadline time.Time
	start := time.Now()
	budget, err := importWithBudget(context.Background(), 3*mib, rows, func(ctx context.Context) error {
		d, ok := ctx.Deadline()
		if !ok {
			return errors.New("the import ran with NO deadline — every IO must be bounded (§9)")
		}
		deadline = d
		return store.importRows(ctx, rows)
	})
	took := time.Since(start)
	if err != nil {
		t.Fatalf("a %d-row collection must import inside its own budget, got: %v", rows, err)
	}
	if store.rows != rows {
		t.Errorf("imported %d rows, want %d", store.rows, rows)
	}
	if took >= budget {
		t.Errorf("took %v of a %v budget — the budget is not proportional to the work", took, budget)
	}
	// The deadline handed to the store IS the budget (not the parent's, not
	// infinity): the collection is bounded on its own terms.
	if got := time.Until(deadline) + took; got < budget-time.Second || got > budget+time.Second {
		t.Errorf("the store saw a %v deadline, want the %v budget", got.Round(time.Second), budget)
	}
}

// TestImportWithBudgetFailsClosedWhenTheStoreWedges — the other half of the
// contract: a store that never finishes must not hang the boot for ever. The
// caller's own bound still caps the budget (WithTimeout takes the earlier
// deadline), and the error surfaces rather than being swallowed.
func TestImportWithBudgetFailsClosedWhenTheStoreWedges(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	store := &slowStore{perRow: time.Second, batchSize: 1} // never finishes in time
	_, err := importWithBudget(parent, 3*mib, 5_000, func(ctx context.Context) error {
		return store.importRows(ctx, 5_000)
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a wedged store must fail closed with a deadline error, got %v", err)
	}
}

// ---- the batched multi-row INSERT ------------------------------------------
//
// The importer used to Exec once PER ROW: 5,000 round trips and 5,000
// parse/plans for the audit trail. These pin the batching that replaced it.

func TestBuildInsertSQLRendersOneStatementPerBatch(t *testing.T) {
	got := buildInsertSQL("audit_events", []string{"id", "tenant_id", "ts", "data"}, 3)
	want := "INSERT INTO audit_events (id, tenant_id, ts, data) VALUES " +
		"($1, $2, $3, $4), ($5, $6, $7, $8), ($9, $10, $11, $12)"
	if got != want {
		t.Errorf("buildInsertSQL:\n got %s\nwant %s", got, want)
	}
	// Every value is a bind parameter — nothing is interpolated (§8).
	if strings.Contains(got, "'") {
		t.Errorf("a rendered INSERT must carry no literals: %s", got)
	}
}

// TestRowColumnsMatchTheArgumentCount — the shapes and their extractors are
// generated from ONE switch precisely so they cannot drift; this proves it for
// every registered spec, including the ts default.
func TestRowColumnsMatchTheArgumentCount(t *testing.T) {
	ts := time.Date(2026, 9, 6, 15, 54, 0, 0, time.UTC)
	for name, spec := range rowSpecs {
		cols, args := rowColumns(spec)
		for _, r := range []rowValue{
			{id: "a", tenant: "acme", typ: "dashboard", data: []byte(`{"id":"a"}`)},
			{id: "b", tenant: "acme", typ: "dashboard", ts: &ts, data: []byte(`{"id":"b"}`)},
		} {
			if got := args(r); len(got) != len(cols) {
				t.Errorf("%s: %d arguments for %d columns %v", name, len(got), len(cols), cols)
			}
		}
		if len(cols) == 0 {
			t.Errorf("%s: no columns", name)
		}
	}
	// audit_events with no timestamp in the file still gets one (default now()).
	_, args := rowColumns(rowSpecs["audit"])
	if v := args(rowValue{id: "x"})[2]; v == (time.Time{}) {
		t.Error("audit rows must carry a non-zero ts even when the file has none")
	}
}

// TestImportInsertBatchRowsStaysUnderThePgBindLimit — PostgreSQL refuses more
// than 65535 bind parameters in one message; exceeding it would turn a large
// import into a hard failure instead of a fast one.
func TestImportInsertBatchRowsStaysUnderThePgBindLimit(t *testing.T) {
	for cols := 1; cols <= 16; cols++ {
		n := importInsertBatchRows(cols)
		if n < 1 {
			t.Errorf("%d columns: batch of %d rows", cols, n)
		}
		if n*cols > pgMaxBindParams {
			t.Errorf("%d columns x %d rows = %d bind params, over the %d limit",
				cols, n, n*cols, pgMaxBindParams)
		}
	}
	if got := importInsertBatchRows(0); got != 1 {
		t.Errorf("a zero-column spec must not produce a zero-row batch, got %d", got)
	}
	// 5,000 audit rows (4 columns) must collapse into a handful of statements,
	// not 5,000 of them.
	if stmts := (5_000 + importInsertBatchRows(4) - 1) / importInsertBatchRows(4); stmts > 20 {
		t.Errorf("a 5,000-row import still takes %d statements", stmts)
	}
}
