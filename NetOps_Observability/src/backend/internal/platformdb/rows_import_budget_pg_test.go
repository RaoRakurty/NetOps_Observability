// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

// rows_import_budget_pg_test.go — the 2026-09-06 cutover failure, against a real
// PostgreSQL: a 5,000-row /data/audit.json must import inside the budget the
// formula gives it, and the batched multi-row INSERT must be measurably faster
// than the row-by-row Exec loop it replaced.
//
// Gated on DATABASE_URL_TEST like every other pg-backed test in this package, so
// the default `go test` stays offline.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// auditFixture renders n audit events in the exact shape the file backend's
// audit ring writes (JSON "tenant"/"time", not "tenant_id"/"ts").
func auditFixture(t *testing.T, n int) []byte {
	t.Helper()
	base := time.Date(2026, 9, 6, 15, 54, 0, 0, time.UTC)
	events := make([]map[string]any, 0, n)
	for i := range n {
		events = append(events, map[string]any{
			"id":     fmt.Sprintf("evt-%06d", i),
			"tenant": "acme",
			"time":   base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			"actor":  "operator@acme.example",
			"action": "device.update",
			"target": fmt.Sprintf("device-%04d", i%1000),
			"result": "ok",
			// Enough body that the file has a realistic size (a real trail
			// carries request context), and nothing that looks like a secret.
			"detail": fmt.Sprintf("changed monitoring profile on device-%04d (revision %d)", i%1000, i),
		})
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("render audit fixture: %v", err)
	}
	return raw
}

// TestFiveThousandRowAuditImportFitsItsBudgetPG is the regression: the exact
// collection that failed the lab's first cutover boot, imported end to end,
// timed against the budget the formula chose for it.
func TestFiveThousandRowAuditImportFitsItsBudgetPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the 5,000-row import-budget regression")
	}
	const rows = 5_000
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.Close()

	raw := auditFixture(t, rows)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit.json"), raw, 0o600); err != nil {
		t.Fatalf("write audit.json: %v", err)
	}
	budget := importBudget(len(raw), rows)

	// BEFORE / AFTER on the mechanism itself, measured against this database in
	// rolled-back transactions so neither measurement changes any state: the
	// row-by-row Exec loop the importer used to run, then the batched multi-row
	// INSERT that replaced it.
	perRow := timeInsert(ctx, t, ps, raw, false)
	perBatch := timeInsert(ctx, t, ps, raw, true)

	// AFTER, end to end: the real import path (explode → batched multi-row
	// INSERT → verify), bounded by the collection's own budget as a boot bounds it.
	start := time.Now()
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("a %d-row audit trail must import inside its %v budget, got: %v", rows, budget, err)
	}
	batched := time.Since(start)

	var got int
	if err := ps.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&got)
	}); err != nil {
		t.Fatalf("count audit_events: %v", err)
	}
	if got != rows {
		t.Errorf("imported %d audit events, want %d", got, rows)
	}
	if batched >= budget {
		t.Errorf("the import took %v of its %v budget — the budget no longer covers the work", batched, budget)
	}
	t.Logf("5,000-row audit trail (%d bytes), budget %v:\n"+
		"  insert  row-by-row %v → batched %v (%.1fx)\n"+
		"  end-to-end importFileState %v",
		len(raw), budget,
		perRow.Round(time.Millisecond), perBatch.Round(time.Millisecond),
		float64(perRow)/float64(perBatch), batched.Round(time.Millisecond))
	if perBatch > perRow {
		t.Errorf("batching made the insert SLOWER: %v vs %v row-by-row", perBatch, perRow)
	}

	// Idempotence survives the change: a second boot imports nothing.
	if err := ps.importFileState(ctx, dir); err != nil {
		t.Fatalf("second boot must be a no-op, got: %v", err)
	}
	if err := ps.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&got)
	}); err != nil {
		t.Fatalf("recount audit_events: %v", err)
	}
	if got != rows {
		t.Errorf("%d rows after the SECOND boot, want %d — the collection was imported twice", got, rows)
	}
}

// timeInsert measures the cost of writing the exploded rows into the real
// table, either the PRE-FIX way (one Exec per row, the loop replaceRowsTx used
// to run) or the batched way that replaced it. Both run inside a transaction
// that is ROLLED BACK, so a measurement changes no state and the two are
// directly comparable.
func timeInsert(ctx context.Context, t *testing.T, ps *PGStore, raw []byte, batched bool) time.Duration {
	t.Helper()
	spec, ok := specFor("/data/audit.json")
	if !ok {
		t.Fatal("no rowSpec for the audit trail")
	}
	values, err := explode(spec, raw)
	if err != nil {
		t.Fatalf("explode: %v", err)
	}
	// Deliberately NOT WithTenant: that commits, and a measurement must leave
	// nothing behind. Set the same RLS GUC by hand, insert, roll back.
	tx, err := ps.db.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin measurement tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // a measurement must leave no rows
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		t.Fatalf("measurement tenant scope: %v", err)
	}
	start := time.Now()
	if batched {
		if err := insertRowsTx(ctx, tx, spec, values); err != nil {
			t.Fatalf("batched insert: %v", err)
		}
		return time.Since(start)
	}
	for _, r := range values {
		ts := time.Now().UTC()
		if r.ts != nil {
			ts = *r.ts
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO "+spec.table+" (id, tenant_id, ts, data) VALUES ($1, $2, $3, $4)",
			r.id, r.tenant, ts, []byte(r.data)); err != nil {
			t.Fatalf("row-by-row insert: %v", err)
		}
	}
	return time.Since(start)
}
