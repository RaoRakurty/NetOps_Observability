//go:build pgintegration

package main

// pg_integration_test.go — exercises the Postgres-dependent paths that were
// COMPILE-REVIEWED ONLY (INVARIANTS.md standing gap #4): the F-60 pool bounds
// (statement_timeout / lock_timeout), the migration advisory lock, the audit
// store's Count/Offset paging, and the retention sweeper's batched DELETE. None
// of these had ever run against a real database.
//
// Build-tagged so the default `go test ./...` stays hermetic. Run it with a
// disposable Postgres pinned to the deployed version:
//
//	docker run -d --rm --name rdpg -p 15432:5432 \
//	  -e POSTGRES_USER=netops -e POSTGRES_PASSWORD=pgpw -e POSTGRES_DB=netops \
//	  --tmpfs /var/lib/postgresql/data \
//	  postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229
//	PG_TEST_DSN='postgres://netops:pgpw@localhost:15432/netops' \
//	  go test -tags=pgintegration -run TestPG ./...
//
// This verifies the mechanism, not tenant isolation (which has its own tests and
// requires a non-superuser role — see the newPgDB RLS note).

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN not set — see the header of this file")
	}
	return dsn
}

// openPG builds a *pgDB the production way (connect + migrate + apply the F-60
// runtime params). Any override of the timeout envs must be set BEFORE this.
func openPG(t *testing.T) *pgDB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := newPgDB(ctx, pgDSN(t))
	if err != nil {
		t.Fatalf("newPgDB: %v", err)
	}
	t.Cleanup(db.close)
	return db
}

// TestPGStatementTimeoutIsApplied proves the F-60 statement_timeout is actually
// set on pooled connections AND actually cancels a runaway query — not merely
// present in the pool config struct.
func TestPGStatementTimeoutIsApplied(t *testing.T) {
	pgDSN(t)
	t.Setenv("PG_STATEMENT_TIMEOUT", "1500ms") // headroom for migrations, short enough to test
	db := openPG(t)
	ctx := context.Background()

	// (a) the param reached the server.
	var shown string
	if err := db.pool.QueryRow(ctx, "SHOW statement_timeout").Scan(&shown); err != nil {
		t.Fatalf("SHOW statement_timeout: %v", err)
	}
	if shown != "1500ms" {
		t.Errorf("statement_timeout = %q, want 1500ms — the F-60 pool param did not reach the server", shown)
	}

	// (b) it actually cancels. A 5s sleep must die at ~1.5s, not run to completion.
	start := time.Now()
	_, err := db.pool.Exec(ctx, "SELECT pg_sleep(5)")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("pg_sleep(5) completed — statement_timeout did NOT cancel a runaway query")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "statement timeout") &&
		!strings.Contains(strings.ToLower(err.Error()), "canceling") {
		t.Errorf("query failed with %v, want a statement-timeout cancellation", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("runaway query ran %v before dying — the 1.5s bound was not enforced", elapsed)
	}
}

// TestPGLockTimeoutIsApplied proves lock_timeout reached the server too.
func TestPGLockTimeoutIsApplied(t *testing.T) {
	pgDSN(t)
	t.Setenv("PG_LOCK_TIMEOUT", "2500ms")
	db := openPG(t)
	var shown string
	if err := db.pool.QueryRow(context.Background(), "SHOW lock_timeout").Scan(&shown); err != nil {
		t.Fatalf("SHOW lock_timeout: %v", err)
	}
	if shown != "2500ms" {
		t.Errorf("lock_timeout = %q, want 2500ms", shown)
	}
}

// TestPGMigrationAdvisoryLockSerialises proves the migration advisory lock does
// what it is for: a second holder is BLOCKED while the first holds it. The
// migration path used pg_advisory_lock (which waits); this uses the try-form to
// assert the lock is genuinely exclusive on the same key.
func TestPGMigrationAdvisoryLockSerialises(t *testing.T) {
	db := openPG(t)
	ctx := context.Background()

	a, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer a.Release()
	b, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire B: %v", err)
	}
	defer b.Release()

	// A takes the migration lock (session-level, the same key migrate() uses).
	if _, err := a.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		t.Fatalf("A lock: %v", err)
	}
	// B must NOT be able to take it.
	var got bool
	if err := b.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", migrationLockKey).Scan(&got); err != nil {
		t.Fatalf("B try-lock: %v", err)
	}
	if got {
		t.Fatal("second holder acquired the migration lock — it does NOT serialise; concurrent migrations could race")
	}
	// A releases; B can now take it.
	if _, err := a.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey); err != nil {
		t.Fatalf("A unlock: %v", err)
	}
	if err := b.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", migrationLockKey).Scan(&got); err != nil {
		t.Fatalf("B re-try: %v", err)
	}
	if !got {
		t.Error("after release the lock was still held — advisory lock did not free")
	}
	_, _ = b.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey)
}

// TestPGAuditCountAndOffsetPaging proves pgAuditStore.Count returns the true
// total and Offset paging returns the right window against a live table — the
// paths F-57/F-73 changed but never ran.
func TestPGAuditCountAndOffsetPaging(t *testing.T) {
	db := openPG(t)
	store := &pgAuditStore{db: db}
	ctx := context.Background()
	// clean slate for a deterministic count.
	if _, err := db.pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	const n = 12
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < n; i++ {
		store.Record(AuditEvent{
			ID: "", Time: base.Add(time.Duration(i) * time.Minute),
			Actor: "tester", Method: "GET", Path: "/api/probe",
			Status: 200, Decision: "allow",
		})
	}

	if got := store.Count("", true, auditQuery{}); got != n {
		t.Errorf("Count = %d, want %d (the TRUE total, not a capped page)", got, n)
	}
	// A window of 5 at offset 5 must return exactly 5 distinct rows, none shared
	// with the first page.
	page1, err := store.List("", true, auditQuery{Limit: 5, Offset: 0})
	if err != nil {
		t.Fatalf("List page1: %v", err)
	}
	page2, err := store.List("", true, auditQuery{Limit: 5, Offset: 5})
	if err != nil {
		t.Fatalf("List page2: %v", err)
	}
	if len(page1) != 5 || len(page2) != 5 {
		t.Fatalf("page sizes = %d,%d, want 5,5", len(page1), len(page2))
	}
	seen := map[string]bool{}
	for _, e := range page1 {
		seen[e.ID] = true
	}
	for _, e := range page2 {
		if seen[e.ID] {
			t.Errorf("offset paging returned a DUPLICATE row across pages: %s", e.ID)
		}
	}
}

// TestPGRetentionSweepDeletesOnlyOldRows proves sweepAuditRetention removes rows
// past the horizon and leaves fresh ones — the DELETE that was compile-reviewed
// only (and whose batching bounds a big purge).
func TestPGRetentionSweepDeletesOnlyOldRows(t *testing.T) {
	db := openPG(t)
	ctx := context.Background()
	if _, err := db.pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// 3 OLD rows (100 days) + 2 FRESH rows (today). Retain 30 days.
	old := time.Now().UTC().AddDate(0, 0, -100)
	fresh := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if _, err := db.pool.Exec(ctx,
			`INSERT INTO audit_events (id, ts, actor, method, path, status, decision)
			 VALUES (gen_random_uuid(), $1, 'old', 'GET', '/x', 200, 'allow')`, old); err != nil {
			t.Fatalf("insert old: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := db.pool.Exec(ctx,
			`INSERT INTO audit_events (id, ts, actor, method, path, status, decision)
			 VALUES (gen_random_uuid(), $1, 'fresh', 'GET', '/x', 200, 'allow')`, fresh); err != nil {
			t.Fatalf("insert fresh: %v", err)
		}
	}

	removed, err := sweepAuditRetention(ctx, db, 30)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 3 {
		t.Errorf("sweep removed %d rows, want 3 (the old ones only)", removed)
	}
	var remaining int
	if err := db.pool.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 2 {
		t.Errorf("%d rows remain, want 2 (the fresh ones survived)", remaining)
	}
	// Idempotent: a second sweep removes nothing.
	if removed2, _ := sweepAuditRetention(ctx, db, 30); removed2 != 0 {
		t.Errorf("second sweep removed %d, want 0", removed2)
	}
}

// pgx import kept meaningful: withTenant callbacks take a pgx.Tx.
var _ = pgx.Tx(nil)
