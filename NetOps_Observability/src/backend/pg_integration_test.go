//go:build pgintegration

package backend

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
//	# newPgDB fails CLOSED on a role that bypasses RLS (assertRLSCapable), and
//	# POSTGRES_USER is a superuser — so connect as a separate NOBYPASSRLS role.
//	# Connecting as 'netops' aborts every test with "bypasses Row-Level Security".
//	docker exec -i rdpg psql -U netops -d netops -v ON_ERROR_STOP=1 <<'SQL'
//	CREATE ROLE netops_app LOGIN PASSWORD 'apppw' NOBYPASSRLS;
//	GRANT CONNECT, CREATE ON DATABASE netops TO netops_app;
//	GRANT USAGE, CREATE ON SCHEMA public TO netops_app;
//	SQL
//	PG_TEST_DSN='postgres://netops_app:apppw@localhost:15432/netops' \
//	  go test -tags=pgintegration -count=1 -run TestPG ./...
//
// Because the role does NOT bypass RLS, the tenant_iso policies are live for the
// whole run: seeds and counts go through withTenant, and a bare pool query would
// legitimately see zero rows. That is the production shape, not a test artifact.
//
// This verifies the mechanism, not tenant isolation itself (which has its own
// dedicated tests — see org_isolation_test.go).
//
// CI: the `pg-integration` job in .github/workflows/backend-ci.yml.

import (
	"context"
	"fmt"
	"netops/backend/internal/audit"
	"netops/backend/internal/platformdb"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgIntegrationTenant is the tenant these tests stamp their rows with. Any
// non-empty value works — the sweeper runs cross-tenant ('*') — but a fixed,
// obviously-synthetic id keeps a stray row identifiable if one ever escapes a
// TRUNCATE into a shared database.
const pgIntegrationTenant = "pgintegration-test-tenant"

func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN not set — see the header of this file")
	}
	return dsn
}

// openPG builds a *platformdb.DB the production way (connect + migrate + apply the F-60
// runtime params). Any override of the timeout envs must be set BEFORE this.
func openPG(t *testing.T) *platformdb.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := platformdb.NewDB(ctx, pgDSN(t))
	if err != nil {
		t.Fatalf("newPgDB: %v", err)
	}
	t.Cleanup(db.Close)
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
	if err := db.PoolForTest().QueryRow(ctx, "SHOW statement_timeout").Scan(&shown); err != nil {
		t.Fatalf("SHOW statement_timeout: %v", err)
	}
	if shown != "1500ms" {
		t.Errorf("statement_timeout = %q, want 1500ms — the F-60 pool param did not reach the server", shown)
	}

	// (b) it actually cancels. A 5s sleep must die at ~1.5s, not run to completion.
	start := time.Now()
	_, err := db.PoolForTest().Exec(ctx, "SELECT pg_sleep(5)")
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
	if err := db.PoolForTest().QueryRow(context.Background(), "SHOW lock_timeout").Scan(&shown); err != nil {
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

	a, err := db.PoolForTest().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer a.Release()
	b, err := db.PoolForTest().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire B: %v", err)
	}
	defer b.Release()

	// A takes the migration lock (session-level, the same key migrate() uses).
	if _, err := a.Exec(ctx, "SELECT pg_advisory_lock($1)", platformdb.MigrationLockKeyForTest()); err != nil {
		t.Fatalf("A lock: %v", err)
	}
	// B must NOT be able to take it.
	var got bool
	if err := b.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", platformdb.MigrationLockKeyForTest()).Scan(&got); err != nil {
		t.Fatalf("B try-lock: %v", err)
	}
	if got {
		t.Fatal("second holder acquired the migration lock — it does NOT serialise; concurrent migrations could race")
	}
	// A releases; B can now take it.
	if _, err := a.Exec(ctx, "SELECT pg_advisory_unlock($1)", platformdb.MigrationLockKeyForTest()); err != nil {
		t.Fatalf("A unlock: %v", err)
	}
	if err := b.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", platformdb.MigrationLockKeyForTest()).Scan(&got); err != nil {
		t.Fatalf("B re-try: %v", err)
	}
	if !got {
		t.Error("after release the lock was still held — advisory lock did not free")
	}
	_, _ = b.Exec(ctx, "SELECT pg_advisory_unlock($1)", platformdb.MigrationLockKeyForTest())
}

// TestPGAuditCountAndOffsetPaging proves pgAuditStore.Count returns the true
// total and Offset paging returns the right window against a live table — the
// paths F-57/F-73 changed but never ran.
func TestPGAuditCountAndOffsetPaging(t *testing.T) {
	db := openPG(t)
	store := audit.NewPGStore(db, nil)
	ctx := context.Background()
	// clean slate for a deterministic count.
	if _, err := db.PoolForTest().Exec(ctx, "TRUNCATE audit_events"); err != nil {
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

// TestPGRetentionSweepDeletesOnlyOldRows proves audit.SweepRetention removes rows
// past the horizon and leaves fresh ones — the DELETE that was compile-reviewed
// only (and whose batching bounds a big purge).
func TestPGRetentionSweepDeletesOnlyOldRows(t *testing.T) {
	db := openPG(t)
	ctx := context.Background()
	if _, err := db.PoolForTest().Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// 3 OLD rows (100 days) + 2 FRESH rows (today). Retain 30 days.
	//
	// Inserted through withTenant, not a bare pool.Exec: audit_events has FORCE
	// ROW LEVEL SECURITY, and the tenant_iso policy's WITH CHECK reads
	// current_setting('app.tenant_id'). A raw INSERT on a pooled connection with
	// no GUC set is refused by the policy — FORCE means the table owner is not
	// exempt either. withTenant(cross=true) sets the '*' scope the sweeper
	// itself runs under.
	old := time.Now().UTC().AddDate(0, 0, -100)
	fresh := time.Now().UTC()
	seed := func(n int, ts time.Time, actor string) {
		t.Helper()
		if err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			for i := 0; i < n; i++ {
				if _, err := tx.Exec(ctx,
					`INSERT INTO audit_events (id, tenant_id, ts, data)
					 VALUES (gen_random_uuid()::text, $1, $2, $3)`,
					pgIntegrationTenant, ts,
					fmt.Sprintf(`{"actor":%q,"method":"GET","path":"/x","status":200,"decision":"allow"}`, actor),
				); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("insert %s: %v", actor, err)
		}
	}
	seed(3, old, "old")
	seed(2, fresh, "fresh")

	removed, err := audit.SweepRetention(ctx, db, 30)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 3 {
		t.Errorf("sweep removed %d rows, want 3 (the old ones only)", removed)
	}
	// Counted under the same cross-tenant scope, for the same reason the seed
	// inserts are: a bare pool query carries no app.tenant_id, so tenant_iso
	// filters every row out and the count reads 0 whether or not the sweep
	// behaved.
	var remaining int
	if err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&remaining)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 2 {
		t.Errorf("%d rows remain, want 2 (the fresh ones survived)", remaining)
	}
	// Idempotent: a second sweep removes nothing.
	if removed2, _ := audit.SweepRetention(ctx, db, 30); removed2 != 0 {
		t.Errorf("second sweep removed %d, want 0", removed2)
	}
}

// pgx import kept meaningful: withTenant callbacks take a pgx.Tx.
var _ = pgx.Tx(nil)

// ── SEC-011.2: the two ways FORCE-RLS is silently defeated ──────────────────

// TestAppRoleCannotBypassRLS asserts the properties the tenant-isolation
// guarantee actually rests on: the connected app role is not a superuser and
// does not hold BYPASSRLS. Either one would make every FORCE-RLS policy a
// no-op WITHOUT any error, log line, or failing query — isolation would
// simply stop being true. (Ownership is deliberately permitted: the app role
// owns its tables and runs migrations; FORCE RLS exists precisely to subject
// the owner to policy. BYPASSRLS and superuser are the two attributes FORCE
// cannot compensate for.)
func TestAppRoleCannotBypassRLS(t *testing.T) {
	db := openPG(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var super, bypass bool
	err := db.PoolForTest().QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).
		Scan(&super, &bypass)
	if err != nil {
		t.Fatalf("role introspection: %v", err)
	}
	if super {
		t.Fatal("the app role is a SUPERUSER — every RLS policy is silently void (SEC-011.2)")
	}
	if bypass {
		t.Fatal("the app role holds BYPASSRLS — FORCE RLS is silently void (SEC-011.2)")
	}
}
