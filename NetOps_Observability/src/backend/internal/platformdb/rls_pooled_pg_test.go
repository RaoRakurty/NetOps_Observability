// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package platformdb

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// rls_pooled_pg_test.go — tracker 312 against a real PostgreSQL: a pooled
// connection that ran a WithTenant transaction must NOT fall back to the blank
// tenant afterwards. Before the fix, current_setting('app.tenant_id', true) read
// '' for the life of that connection, so a query that forgot WithTenant matched
// every tenant_id = '' row (installation meters, platform rows). Runs with
// DATABASE_URL_TEST set (CI: the pg-integration job).

const rlsRole, rlsPassword = "netops_rls312_test", "rls312-password"

func rlsSetup(ctx context.Context, t *testing.T) *DB {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the pooled-connection RLS test")
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Best-effort teardown of a throwaway role on a throwaway database.
		_, _ = admin.Exec(cctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '"+rlsRole+"'")
		_, _ = admin.Exec(cctx, "DROP OWNED BY "+rlsRole)
		_, _ = admin.Exec(cctx, "DROP ROLE IF EXISTS "+rlsRole)
		_ = admin.Close(cctx)
	})
	for _, s := range []string{
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '" + rlsRole + "'",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + rlsRole + "') THEN EXECUTE 'DROP OWNED BY " + rlsRole + "'; END IF; END $do$",
		"DROP ROLE IF EXISTS " + rlsRole,
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
		"CREATE ROLE " + rlsRole + " LOGIN PASSWORD '" + rlsPassword + "' NOSUPERUSER NOBYPASSRLS",
		"GRANT ALL ON SCHEMA public TO " + rlsRole,
	} {
		if _, err := admin.Exec(ctx, s); err != nil {
			t.Fatalf("provision (%s): %v", s, err)
		}
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse adminDSN: %v", err)
	}
	u.User = url.UserPassword(rlsRole, rlsPassword)
	q := u.Query()
	if q.Get("sslmode") == "" {
		q.Set("sslmode", "disable")
	}
	u.RawQuery = q.Encode()
	db, err := NewDB(ctx, u.String())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(db.Close)

	// A table with EXACTLY the shape every tenant_iso policy has (migration 0013),
	// so the test exercises the policy predicate itself, not one table's quirks.
	for _, s := range []string{
		`CREATE TABLE rls312 (tenant_id text NOT NULL, v text NOT NULL)`,
		`ALTER TABLE rls312 ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE rls312 FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_iso ON rls312
		   USING (current_setting('app.tenant_id', true) = '*'
		       OR tenant_id = current_setting('app.tenant_id', true))
		   WITH CHECK (current_setting('app.tenant_id', true) = '*'
		       OR tenant_id = current_setting('app.tenant_id', true))`,
	} {
		if _, err := db.pool.Exec(ctx, s); err != nil {
			t.Fatalf("schema (%s): %v", s, err)
		}
	}
	if err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO rls312 (tenant_id, v) VALUES ('', 'installation'), ('t_a', 'a'), ('t_b', 'b')`)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return db
}

func countIn(ctx context.Context, t *testing.T, db *DB, tenant string, cross bool) int {
	t.Helper()
	var n int
	if err := db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM rls312`).Scan(&n)
	}); err != nil {
		t.Fatalf("WithTenant(%q, %v): %v", tenant, cross, err)
	}
	return n
}

// The leak itself: ONE pooled connection runs a WithTenant-shaped transaction,
// then a bare query on the SAME connection. It must read nothing — not the
// blank tenant's rows.
func TestPooledConnectionAfterWithTenantReadsNoRows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db := rlsSetup(ctx, t)

	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	// Fresh connection: the session default, never ''.
	var guc string
	if err := conn.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&guc); err != nil {
		t.Fatalf("read GUC: %v", err)
	}
	if guc != UnscopedTenant {
		t.Fatalf("a fresh pooled connection reads app.tenant_id = %q, want the %q sentinel", guc, UnscopedTenant)
	}

	// Exactly what WithTenant does, on this one connection.
	for _, scope := range []string{"t_a", "", "*"} {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, scope); err != nil {
			t.Fatalf("set_config: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		if err := conn.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&guc); err != nil {
			t.Fatalf("read GUC: %v", err)
		}
		if guc != UnscopedTenant {
			t.Fatalf("after a %q-scoped transaction the connection reads app.tenant_id = %q, want %q (the blank-tenant fallback)", scope, guc, UnscopedTenant)
		}
		var n int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM rls312`).Scan(&n); err != nil {
			t.Fatalf("bare count: %v", err)
		}
		if n != 0 {
			t.Fatalf("a bare query on a reused connection (after a %q-scoped transaction) read %d row(s), want 0", scope, n)
		}
	}

	// A bare write is refused too: neither the blank installation tenant nor a
	// real tenant can be written outside WithTenant.
	for _, tenant := range []string{"", "t_a"} {
		if _, err := conn.Exec(ctx, `INSERT INTO rls312 (tenant_id, v) VALUES ($1, 'bare')`, tenant); err == nil {
			t.Fatalf("a bare INSERT for tenant %q outside WithTenant was accepted", tenant)
		}
	}
}

// A rolled-back WithTenant transaction reverts to the sentinel as well.
func TestRolledBackWithTenantRevertsToTheSentinel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db := rlsSetup(ctx, t)
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM rls312`).Scan(&n); err != nil {
		t.Fatalf("bare count: %v", err)
	}
	if n != 0 {
		t.Fatalf("after a rolled-back blank-scope transaction a bare query read %d row(s), want 0", n)
	}
}

// The explicit scopes are unchanged: the blank (installation/platform) rows are
// still reachable through WithTenant with an explicit "" scope, a tenant sees
// only its own, and the platform owner ('*') sees all.
func TestExplicitScopesStillReachTheirRows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db := rlsSetup(ctx, t)
	for _, tc := range []struct {
		tenant string
		cross  bool
		want   int
	}{
		{"", false, 1},    // the blank installation tenant, by explicit scope
		{"t_a", false, 1}, // own rows only
		{"t_b", false, 1},
		{"t_nobody", false, 0},
		{"t_a", true, 3}, // cross = '*'
	} {
		if got := countIn(ctx, t, db, tc.tenant, tc.cross); got != tc.want {
			t.Errorf("WithTenant(%q, cross=%v) read %d row(s), want %d", tc.tenant, tc.cross, got, tc.want)
		}
	}
	// And an explicit blank scope may still WRITE the blank tenant's rows.
	if err := db.WithTenant(ctx, "", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO rls312 (tenant_id, v) VALUES ('', 'installation-2')`)
		return err
	}); err != nil {
		t.Fatalf("an explicit blank-scope write was refused: %v", err)
	}
}

// A DATABASE_URL that tries to set app.tenant_id cannot switch the fail-closed
// off: NewDB FORCES the sentinel rather than defaulting it (setDefaultParam is
// fill-if-absent, which an operator DSN would win).
func TestDSNCannotOverrideTheUnscopedSentinel(t *testing.T) {
	src, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\trp[tenantGUC] = UnscopedTenant\n") {
		t.Fatal("NewDB must FORCE app.tenant_id to UnscopedTenant (rp[tenantGUC] = UnscopedTenant), not default it")
	}
	if strings.Contains(string(src), "setDefaultParam(rp, tenantGUC") {
		t.Fatal("app.tenant_id must not go through setDefaultParam: a DSN option would override it")
	}
}
