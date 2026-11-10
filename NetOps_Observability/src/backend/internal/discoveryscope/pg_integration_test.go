// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package discoveryscope

// pg_integration_test.go — storage-layer proof for migration 0067, against a
// real PostgreSQL as a NOBYPASSRLS role: FORCE-RLS confines every statement to
// the tenant (a write as A, read as B, sees nothing; WITH CHECK refuses a B row
// under A's scope; a query that forgets its WHERE still sees one tenant), the
// CHECKs refuse a platform-owned or client-shaped row, an id is never held by
// two tenants, and the migration goes down and up again.

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
)

// provisionAppRole is the root package's helper of the same name (tests there
// are not importable from here): a clean schema and a non-superuser DSN.
func provisionAppRole(ctx context.Context, t *testing.T, adminDSN string) string {
	t.Helper()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() {
		if err := admin.Close(ctx); err != nil {
			t.Logf("admin close: %v", err)
		}
	}()
	const role, pass = "netops_app_test", "apppw"
	for _, s := range []string{
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') THEN EXECUTE 'DROP OWNED BY " + role + "'; END IF; END $do$",
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + pass + "' NOSUPERUSER",
		"GRANT ALL ON SCHEMA public TO " + role,
	} {
		if _, err := admin.Exec(ctx, s); err != nil {
			t.Fatalf("provision (%s): %v", s, err)
		}
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse adminDSN: %v", err)
	}
	u.User = url.UserPassword(role, pass)
	return u.String()
}

func pgFixture(t *testing.T) (*platformdb.PGStore, *PGStore) {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ps.DB().Close)
	return ps, NewPGStore(ps.DB())
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestDiscoveryScopesRLSIsolationPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	for _, sc := range []Scope{scope(sid(1), "t_a", "10.1.0.0/30"), scope(sid(2), "t_b", "10.2.0.0/30"), scope(sid(3), "t_a", "10.3.0.0/30")} {
		if err := st.Put(ctx, sc); err != nil {
			t.Fatalf("put %s: %v", sc.ID, err)
		}
	}
	ids := func(tenant string, cross bool) string {
		t.Helper()
		l, err := st.List(ctx, tenant, cross)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range l {
			out = append(out, s.ID[len(s.ID)-1:])
		}
		return strings.Join(out, ",")
	}
	if got := ids("t_a", false); got != "1,3" {
		t.Fatalf("RLS LEAK: t_a lists %q", got)
	}
	if got := ids("t_b", false); got != "2" {
		t.Fatalf("t_b lists %q", got)
	}
	if got := ids("t_c", false); got != "" {
		t.Fatalf("RLS LEAK: a tenant with no scans lists %q", got)
	}
	if got := ids("", true); got != "1,3,2" {
		t.Fatalf("the '*' read lists %q", got)
	}
	// Written as A, read as B: nothing.
	if _, found, err := st.Get(ctx, "t_b", false, sid(1)); err != nil || found {
		t.Fatalf("RLS LEAK: t_b read t_a's scan by id (%v, %v)", found, err)
	}
	if ok, err := st.Delete(ctx, "t_b", sid(1)); err != nil || ok {
		t.Fatalf("t_b deleted t_a's scan (%v, %v)", ok, err)
	}
	if got, found, err := st.Get(ctx, "t_a", false, sid(1)); err != nil || !found || got.TenantID != "t_a" || got.Ranges[0] != "10.1.0.0/30" {
		t.Fatalf("t_a's scan must survive and round-trip: %+v %v %v", got, found, err)
	}

	// RLS is the backstop even for a query that forgets its WHERE.
	var n int
	if err := ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM discovery_scopes`).Scan(&n)
	}); err != nil || n != 2 {
		t.Fatalf("an unfiltered read in t_a's scope counted %d rows (%v), want 2", n, err)
	}
	// WITH CHECK: a B row under A's scope is refused.
	err := ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO discovery_scopes (tenant_id, id, name, ranges) VALUES ('t_b', 'ds-00000000000000aa', 'x', '["10.9.0.0/30"]')`)
		return e
	})
	if pgCode(err) != "42501" {
		t.Fatalf("a write into another tenant must be RLS-denied (42501); got %v", err)
	}
	// Nor can A's scope rewrite B's row (USING hides it: zero rows).
	if err := ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE discovery_scopes SET name = 'pwned', tenant_id = 't_a' WHERE tenant_id = 't_b'`)
		if e == nil && tag.RowsAffected() != 0 {
			return errors.New("updated another tenant's row")
		}
		return e
	}); err != nil {
		t.Fatalf("cross-tenant update: %v", err)
	}
	// Re-homing one's own row into another tenant is refused by WITH CHECK.
	err = ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE discovery_scopes SET tenant_id = 't_b' WHERE id = $1`, sid(1))
		return e
	})
	if pgCode(err) != "42501" {
		t.Fatalf("moving a scan to another tenant must be RLS-denied (42501); got %v", err)
	}

	// An id held by one tenant is never filed under a second (UNIQUE (id)).
	if err := st.Put(ctx, scope(sid(2), "t_a", "10.9.0.0/30")); pgCode(err) != "23505" {
		t.Fatalf("an id another tenant holds must be refused (23505); got %v", err)
	}

	// The CHECKs refuse what the application never writes: a platform-owned
	// row, a client-shaped id, a non-array ranges.
	for name, q := range map[string]string{
		"platform owner": `INSERT INTO discovery_scopes (tenant_id, id, name, ranges) VALUES ('', 'ds-00000000000000b1', 'x', '[]')`,
		"global owner":   `INSERT INTO discovery_scopes (tenant_id, id, name, ranges) VALUES ('global', 'ds-00000000000000b2', 'x', '[]')`,
		"client id":      `INSERT INTO discovery_scopes (tenant_id, id, name, ranges) VALUES ('t_a', 'my-scope', 'x', '[]')`,
		"ranges object":  `INSERT INTO discovery_scopes (tenant_id, id, name, ranges) VALUES ('t_a', 'ds-00000000000000b3', 'x', '{}')`,
	} {
		err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, q); return e })
		if pgCode(err) != "23514" {
			t.Errorf("%s: want a CHECK violation (23514), got %v", name, err)
		}
	}

	// Update in place keeps the owner and the creation stamp.
	upd := scope(sid(1), "t_a", "10.1.0.4/30")
	upd.Name, upd.Enabled, upd.CreatedBy = "renamed", false, "someone-else"
	if err := st.Put(ctx, upd); err != nil {
		t.Fatal(err)
	}
	got, _, err := st.Get(ctx, "t_a", false, sid(1))
	if err != nil || got.Name != "renamed" || got.Enabled || got.CreatedBy != "admin" || got.Ranges[0] != "10.1.0.4/30" {
		t.Fatalf("update: %+v %v", got, err)
	}

	// The per-customer bound holds in the database transaction.
	for i := 10; i < 10+MaxPerTenant-2; i++ {
		if err := st.Put(ctx, scope(sid(i), "t_a", "10.4.0.0/30")); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if err := st.Put(ctx, scope(sid(99), "t_a", "10.4.0.0/30")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the per-customer bound must hold: %v", err)
	}
}

func TestDiscoveryScopesMigrationDownUpPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	if err := st.Put(ctx, scope(sid(1), "t_a", "10.1.0.0/30")); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../platformdb/migrations/rollback/0067_discovery_scopes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := ps.DB().BeginForTest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(down)); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.List(ctx, "", true); err == nil {
		t.Fatal("the table must be gone after the rollback")
	}
	// Re-apply: a fresh store run migrates it back (the schema_migrations row was removed).
	ps2, err := platformdb.NewPGStore(ctx, ps.DB().PoolForTest().Config().ConnString())
	if err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	t.Cleanup(ps2.DB().Close)
	if got, err := NewPGStore(ps2.DB()).List(ctx, "", true); err != nil || len(got) != 0 {
		t.Fatalf("after re-apply the table is back and empty: %v %v", got, err)
	}
}
