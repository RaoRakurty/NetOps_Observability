// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package backend

// platform_alias_pg_test.go — migration 0062 (tracker 365) against a real
// Postgres, as the non-superuser app role so FORCE RLS bites.
//
// The Provider scope ('global', non-cross) must read the platform's rows in
// both spellings ('' and 'global') on the allowlisted DATA tables, a tenant
// scope must read neither, an IDENTITY table must never alias (a '' users row
// is the platform owner's account class), and WITH CHECK must still refuse a
// 'global' session filing a row under a real tenant.
//
// Gated on DATABASE_URL_TEST (a superuser DSN provisionAppRole drops and
// recreates the public schema on — never point it at a real database).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"testing"

	"netops/backend/internal/platformdb"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// platformAliasTables is the allowlist 0062 must cover — exactly. A table
// added to the migration without updating this list, or one silently dropped,
// fails TestPGPlatformAliasPolicyCatalogue.
var platformAliasTables = []string{
	"config_backup_versions",
	"config_drift_state",
	"incident_events",
	"incidents",
	"metering_daily",
	"saved_objects",
	"seam_groups",
	"seams",
	"topology_edges",
	"topology_nodes",
}

func platformAliasDB(t *testing.T) (*platformdb.DB, context.Context) {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the 0062 platform-alias RLS test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	t.Cleanup(func() { ps.DB().Close() })
	return ps.DB(), ctx
}

// The policy exists on every allowlisted table, on NO other table, and in
// particular on no identity/credential table.
func TestPGPlatformAliasPolicyCatalogue(t *testing.T) {
	db, ctx := platformAliasDB(t)
	var got []string
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tablename, permissive, qual, with_check FROM pg_policies
			WHERE schemaname='public' AND policyname='platform_alias' ORDER BY tablename`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tbl, perm, qual, check string
			if err := rows.Scan(&tbl, &perm, &qual, &check); err != nil {
				return err
			}
			if perm != "PERMISSIVE" {
				t.Errorf("%s: platform_alias is %s, want PERMISSIVE (it must OR with tenant_iso)", tbl, perm)
			}
			if qual != check {
				t.Errorf("%s: USING %q != WITH CHECK %q", tbl, qual, check)
			}
			got = append(got, tbl)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("read pg_policies: %v", err)
	}
	want := append([]string(nil), platformAliasTables...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("platform_alias on %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("platform_alias on %v, want exactly %v", got, want)
		}
	}
	for _, identity := range []string{"users", "user_identities", "user_identity_state", "api_keys", "snmp_credentials", "tenants"} {
		for _, g := range got {
			if g == identity {
				t.Fatalf("platform_alias must NEVER be on identity table %s", identity)
			}
		}
	}
}

// Behaviour on two representative data tables plus the identity negative.
func TestPGPlatformAliasScopes(t *testing.T) {
	db, ctx := platformAliasDB(t)
	body := json.RawMessage(`{"k":"v"}`)

	// Seed at '*' (the store's system-write scope): one row per owner spelling
	// plus a real tenant's row, in saved_objects, topology_nodes and users.
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range []struct{ id, tenant string }{
			{"so-blank", ""}, {"so-global", "global"}, {"so-acme", "t_acme"},
		} {
			if _, err := tx.Exec(ctx, `INSERT INTO saved_objects (id, tenant_id, type, data) VALUES ($1,$2,'report',$3)`, r.id, r.tenant, body); err != nil {
				return err
			}
		}
		for _, r := range []struct{ id, tenant string }{
			{"n-blank", ""}, {"n-global", "global"}, {"n-acme", "t_acme"},
		} {
			if _, err := tx.Exec(ctx, `INSERT INTO topology_nodes (tenant_id, id) VALUES ($1,$2)`, r.tenant, r.id); err != nil {
				return err
			}
		}
		for _, r := range []struct{ id, tenant string }{
			{"root", ""}, {"provider-admin", "global"}, {"acme-admin", "t_acme"},
		} {
			if _, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ($1,$2,$3)`, r.id, r.tenant, body); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	ids := func(scope string, cross bool, q string) []string {
		t.Helper()
		var out []string
		if err := db.WithTenant(ctx, scope, cross, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, q)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				out = append(out, id)
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("query %q at %q: %v", q, scope, err)
		}
		sort.Strings(out)
		return out
	}
	eq := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s = %v, want %v", name, got, want)
			return
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s = %v, want %v", name, got, want)
				return
			}
		}
	}
	const qSaved = `SELECT id FROM saved_objects`
	const qNodes = `SELECT id FROM topology_nodes`
	const qUsers = `SELECT id FROM users`

	// Provider scope: both platform spellings, never the tenant's row.
	eq("saved@global", ids("global", false, qSaved), []string{"so-blank", "so-global"})
	eq("nodes@global", ids("global", false, qNodes), []string{"n-blank", "n-global"})
	// A tenant scope sees neither platform spelling.
	eq("saved@t_acme", ids("t_acme", false, qSaved), []string{"so-acme"})
	eq("nodes@t_acme", ids("t_acme", false, qNodes), []string{"n-acme"})
	// Cross still sees everything.
	eq("saved@*", ids("", true, qSaved), []string{"so-acme", "so-blank", "so-global"})
	// IDENTITY: the '' user (the platform owner's account class) is NOT visible
	// under 'global' — only the Provider tenant's own account is.
	eq("users@global", ids("global", false, qUsers), []string{"provider-admin"})
	eq("users@t_acme", ids("t_acme", false, qUsers), []string{"acme-admin"})

	rlsDenied := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "42501"
	}
	asGlobal := func(fn func(tx pgx.Tx) error) error { return db.WithTenant(ctx, "global", false, fn) }

	// WITH CHECK: a 'global' session may NOT file a row under a real tenant…
	err = asGlobal(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO topology_nodes (tenant_id, id) VALUES ('t_acme','n-planted')`)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("'global' INSERT under t_acme must be RLS-denied (42501); got %v", err)
	}
	// …nor re-home a platform row into one…
	err = asGlobal(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE saved_objects SET tenant_id='t_acme' WHERE id='so-blank'`)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("'global' re-homing a platform row to t_acme must be RLS-denied (42501); got %v", err)
	}
	// …nor write a '' row on an identity table…
	err = asGlobal(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ('planted-root','',$1)`, body)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("'global' INSERT of a '' users row must be RLS-denied (42501); got %v", err)
	}
	// …nor reach the '' user to change it (USING hides it: zero rows).
	err = asGlobal(func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE users SET data='{"role":"hijacked"}' WHERE id='root'`)
		if e == nil && tag.RowsAffected() != 0 {
			t.Errorf("'global' UPDATE of the '' user affected %d rows, want 0", tag.RowsAffected())
		}
		return e
	})
	if err != nil {
		t.Fatalf("'global' UPDATE of the '' user: %v", err)
	}
	// Control: a 'global' session CAN write its own '' data row (it is its own).
	err = asGlobal(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO topology_nodes (tenant_id, id) VALUES ('','n-provider-new')`)
		return e
	})
	if err != nil {
		t.Fatalf("'global' INSERT of its own '' data row should succeed; got %v", err)
	}
	// A tenant scope still may not write a '' row (alias is 'global'-only).
	err = db.WithTenant(ctx, "t_acme", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO topology_nodes (tenant_id, id) VALUES ('','n-tenant-planted')`)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("tenant INSERT of a '' row must be RLS-denied (42501); got %v", err)
	}
}

// Rollback removes the alias (and only the alias): the Provider scope is back
// to 'global' rows only and tenant_iso is intact.
func TestPGPlatformAliasRollback(t *testing.T) {
	db, ctx := platformAliasDB(t)
	down, err := os.ReadFile("internal/platformdb/migrations/rollback/0062_platform_owner_alias.down.sql")
	if err != nil {
		t.Fatalf("read rollback: %v", err)
	}
	if err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO topology_nodes (tenant_id, id) VALUES ('','n-blank'),('global','n-global')`)
		return e
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, string(down))
		return e
	}); err != nil {
		t.Fatalf("apply rollback: %v", err)
	}
	var policies, applied int
	var visible []string
	if err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_policies WHERE schemaname='public' AND policyname='platform_alias'`).Scan(&policies); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version='0062_platform_owner_alias.sql'`).Scan(&applied)
	}); err != nil {
		t.Fatalf("inspect after rollback: %v", err)
	}
	if policies != 0 || applied != 0 {
		t.Fatalf("after rollback: %d platform_alias policies, %d schema_migrations rows; want 0, 0", policies, applied)
	}
	if err := db.WithTenant(ctx, "global", false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM topology_nodes ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			visible = append(visible, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
	if len(visible) != 1 || visible[0] != "n-global" {
		t.Fatalf("after rollback 'global' sees %v, want [n-global] (tenant_iso only)", visible)
	}
}
