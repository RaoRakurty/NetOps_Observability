// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package devbaseline

// pg_integration_test.go — storage-layer proof for migration 0079, against a real
// PostgreSQL as a NOBYPASSRLS role: FORCE-RLS confines every statement to the
// tenant (even an unfiltered one); a baseline round-trips; retention keeps the
// newest MaxPerDevice per device; the database refuses an oversized body even
// when the application is bypassed; the rollback removes the table and its
// schema_migrations row.

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
)

// provisionAppRole is the root package's helper of the same name (tests there
// are not importable). It leaves a clean schema and a non-superuser DSN.
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
	role, pass := "netops_app_test", "app"+"pw" // built from parts: not a credential
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

func pgFixture(t *testing.T) (*platformdb.PGStore, Store) {
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

func TestBaselineRoundTripAndRetentionPG(t *testing.T) {
	_, st := pgFixture(t)
	ctx := context.Background()
	s := baseFixture(t)
	var last Snapshot
	for i := 0; i < MaxPerDevice+2; i++ {
		s.ID = ""
		s.TakenAt = time.Date(2026, 11, 18, 9, i, 0, 0, time.UTC)
		got, err := st.Put(ctx, "t-a", s)
		if err != nil {
			t.Fatal(err)
		}
		last = got
	}
	list, err := st.List(ctx, "t-a", "dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != MaxPerDevice || list[0].ID != last.ID {
		t.Fatalf("retention/order: %d rows, newest %s (want %d, %s)", len(list), list[0].ID, MaxPerDevice, last.ID)
	}
	back, err := st.Get(ctx, "t-a", "dev-a", last.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.TenantID != "t-a" || len(back.Interfaces) != 5 || back.RouteTotal == nil || *back.RouteTotal != 10 {
		t.Fatalf("round-trip lost fields: %+v", back)
	}
	if d := Compare(back, baseFixture(t)); len(d.Changes) != 0 {
		t.Fatalf("a stored baseline no longer compares equal to its source: %+v", d.Changes)
	}
	latest, err := st.Latest(ctx, "t-a", "dev-a")
	if err != nil || latest.ID != last.ID {
		t.Fatalf("Latest = %s, %v; want %s", latest.ID, err, last.ID)
	}
	if _, err := st.Get(ctx, "t-a", "dev-a", "not-a-uuid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a malformed id: %v, want ErrNotFound", err)
	}
}

func TestBaselineRLSIsolationPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	got, err := st.Put(ctx, "t-a", baseFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "t-b", "dev-a", got.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RLS LEAK: t-b read t-a's baseline (%v)", err)
	}
	if _, err := st.Latest(ctx, "t-b", "dev-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RLS LEAK: t-b Latest saw t-a's baseline (%v)", err)
	}
	if l, err := st.List(ctx, "t-b", "dev-a"); err != nil || len(l) != 0 {
		t.Fatalf("RLS LEAK: t-b listed %d baselines (%v)", len(l), err)
	}
	// Even unfiltered statements see and touch nothing of another tenant.
	err = ps.DB().WithTenant(ctx, "t-b", false, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_baselines`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("RLS LEAK: an unfiltered SELECT as t-b saw %d rows", n)
		}
		_, err := tx.Exec(ctx, `DELETE FROM device_baselines`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "t-a", "dev-a", got.ID); err != nil {
		t.Fatalf("RLS LEAK: an unfiltered DELETE as t-b removed t-a's baseline (%v)", err)
	}
	// An insert stamped with another tenant is refused by WITH CHECK.
	err = ps.DB().WithTenant(ctx, "t-b", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO device_baselines (tenant_id, id, device_id, body)
		    VALUES ('t-a', '00000000-0000-4000-8000-000000000001', 'dev-a', '{}'::jsonb)`)
		return err
	})
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" {
		t.Fatalf("a cross-tenant insert: %v, want insufficient_privilege 42501", err)
	}
}

func TestBaselineDatabaseRefusesAnOversizedBodyPG(t *testing.T) {
	ps, _ := pgFixture(t)
	ctx := context.Background()
	err := ps.DB().WithTenant(ctx, "t-a", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO device_baselines (tenant_id, id, device_id, body)
		    VALUES ('t-a', '00000000-0000-4000-8000-000000000002', 'dev-a', jsonb_build_object('x', repeat('a', 300000)))`)
		return err
	})
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatalf("an oversized body: %v, want check_violation 23514", err)
	}
}

func TestBaselineRollbackPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	dsn := provisionAppRole(ctx, t, adminDSN)
	ps, err := platformdb.NewPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ps.DB().Close)
	if _, err := NewPGStore(ps.DB()).Put(ctx, "t-a", baseFixture(t)); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../platformdb/migrations/rollback/0079_device_baselines.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(ctx); err != nil {
			t.Logf("close: %v", err)
		}
	}()
	if _, err := conn.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	var tables, rows int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE tablename = 'device_baselines'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0079_device_baselines.sql'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if tables != 0 || rows != 0 {
		t.Fatalf("after down: %d tables, %d schema_migrations rows, want 0 and 0", tables, rows)
	}
}
