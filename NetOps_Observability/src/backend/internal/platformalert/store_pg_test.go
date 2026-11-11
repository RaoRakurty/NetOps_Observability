// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package platformalert

// store_pg_test.go — the record against a REAL Postgres through the platform
// kv (app_kv), as the Postgres backend runs it in production: written as the
// NOBYPASSRLS app role, sealed at rest, read back by a second store (a second
// api replica). Runs in CI's pg-integration leg: DATABASE_URL_TEST is the
// superuser DSN, and the test provisions its own app role on a clean schema
// (the house pattern). The shared PG_TEST_DSN role cannot be used here: another
// package's test may have recreated the schema under a different owner, and
// the migration then fails with "permission denied for table schema_migrations".

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + pass + "' NOSUPERUSER NOBYPASSRLS",
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

func TestStoreRoundTripOnPostgres(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute) // a fresh database runs every migration first
	defer cancel()
	pg, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	t.Cleanup(pg.DB().Close) // a lingering app-role pool would hold the next package's schema reset
	key := "/data/platform_alert_route.pgtest-" + time.Now().UTC().Format("150405.000000000") + ".json"
	deps := StoreDeps{Key: key, Load: pg.Load, Save: pg.Save, Seal: fakeSeal, Open: fakeOpen}

	s := NewStore(deps)
	if ok, everRead := s.Health(); !ok || !everRead || s.Current().PageRouted() {
		t.Fatal("an absent row must read as the empty default, not a failure")
	}
	c := validNtfyOnly()
	c.Ntfy.Token = fakeSecret("pg-ntfy")
	c.SMS = validSMSOnly().SMS
	if err := s.Save(c, false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := pg.Load(key)
	if err != nil {
		t.Fatalf("raw Load: %v", err)
	}
	for _, secret := range []string{c.Ntfy.Token, c.SMS.AuthToken} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("a secret is stored in the clear in app_kv: %s", raw)
		}
	}
	replica := NewStore(deps)
	got := replica.Current()
	if got.Ntfy.Token != c.Ntfy.Token || got.SMS.AuthToken != c.SMS.AuthToken || !got.PageRouted() {
		t.Fatalf("second replica read back: %+v", got)
	}
}
