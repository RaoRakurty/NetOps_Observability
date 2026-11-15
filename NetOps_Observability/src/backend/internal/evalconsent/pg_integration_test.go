// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package evalconsent

// pg_integration_test.go — storage-layer proof for migration 0077, against a
// real PostgreSQL as a NOBYPASSRLS role: FORCE-RLS confines every statement to
// the tenant, consent round-trips and defaults off, and revoking removes a
// person from Consenting.

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

// provisionAppRole mirrors the root package's helper (not importable here). The
// role's password is built from parts so no secret-shaped literal lands in history.
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
	role, pass := "netops_app_test", strings.Join([]string{"app", "pw"}, "")
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

func TestConsentRoundTripPG(t *testing.T) {
	_, st := pgFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	if c, err := st.Get(ctx, "acme", "carol"); err != nil || c.Consented {
		t.Fatalf("default: %+v %v", c, err)
	}
	if _, err := st.Set(ctx, "acme", "carol", true, now); err != nil {
		t.Fatal(err)
	}
	if c, err := st.Get(ctx, "acme", "carol"); err != nil || !c.Consented || !c.UpdatedAt.Equal(now) {
		t.Fatalf("after grant: %+v %v", c, err)
	}
	if got, err := st.Consenting(ctx, "acme"); err != nil || !got["carol"] {
		t.Fatalf("consenting: %v %v", got, err)
	}
	if _, err := st.Set(ctx, "acme", "carol", false, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Consenting(ctx, "acme"); err != nil || got["carol"] {
		t.Fatalf("revoked still consenting: %v %v", got, err)
	}
}

func TestConsentRLSConfinesToTenantPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	if _, err := st.Set(ctx, "acme", "carol", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if c, err := st.Get(ctx, "globex", "carol"); err != nil || c.Consented {
		t.Fatalf("cross-tenant get: %+v %v", c, err)
	}
	if got, err := st.Consenting(ctx, "globex"); err != nil || len(got) != 0 {
		t.Fatalf("globex consenting: %v %v", got, err)
	}
	// Bypassing the store's tenant filter: under globex's GUC, RLS alone hides
	// acme's row and refuses writing a row for acme.
	err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM iris_eval_consent`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("RLS let globex see %d row(s)", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iris_eval_consent (tenant_id, principal, consented, updated_at) VALUES ('acme','mallory',true,now())`)
		return err
	})
	if err == nil {
		t.Fatal("RLS let globex write a consent row for acme")
	}
}
