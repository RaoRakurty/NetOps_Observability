// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package platformdb

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// passfile_pg_test.go — tracker 384 against a real PostgreSQL: the password in a
// mounted file, what happens across a rotation, and why PGPASSFILE alone is not
// enough. Runs with DATABASE_URL_TEST set (CI: the pg-integration job).

const pfRole, pfFirst, pfSecond = "netops_pf_test", "pf-first-password", "pf-second-password"

type pfFixture struct {
	admin    *pgx.Conn
	cleanDSN string
	file     string
}

// pfSetup makes a dedicated role, so changing its password cannot disturb another
// test. The DSN it returns carries no password.
func pfSetup(ctx context.Context, t *testing.T) *pfFixture {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres password-file tests")
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Best-effort teardown of a throwaway role on a throwaway database.
		_, _ = admin.Exec(cctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '"+pfRole+"'")
		_, _ = admin.Exec(cctx, "DROP OWNED BY "+pfRole)
		_, _ = admin.Exec(cctx, "DROP ROLE IF EXISTS "+pfRole)
		_ = admin.Close(cctx)
	})
	for _, s := range []string{
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '" + pfRole + "'",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + pfRole + "') THEN EXECUTE 'DROP OWNED BY " + pfRole + "'; END IF; END $do$",
		"DROP ROLE IF EXISTS " + pfRole,
		// NewDB migrates as this role, and an earlier package on this shared
		// database may have left tables another role owns (provisionAppRole has
		// the same reset, and the same reason to restore the schema's grant).
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
		"CREATE ROLE " + pfRole + " LOGIN PASSWORD '" + pfFirst + "' NOSUPERUSER NOBYPASSRLS",
		"GRANT ALL ON SCHEMA public TO " + pfRole,
	} {
		if _, err := admin.Exec(ctx, s); err != nil {
			t.Fatalf("provision (%s): %v", s, err)
		}
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse adminDSN: %v", err)
	}
	u.User = url.User(pfRole) // the shape install.py now writes: no password
	q := u.Query()
	if q.Get("sslmode") == "" {
		q.Set("sslmode", "disable")
	}
	u.RawQuery = q.Encode()
	return &pfFixture{
		admin:    admin,
		cleanDSN: u.String(),
		file:     filepath.Join(t.TempDir(), "pgpass"),
	}
}

func (f *pfFixture) writeFile(t *testing.T, password string) {
	t.Helper()
	tmp := f.file + ".tmp"
	if err := os.WriteFile(tmp, []byte("*:*:*:*:"+password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, f.file); err != nil {
		t.Fatal(err)
	}
}

func (f *pfFixture) alter(ctx context.Context, t *testing.T, password string) {
	t.Helper()
	if _, err := f.admin.Exec(ctx, "ALTER ROLE "+pfRole+" PASSWORD '"+password+"'"); err != nil {
		t.Fatalf("ALTER ROLE: %v", err)
	}
}

// newConn forces a brand-new server connection from the pool, past its idle ones.
func newConn(ctx context.Context, db *DB) error {
	conn := db.pool.Config().ConnConfig.Copy()
	if bc := db.pool.Config().BeforeConnect; bc != nil {
		if err := bc(ctx, conn); err != nil {
			return err
		}
	}
	c, err := pgx.ConnectConfig(ctx, conn)
	if err != nil {
		return err
	}
	return c.Close(ctx)
}

func isAuthFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "28P01"
}

// The premise: pgx reads PGPASSFILE once, in ParseConfig. If this ever stops being
// true the BeforeConnect hook is dead weight; while it holds, the hook is the only
// reason a connection opened after a rotation authenticates.
func TestPGPassfileAloneDoesNotSurviveARotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := pfSetup(ctx, t)
	f.writeFile(t, pfFirst)
	t.Setenv("PGPASSFILE", f.file)

	parsed, err := pgx.ParseConfig(f.cleanDSN)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pgx.ConnectConfig(ctx, parsed)
	if err != nil {
		t.Fatalf("the driver must authenticate from PGPASSFILE (a rollback to an old image relies on it): %v", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}

	f.alter(ctx, t, pfSecond)
	f.writeFile(t, pfSecond)
	if _, err := pgx.ConnectConfig(ctx, parsed); !isAuthFailure(err) {
		t.Fatalf("expected the once-parsed config to fail with the old password, got %v", err)
	}
}

// The whole NewDB path from a DSN with no password, then a rotation:
//
//  1. the pool works and has migrated, authenticated by the file alone;
//  2. the ALTER does not touch a connection that is already open;
//  3. between the ALTER and the file change, a new connection is refused. That is
//     the window the runbook documents, and it must recover by itself;
//  4. a connection opened after the file changed authenticates with no restart;
//  5. every pooled connection recycled onto the new password still works.
func TestPGRotationReachesTheNextConnectionWithoutARestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	f := pfSetup(ctx, t)
	f.writeFile(t, pfFirst)
	t.Setenv("PGPASSFILE", f.file)

	db, err := NewDB(ctx, f.cleanDSN)
	if err != nil {
		t.Fatalf("NewDB from a password-free DSN: %v", err)
	}
	defer db.Close()
	if db.cred == nil {
		t.Fatal("PGPASSFILE must attach the file-backed credential")
	}
	var one int
	if err := db.pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatal(err)
	}

	// 2. An open connection outlives the ALTER.
	held, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	f.alter(ctx, t, pfSecond)
	if err := held.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("ALTER ROLE must not break an open connection: %v", err)
	}

	// 3. The window: role changed, file not yet.
	if err := newConn(ctx, db); !isAuthFailure(err) {
		t.Fatalf("while the file is stale a new connection must fail authentication, got %v", err)
	}

	// 4. The file changes: the very next connection is good, no restart.
	f.writeFile(t, pfSecond)
	if err := newConn(ctx, db); err != nil {
		t.Fatalf("a connection opened after the file changed: %v", err)
	}

	// 5. Recycle the pool's connections onto the new password through the real
	// pool path. Reset closes every idle connection; the next query opens one.
	db.pool.Reset()
	if err := db.pool.QueryRow(ctx, "SELECT current_user").Scan(new(string)); err != nil {
		t.Fatalf("pool after recycling: %v", err)
	}
	if loaded, failures, _ := db.cred.file.Status(); !loaded || failures != 0 {
		t.Fatalf("credential state: loaded=%v failures=%d", loaded, failures)
	}
}

// A password in the DSN is honoured for an install not migrated yet, and the file
// beats it the moment the file exists.
func TestPGLegacyDSNPasswordKeepsWorkingUntilTheFileAppears(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	f := pfSetup(ctx, t)
	u, err := url.Parse(f.cleanDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(pfRole, pfFirst)
	t.Setenv("PGPASSFILE", f.file) // compose sets it; the file is not rendered yet

	db, err := NewDB(ctx, u.String())
	if err != nil {
		t.Fatalf("an old-form DATABASE_URL must keep working through an update: %v", err)
	}
	defer db.Close()

	f.alter(ctx, t, pfSecond)
	f.writeFile(t, pfSecond)
	if err := newConn(ctx, db); err != nil {
		t.Fatalf("the file must win over the DSN: %v", err)
	}
}

// Never an anonymous attempt: no file, no DSN password, no connection, and the
// failure names the file rather than a confusing auth error.
func TestPGNoCredentialAnywhereFailsBootClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := pfSetup(ctx, t)
	t.Setenv("PGPASSFILE", f.file)
	db, err := NewDB(ctx, f.cleanDSN)
	if err == nil {
		db.Close()
		t.Fatal("NewDB must fail with no credential")
	}
	if !strings.Contains(err.Error(), "postgres password") || strings.Contains(err.Error(), "SQLSTATE 28P01") {
		t.Fatalf("expected the refusal, not an attempted login: %v", err)
	}
}

func TestPGCredentialMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	f := pfSetup(ctx, t)
	f.writeFile(t, pfFirst)
	t.Setenv("PGPASSFILE", f.file)
	prevActive, prevKind := active, kind
	t.Cleanup(func() { active, kind = prevActive, prevKind })
	if err := UsePostgres(ctx, f.cleanDSN); err != nil {
		t.Fatal(err)
	}
	if pg, ok := ActivePG(); ok {
		defer pg.DB().Close()
	}
	var buf bytes.Buffer
	WriteCredentialMetrics(&buf)
	if !strings.Contains(buf.String(), "netops_postgres_credential_loaded 1\n") {
		t.Fatalf("metrics: %s", buf.String())
	}
	if strings.Contains(buf.String(), pfFirst) {
		t.Fatal("metrics carry the password")
	}
}
