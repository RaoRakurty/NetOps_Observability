package main

import (
	"context"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
)

// provisionAppRole duplicates the platformdb test fixture (test files cannot
// cross packages): from a superuser DSN it provisions the non-superuser app
// role FORCE RLS actually applies to, returning its DSN.
// It returns a DSN pointing at that role. Connecting as the role to create the
// tables makes the role their owner, and FORCE ROW LEVEL SECURITY keeps even the
// owner subject to policy.
func provisionAppRole(ctx context.Context, t *testing.T, adminDSN string) string {
	t.Helper()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	const role, pass = "netops_app_test", "apppw"
	stmts := []string{
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + pass + "' NOSUPERUSER",
		"GRANT ALL ON SCHEMA public TO " + role,
	}
	for _, s := range stmts {
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
