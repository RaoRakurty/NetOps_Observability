package backend

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
		// Clear residue from a prior package's tests on this shared database
		// BEFORE dropping: the pg-integration CI job runs the whole corpus with
		// `-p 1 ./...` against ONE database, and a leaked/late-closing connection
		// as the app role would otherwise block DROP ROLE / hold the objects the
		// schema drop needs. Terminate other backends, then drop what the role
		// still owns, so provisioning is deterministic regardless of run order.
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') THEN EXECUTE 'DROP OWNED BY " + role + "'; END IF; END $do$",
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		// Recreating public leaves it owned by the superuser with no CREATE for
		// anyone else (PG15+ dropped the public-CREATE-to-PUBLIC default), which
		// strips the persistent CI app role's (PG_TEST_DSN) grant and makes the
		// next non-provisioning test fail "no schema has been selected to create
		// in". Restore usability for every role on this shared test database.
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
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
