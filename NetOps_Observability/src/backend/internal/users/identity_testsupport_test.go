// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity_testsupport_test.go — the fixtures the cross-backend identity
// contracts share. They used to live in federated_contract_test.go /
// federated_realm_test.go, which went with the username-keyed
// UpsertFederated surface tracker 300 deleted; the fixtures themselves are
// backend plumbing and outlived it.

import (
	"context"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
)

// guardCall records one SR-025 federated-role-guard consultation: the raw role
// an IdP mapped, the tenant it was judged against, the PRINCIPAL it was judged
// for, and the door it came from.
type guardCall struct{ role, tenant, username, source string }

// realmOf builds the constraint a tenant-bound flow hands down: this realm
// reaches exactly these tenants. The real one is derived from the tenant
// directory (an /org/{id} locator reaches every tenant its org owns); the store
// only ever sees the answer.
func realmOf(tenants ...string) Realm {
	return Realm{Reaches: func(accountTenant string) bool {
		for _, t := range tenants {
			if t == accountTenant {
				return true
			}
		}
		return false
	}}
}

// provisionAppRole duplicates the platformdb test fixture (test files cannot
// cross packages): from a superuser DSN it provisions the non-superuser app
// role FORCE RLS actually applies to, returning its DSN.
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
