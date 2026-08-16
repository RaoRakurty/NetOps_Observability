package platformdb

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgstore_test.go — coverage for the normalized Postgres backend.
//
// The explode/assemble logic is pure and tested without a database. The RLS
// isolation test needs a real PostgreSQL and is skipped unless DATABASE_URL_TEST
// is set, so the default `go test` stays offline and dependency-free at runtime.

func TestSpecForResolvesBothKeyShapes(t *testing.T) {
	cases := map[string]string{
		"/data/users.json":            "users",
		"kv://users":                  "users",
		"/data/snmp_credentials.json": "snmp_credentials",
		"/data/apikeys.json":          "api_keys",
		"kv://audit":                  "audit_events",
	}
	for key, wantTable := range cases {
		spec, ok := specFor(key)
		if !ok {
			t.Errorf("specFor(%q): expected a spec", key)
			continue
		}
		if spec.table != wantTable {
			t.Errorf("specFor(%q).table = %q, want %q", key, spec.table, wantTable)
		}
	}
	if _, ok := specFor("/data/ldap_config.json"); ok {
		t.Error("ldap_config is a singleton blob, must NOT resolve to a normalized table")
	}
}

func TestExplodeUsersLowercasesIDAndLiftsTenant(t *testing.T) {
	blob := []byte(`[
		{"username":"Alice","tenant_id":"acme","role":"admin"},
		{"username":"bob","role":"viewer"}
	]`)
	rows, err := explode(rowSpecs["users"], blob)
	if err != nil {
		t.Fatalf("explode: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].id != "alice" {
		t.Errorf("id = %q, want lowercased \"alice\"", rows[0].id)
	}
	if rows[0].tenant != "acme" {
		t.Errorf("tenant = %q, want \"acme\"", rows[0].tenant)
	}
	if rows[1].tenant != "" {
		t.Errorf("missing tenant_id must explode to \"\" (global), got %q", rows[1].tenant)
	}
	// data must be the verbatim element (lossless round-trip).
	var got map[string]any
	if err := json.Unmarshal(rows[0].data, &got); err != nil {
		t.Fatalf("data not valid JSON: %v", err)
	}
	if got["role"] != "admin" {
		t.Errorf("verbatim data lost a field: %v", got)
	}
}

func TestExplodeAuditUsesTenantAndTimeFields(t *testing.T) {
	blob := []byte(`[{"id":"e1","tenant":"acme","time":"2026-06-02T10:00:00Z","method":"GET"}]`)
	rows, err := explode(rowSpecs["audit"], blob)
	if err != nil {
		t.Fatalf("explode: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].tenant != "acme" {
		t.Errorf("audit tenant lifted from JSON \"tenant\" = %q, want \"acme\"", rows[0].tenant)
	}
	if rows[0].ts == nil || !rows[0].ts.Equal(time.Date(2026, 6, 2, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("audit ts lifted from JSON \"time\" = %v, want 2026-06-02T10:00:00Z", rows[0].ts)
	}
}

func TestExplodeTenantsDoesNotLiftTenantColumn(t *testing.T) {
	// tenants.tenant_id is a generated column; the exploder must leave tenant empty.
	rows, err := explode(rowSpecs["tenants"], []byte(`[{"id":"acme","name":"Acme"}]`))
	if err != nil {
		t.Fatalf("explode: %v", err)
	}
	if rows[0].id != "acme" || rows[0].tenant != "" {
		t.Errorf("tenants row = %+v, want id=acme tenant=\"\"", rows[0])
	}
}

func TestExplodeMissingIDIsError(t *testing.T) {
	if _, err := explode(rowSpecs["users"], []byte(`[{"role":"admin"}]`)); err == nil {
		t.Error("element missing the id field must error, not silently drop")
	}
}

func TestExplodeEmptyBlobIsEmpty(t *testing.T) {
	for _, blob := range [][]byte{nil, []byte(""), []byte("  "), []byte("[]")} {
		rows, err := explode(rowSpecs["roles"], blob)
		if err != nil {
			t.Fatalf("explode(%q): %v", blob, err)
		}
		if len(rows) != 0 {
			t.Errorf("explode(%q) = %d rows, want 0", blob, len(rows))
		}
	}
}

func TestAssembleRoundTrips(t *testing.T) {
	if got := string(assemble(nil)); got != "[]" {
		t.Errorf("assemble(nil) = %q, want \"[]\"", got)
	}
	datas := [][]byte{[]byte(`{"id":"a"}`), []byte(`{"id":"b"}`)}
	out := assemble(datas)
	var list []map[string]string
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatalf("assembled blob is not valid JSON: %v (%s)", err, out)
	}
	if len(list) != 2 || list[0]["id"] != "a" || list[1]["id"] != "b" {
		t.Errorf("assembled list mismatch: %s", out)
	}
}

// TestPgStoreRLSIsolation proves database-enforced tenant isolation end to end:
// two tenants' users are saved through the store, then a tenant-scoped
// transaction sees only its own rows while the platform owner sees all. Requires
// a real PostgreSQL — set DATABASE_URL_TEST (e.g. a throwaway docker container)
// to run it; skipped otherwise so the default suite needs no database.
//
// CRUCIAL: PostgreSQL superusers (and BYPASSRLS roles) ignore RLS entirely, even
// with FORCE ROW LEVEL SECURITY. DATABASE_URL_TEST is expected to be a superuser
// (it provisions roles); the test connects the store as a freshly-created
// NON-superuser role so isolation is exercised the way production must run.
func TestPgStoreRLSIsolation(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the live RLS isolation test")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)

	ps, err := NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()

	// Start clean, then save two tenants' worth of users through the seam.
	if err := ps.Save("/data/users.json", []byte(`[
		{"username":"alice","tenant_id":"acme"},
		{"username":"carol","tenant_id":"globex"}
	]`)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	count := func(tenant string, cross bool) int {
		var n int
		if err := ps.DB().WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n)
		}); err != nil {
			t.Fatalf("count(%q): %v", tenant, err)
		}
		return n
	}

	if got := count("acme", false); got != 1 {
		t.Errorf("acme scope sees %d users, want 1 (RLS must hide globex)", got)
	}
	if got := count("globex", false); got != 1 {
		t.Errorf("globex scope sees %d users, want 1", got)
	}
	if got := count("", true); got != 2 {
		t.Errorf("platform owner ('*') sees %d users, want 2", got)
	}

	// The blob-shaped seam reassembles the full collection (platform load path).
	blob, err := ps.Load("/data/users.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var users []map[string]string
	if err := json.Unmarshal(blob, &users); err != nil {
		t.Fatalf("reassembled blob invalid: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("reassembled %d users, want 2", len(users))
	}
}

// TestPgStoreImportsLegacyBlob proves the one-time importer moves data left by
// the old blob backend (netops_kv) into the normalized tables on first boot.
// Gated on DATABASE_URL_TEST like the RLS test.
func TestPgStoreImportsLegacyBlob(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the live legacy-import test")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)

	// Seed a legacy netops_kv blob (as the app role, so it owns the table) before
	// the store boots — keyed exactly as the old pgkv.go wrote it.
	conn, err := pgx.Connect(ctx, appDSN)
	if err != nil {
		t.Fatalf("app connect: %v", err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE netops_kv (key TEXT PRIMARY KEY, data BYTEA NOT NULL)`); err != nil {
		t.Fatalf("create netops_kv: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO netops_kv (key, data) VALUES ($1, $2)`,
		"/data/roles.json", []byte(`[{"id":"admin","name":"Admin"}]`)); err != nil {
		t.Fatalf("seed legacy blob: %v", err)
	}
	conn.Close(ctx)

	ps, err := NewPGStore(ctx, appDSN) // migrates, then importLegacy runs
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()

	blob, err := ps.Load("/data/roles.json")
	if err != nil {
		t.Fatalf("Load after import: %v", err)
	}
	var roles []map[string]string
	if err := json.Unmarshal(blob, &roles); err != nil {
		t.Fatalf("imported blob invalid: %v", err)
	}
	if len(roles) != 1 || roles[0]["id"] != "admin" {
		t.Errorf("legacy import = %s, want one admin role", blob)
	}
}

// TestPgStoreRefusesSuperuser proves the fail-closed RLS guard: connecting as a
// superuser (which would silently bypass RLS) must abort startup, not boot with
// isolation quietly disabled. DATABASE_URL_TEST is expected to be a superuser.
func TestPgStoreRefusesSuperuser(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST (a superuser) to run the RLS guard test")
	}
	_, err := NewPGStore(context.Background(), adminDSN)
	if err == nil {
		t.Fatal("newPgStore as superuser must fail closed (RLS would be bypassed), but it succeeded")
	}
	if !strings.Contains(err.Error(), "Row-Level Security") {
		t.Errorf("error should explain the RLS bypass, got: %v", err)
	}
}

// provisionAppRole resets the public schema and (re)creates a non-superuser role
// the store connects as, so RLS actually enforces (a superuser would bypass it).
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
