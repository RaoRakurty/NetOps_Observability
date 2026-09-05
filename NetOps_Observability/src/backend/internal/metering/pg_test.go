package metering

// pg_test.go — the Postgres backend against a REAL database, proving that the
// isolation is the DATABASE's and not merely the store's.
//
// The file backend's tests prove the app layer filters correctly. That is the
// first line, not the last one: §3a rule 4 asks for FORCE row-level security
// underneath it, so that a future query which forgot its predicate still
// returns nothing rather than everything. Only a live server can show that, so
// this runs against DATABASE_URL_TEST and skips otherwise.
//
// CRUCIAL: a PostgreSQL superuser ignores RLS entirely, even with FORCE ROW
// LEVEL SECURITY. DATABASE_URL_TEST is expected to be a superuser (it
// provisions the role); the store connects as a freshly created NON-superuser,
// so isolation is exercised the way production runs it.

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// pgFixture provisions a clean app role, boots the platform store (which applies
// migration 0046 among the rest) and returns a metering store over it.
func pgFixture(t *testing.T) (*PGStore, *platformdb.DB) {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST (a superuser DSN) to run the live metering RLS test")
	}
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	const role, pass = "netops_metering_test", "meterpw"
	stmts := []string{
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') THEN EXECUTE 'DROP OWNED BY " + role + "'; END IF; END $do$",
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + pass + "' NOSUPERUSER",
		"GRANT ALL ON SCHEMA public TO " + role,
	}
	for _, s := range stmts {
		if _, err := admin.Exec(ctx, s); err != nil {
			_ = admin.Close(ctx) // best-effort: the provisioning failure below is the one that matters
			t.Fatalf("provision (%s): %v", s, err)
		}
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("admin close: %v", err)
	}

	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse DATABASE_URL_TEST: %v", err)
	}
	u.User = url.UserPassword(role, pass)

	ps, err := platformdb.NewPGStore(ctx, u.String())
	if err != nil {
		t.Fatalf("platform store: %v", err)
	}
	t.Cleanup(ps.DB().Close)
	return NewPGStore(ps.DB()), ps.DB()
}

func TestPGMeteringIsolationIsEnforcedByTheDatabase(t *testing.T) {
	store, db := pgFixture(t)
	ctx := context.Background()

	at := day("2026-09-05T01:00:00Z")
	if err := store.Record(ctx, at, map[string][]Reading{
		"acme":            {Unique(MeterMonitoredDevicesUnique, "acme", []string{"a1", "a2"})},
		"globex":          {Unique(MeterMonitoredDevicesUnique, "globex", []string{"g1"})},
		ScopeInstallation: {Measured(MeterTenants, ScopeInstallation, 2)},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// ── the STORE's answer ──────────────────────────────────────────────────
	acme, err := store.List(ctx, "acme", false, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("list acme: %v", err)
	}
	if len(acme) != 1 || acme[0].TenantID != "acme" {
		t.Fatalf("acme sees %d rows (%+v), want only its own", len(acme), acme)
	}
	if v := acme[0].Meters[MeterMonitoredDevicesUnique].Value; v == nil || *v != 2 {
		t.Fatalf("acme's meter did not round-trip: %+v", acme[0].Meters)
	}
	all, err := store.List(ctx, "", true, "2026-09-01", "2026-09-30")
	if err != nil {
		t.Fatalf("list cross: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("the platform read sees %d rows, want 3", len(all))
	}

	// ── the DATABASE's answer, with no predicate at all ─────────────────────
	//
	// This is the point of the file. The query below asks for EVERY row; RLS is
	// what makes a tenant-scoped transaction return only one. If the policy were
	// missing or not FORCEd, this count would be 3 and the app-layer filter above
	// would be the only thing standing between two customers.
	count := func(tenant string, cross bool) int {
		var n int
		if err := db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM metering_daily`).Scan(&n)
		}); err != nil {
			t.Fatalf("count(%q, cross=%v): %v", tenant, cross, err)
		}
		return n
	}
	if got := count("acme", false); got != 1 {
		t.Errorf("an UNFILTERED query under the acme scope returned %d rows, want 1 — the row policy is not enforcing", got)
	}
	if got := count("globex", false); got != 1 {
		t.Errorf("an UNFILTERED query under the globex scope returned %d rows, want 1", got)
	}
	if got := count("", true); got != 3 {
		t.Errorf("the platform scope sees %d rows, want 3", got)
	}
	// The INSTALLATION row is reachable only from the platform scope: its key is
	// the empty string, which no tenant scope can equal.
	if got := count("acme", false); got == 3 {
		t.Errorf("a tenant scope reached the installation row")
	}
}

func TestPGMeteringFoldsHoursIntoOneDayAndSealsTheOnesBefore(t *testing.T) {
	store, db := pgFixture(t)
	ctx := context.Background()

	for _, at := range []string{"2026-09-04T01:00:00Z", "2026-09-04T02:00:00Z"} {
		if err := store.Record(ctx, day(at), map[string][]Reading{
			"acme": {
				Unique(MeterMonitoredDevicesUnique, "acme", []string{"a1", "a2"}),
				Counted(MeterDEMChecks, "acme", 10),
			},
		}); err != nil {
			t.Fatalf("record %s: %v", at, err)
		}
	}
	rows, err := store.List(ctx, "acme", false, "2026-09-04", "2026-09-04")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("two hours produced %d rows, want one day", len(rows))
	}
	if rows[0].Samples != 2 {
		t.Errorf("samples = %d, want 2", rows[0].Samples)
	}
	if v := rows[0].Meters[MeterDEMChecks].Value; v == nil || *v != 20 {
		t.Errorf("the interval counter did not sum across hours: %+v", rows[0].Meters[MeterDEMChecks])
	}
	if v := rows[0].Meters[MeterMonitoredDevicesUnique].Value; v == nil || *v != 2 {
		t.Errorf("the unique count double-counted the same devices: %+v", rows[0].Meters[MeterMonitoredDevicesUnique])
	}

	// A NEW day seals the previous one: the identity set a closed day no longer
	// needs must not outlive it.
	if err := store.Record(ctx, day("2026-09-05T01:00:00Z"), map[string][]Reading{
		"acme": {Unique(MeterMonitoredDevicesUnique, "acme", []string{"a3"})},
	}); err != nil {
		t.Fatalf("record next day: %v", err)
	}
	var hasOpen bool
	if err := db.WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT data ? 'open' FROM metering_daily WHERE day = '2026-09-04'`).Scan(&hasOpen)
	}); err != nil {
		t.Fatalf("read sealed row: %v", err)
	}
	if hasOpen {
		t.Errorf("a closed day still carries its accumulator state in the database")
	}
}

func TestPGMeteringPruneAndCount(t *testing.T) {
	store, _ := pgFixture(t)
	ctx := context.Background()

	for _, d := range []string{"2024-01-01T01:00:00Z", "2026-09-05T01:00:00Z"} {
		if err := store.Record(ctx, day(d), map[string][]Reading{
			"acme": {Measured(MeterMonitoredDevicesPeak, "acme", 1)},
		}); err != nil {
			t.Fatalf("record %s: %v", d, err)
		}
	}
	if n, err := store.Rows(ctx); err != nil || n != 2 {
		t.Fatalf("rows = %d (%v), want 2", n, err)
	}
	dropped, err := store.Prune(ctx, PruneHorizon(day("2026-09-05T01:00:00Z")))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("pruned %d rows, want the one outside the %d-day bound", dropped, RetentionDays)
	}
	if n, err := store.Rows(ctx); err != nil || n != 1 {
		t.Fatalf("rows after prune = %d (%v), want 1", n, err)
	}
	if _, err := store.Prune(ctx, "not-a-day"); err == nil {
		t.Errorf("prune accepted a malformed horizon")
	}
}
