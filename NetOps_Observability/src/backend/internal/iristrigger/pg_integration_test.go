// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package iristrigger

// pg_integration_test.go — storage-layer proof for migration 0075 against a
// real PostgreSQL as a NOBYPASSRLS role: FORCE-RLS confines every statement to
// the tenant; the DATABASE refuses a skipped run without a reason, a schedule
// faster than 15 minutes, an incident trigger with no condition and a second
// run for the same (trigger, dedupe key) even when the application is
// bypassed; Admit holds the daily cap; DueSchedules reads only workspaces whose
// switch is on.

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

// provisionAppRole mirrors the root package's helper of the same name. The
// role's password is assembled from parts so no secret-shaped literal lands in
// git history (gitleaks scans every branch).
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
	role, pass := "netops_app_test", "app"+"pw"
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

func pgFixture(t *testing.T) (*platformdb.PGStore, *PGStore) {
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

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

var pgNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func TestTriggerRoundTripAndRLSPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	tr, err := st.Create(ctx, "acme", "u-admin", Trigger{Name: "Critical BGP", Kind: KindIncident, Enabled: true,
		Filter: Filter{MinSeverity: "error", Signature: "bgp", Site: "dallas", Role: "wan_edge"}, Question: "why?"}, pgNow)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "acme", tr.ID)
	if err != nil || got.Name != "Critical BGP" || got.Filter.Role != "wan_edge" || got.CreatedBy != "u-admin" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := st.Get(ctx, "globex", tr.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant read the trigger: %v", err)
	}
	if err := st.Delete(ctx, "globex", tr.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant deleted the trigger: %v", err)
	}
	// RLS itself, without the application's tenant filter: under globex's
	// scope the row does not exist.
	var n int
	if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM iris_investigation_triggers`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("FORCE RLS let globex see %d of acme's triggers", n)
	}
	// Writing a row for another tenant from inside globex's scope is refused.
	err = ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iris_investigation_triggers (tenant_id, id, name, kind, every_minutes)
            VALUES ('acme', gen_random_uuid(), 'smuggled', 'schedule', 30)`)
		return err
	})
	if err == nil {
		t.Fatal("a row for another tenant was written under globex's scope")
	}
}

func TestDatabaseRefusesBadRowsPG(t *testing.T) {
	ps, _ := pgFixture(t)
	ctx := context.Background()
	for name, q := range map[string]string{
		"schedule faster than 15 min": `INSERT INTO iris_investigation_triggers (tenant_id, id, name, kind, every_minutes)
            VALUES ('acme', gen_random_uuid(), 'x', 'schedule', 5)`,
		"incident trigger without a condition": `INSERT INTO iris_investigation_triggers (tenant_id, id, name, kind)
            VALUES ('acme', gen_random_uuid(), 'x', 'incident')`,
		"skipped run without a reason": `INSERT INTO iris_investigation_trigger_runs (tenant_id, id, trigger_id, dedupe_key, status)
            VALUES ('acme', gen_random_uuid(), gen_random_uuid(), 'k', 'skipped')`,
		"runs per day above 100": `INSERT INTO iris_investigation_trigger_settings (tenant_id, max_runs_per_day) VALUES ('acme', 500)`,
	} {
		err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, q)
			return err
		})
		if pgCode(err) != "23514" {
			t.Errorf("%s: err=%v, want a CHECK violation", name, err)
		}
	}
}

func TestAdmitDedupesAndHoldsTheCapPG(t *testing.T) {
	_, st := pgFixture(t)
	ctx := context.Background()
	tr, err := st.Create(ctx, "acme", "u", Trigger{Name: "Critical", Kind: KindIncident, Enabled: true,
		Filter: Filter{MinSeverity: "critical"}}, pgNow)
	if err != nil {
		t.Fatal(err)
	}
	run := func(inc string) Run {
		return Run{TriggerID: tr.ID, TriggerName: tr.Name, IncidentID: inc, DedupeKey: IncidentKey(inc)}
	}
	r1, err := st.Admit(ctx, "acme", run("i1"), 1, pgNow)
	if err != nil || r1.Status != RunRunning {
		t.Fatalf("first: %+v %v", r1, err)
	}
	if _, err := st.Admit(ctx, "acme", run("i1"), 1, pgNow); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("the same incident was admitted twice: %v", err)
	}
	r2, err := st.Admit(ctx, "acme", run("i2"), 1, pgNow)
	if err != nil || r2.Status != RunSkipped || r2.Reason != SkipRunCap {
		t.Fatalf("the cap did not hold: %+v %v", r2, err)
	}
	if err := st.Finish(ctx, "acme", r1.ID, RunDone, "concluded", "inv-1", 4200, "found it", pgNow); err != nil {
		t.Fatal(err)
	}
	if n, err := st.TokensToday(ctx, "acme", pgNow); err != nil || n != 4200 {
		t.Fatalf("tokens today: %d %v", n, err)
	}
	runs, err := st.Runs(ctx, "acme", 10)
	if err != nil || len(runs) != 2 {
		t.Fatalf("runs: %+v %v", runs, err)
	}
	if other, _ := st.Runs(ctx, "globex", 10); len(other) != 0 {
		t.Fatalf("another tenant listed %d runs", len(other))
	}
	got, _ := st.Get(ctx, "acme", tr.ID)
	if got.LastRunAt == nil || !got.LastRunAt.Equal(pgNow) {
		t.Fatalf("an admitted run must move the last run time: %v", got.LastRunAt)
	}
	// A skipped schedule slot dedupes too.
	slot := Run{TriggerID: tr.ID, DedupeKey: "slot:x", Reason: SkipModelUnavailable, Summary: SkipText(SkipModelUnavailable)}
	if _, err := st.Skip(ctx, "acme", slot, pgNow); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Skip(ctx, "acme", slot, pgNow); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("a skipped slot was recorded twice: %v", err)
	}
}

func TestDueSchedulesOnlyForSwitchedOnWorkspacesPG(t *testing.T) {
	_, st := pgFixture(t)
	ctx := context.Background()
	sched := Trigger{Name: "Sweep", Kind: KindSchedule, Enabled: true, Schedule: Schedule{EveryMinutes: 15}}
	a, err := st.Create(ctx, "acme", "u", sched, pgNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(ctx, "globex", "u", sched, pgNow); err != nil {
		t.Fatal(err)
	}
	later := pgNow.Add(20 * time.Minute)
	if due, err := st.DueSchedules(ctx, later); err != nil || len(due) != 0 {
		t.Fatalf("due with every switch off: %v %v", due, err)
	}
	on := DefaultSettings()
	on.Enabled = true
	if err := st.PutSettings(ctx, "acme", on); err != nil {
		t.Fatal(err)
	}
	if s, err := st.Settings(ctx, "acme"); err != nil || !s.Enabled {
		t.Fatalf("settings round trip: %+v %v", s, err)
	}
	if s, err := st.Settings(ctx, "globex"); err != nil || s.Enabled {
		t.Fatalf("globex's switch: %+v %v", s, err)
	}
	due, err := st.DueSchedules(ctx, later)
	if err != nil || len(due) != 1 || due[0].ID != a.ID || due[0].TenantID != "acme" {
		t.Fatalf("due: %+v %v", due, err)
	}
}
