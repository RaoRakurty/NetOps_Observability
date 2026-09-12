// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// audit_retention_floor_pg_test.go — tracker 235's Postgres half.
//
// The file backend keeps platform-global config changes in a separately bounded
// trail. The Postgres backend has no ring at all — it has an OPT-IN retention
// sweeper — so the same promise has to be kept a different way: the sweep
// carries a FLOOR under the platform-change class, and deletes those rows only
// once the platform horizon has passed.
//
// Without the floor, an operator turning retention on with a short horizon
// ("keep 7 days of audit") would silently delete exactly the events the
// 2026-09-03 incident could not answer without — months before anyone asked,
// and with nothing in the trail to say it happened.
//
// This test runs the REAL statement against a REAL Postgres, because the thing
// most likely to break is not the logic but the binding: the class predicate
// binds a method array and a LIKE-pattern array, and a driver that would not
// bind them turns the whole sweeper into a runtime error — retention would then
// stop, silently, at the exact moment it was switched on.
//
// Gated on DATABASE_URL_TEST and opened through provisionAppRole like every
// other store test in this package (the superuser migrates, the throwaway
// NOBYPASSRLS role runs). The earlier PG_TEST_DSN variant opened the store on
// the app role directly and failed its own migration in CI — a sweep that
// runs under platform scope still needs a migrated schema to sweep.
//
// Every row it writes carries one dedicated tenant, and it reads and cleans up
// through that scope, so it neither asserts about nor leaves behind another
// test's rows. The SWEEP is necessarily table-wide (retention is a platform
// policy); on the CI service container the only other rows are that job's own.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/audit"
	"netops/backend/internal/platformdb"
)

func TestPgRetentionKeepsPlatformChangesUnderTheirOwnFloor(t *testing.T) {
	ps, a := auditRetentionFixture(t)
	now := time.Now().UTC()
	rows := []struct {
		id           string
		age          time.Duration
		method, path string
		keep         bool
	}{
		// Ordinary traffic: gone once it is older than the general horizon.
		{"ordinary-old", 40 * 24 * time.Hour, "GET", "/api/devices", false},
		{"ordinary-new", 5 * 24 * time.Hour, "GET", "/api/devices", true},
		// A platform config change inside the general horizon: kept by both.
		{"platform-new", 5 * 24 * time.Hour, "PUT", "/api/system/backup/schedule", true},
		// The row this test exists for: older than the 30-day general horizon,
		// younger than the 90-day platform floor. It MUST survive.
		{"platform-mid", 40 * 24 * time.Hour, "PUT", "/api/system/backup/schedule", true},
		// Past the floor as well: the policy is a floor, not an exemption.
		{"platform-ancient", 200 * 24 * time.Hour, "POST", "/api/auth/oidc/config", false},
		// A MUTATION on a non-platform path is ordinary traffic.
		{"tenant-write-old", 40 * 24 * time.Hour, "POST", "/api/devices", false},
		// A READ of a platform path is not a change and gets no floor.
		{"platform-read-old", 40 * 24 * time.Hour, "GET", "/api/system/backup/schedule", false},
	}
	for _, r := range rows {
		if err := a.RecordStrict(AuditEvent{
			ID: r.id, Time: now.Add(-r.age), Actor: "rao", Tenant: auditRetentionTenant,
			Method: r.method, Path: r.path, Status: 200, Decision: "allow",
		}); err != nil {
			t.Fatalf("record %s: %v", r.id, err)
		}
	}

	// 30-day general horizon, 90-day platform floor.
	if _, err := audit.SweepRetention(context.Background(), ps.DB(), 30, 90); err != nil {
		t.Fatalf("sweep: %v — the class predicate did not bind, so retention would "+
			"fail silently the moment an operator switched it on", err)
	}

	left, err := a.List(auditRetentionTenant, false, auditQuery{Limit: audit.MaxQueryLimit})
	if err != nil {
		t.Fatalf("list after sweep: %v", err)
	}
	survived := map[string]bool{}
	for _, e := range left {
		survived[e.ID] = true
	}
	for _, r := range rows {
		if survived[r.id] != r.keep {
			verb := "was deleted"
			if survived[r.id] {
				verb = "survived"
			}
			t.Errorf("%s (%s %s, %v old) %s — want keep=%v",
				r.id, r.method, r.path, r.age, verb, r.keep)
		}
	}
}

// TestPgRetentionWithoutAFloorIsTheOldBehaviour — the floor is opt-in in the
// same sense retention is: platformDays <= days means one horizon for
// everything, and the statement must still run.
func TestPgRetentionWithoutAFloorIsTheOldBehaviour(t *testing.T) {
	ps, a := auditRetentionFixture(t)
	old := time.Now().UTC().Add(-40 * 24 * time.Hour)
	if err := a.RecordStrict(AuditEvent{ID: "platform-old", Time: old, Tenant: auditRetentionTenant,
		Method: "PUT", Path: "/api/system/backup/schedule", Status: 200, Decision: "allow"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := audit.SweepRetention(context.Background(), ps.DB(), 30, 0); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	left, err := a.List(auditRetentionTenant, false, auditQuery{Limit: audit.MaxQueryLimit})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("with no floor, an over-horizon platform row must be swept like any other: %+v", left)
	}
}

// auditRetentionTenant scopes every row these tests write, so their assertions
// and their cleanup can never reach another test's audit rows.
const auditRetentionTenant = "audit-retention-floor-test"

// auditRetentionFixture opens the pg corpus's database, runs the migrations and
// removes any rows a previous run of THESE tests left: they assert about what
// survives a sweep, so a leftover row would be indistinguishable from a row the
// floor protected.
func auditRetentionFixture(t *testing.T) (*platformdb.PGStore, audit.Repo) {
	t.Helper()
	// Same prologue as every other pgintegration store test: DATABASE_URL_TEST
	// is the superuser that migrates and provisions a throwaway NOBYPASSRLS app
	// role; the store then runs as that role. Opening the store straight on the
	// app role fails its own migration ("permission denied for table
	// schema_migrations") — which is what CI reported on 5105ca31.
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres audit retention tests")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	t.Cleanup(func() { ps.DB().Close() })
	clear := func() error {
		return ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, "DELETE FROM audit_events WHERE tenant_id = $1", auditRetentionTenant)
			return execErr
		})
	}
	if err := clear(); err != nil {
		t.Fatalf("clear audit_events: %v", err)
	}
	t.Cleanup(func() {
		if err := clear(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return ps, audit.NewPGStore(ps.DB(), logError)
}
