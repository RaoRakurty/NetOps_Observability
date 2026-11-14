// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// rca_resolution_pg_isolation_test.go — storage-layer RLS proof for the
// rca_resolutions table (migration 0071), mirroring
// rca_feedback_pg_isolation_test.go: the FORCE-RLS tenant_iso policy is the
// backstop even if every handler check were bypassed (§3a rule 4). Gated on
// DATABASE_URL_TEST like every pg-integration test in this package.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/internal/rcaresolution"
)

func TestRcaResolutionRLSIsolationPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()
	st := rcaresolution.NewPGStore(ps.DB())

	const (
		caseA = "11111111-2222-4333-8444-555555555555"
		caseB = "66666666-7777-4888-8999-aaaaaaaaaaaa"
	)
	now := time.Now().UTC().Truncate(time.Microsecond)
	add := func(tenant, corrID string, k rcaresolution.Kind, at time.Time) rcaresolution.Resolution {
		t.Helper()
		r, addErr := st.Add(ctx, tenant, rcaresolution.Resolution{
			TenantID: tenant, CorrelationID: corrID, Kind: k, Note: "recorded by the pg isolation test",
			ChangeID: "CHG-1", CreatedBy: "op@" + tenant, CreatedAt: at,
		})
		if addErr != nil {
			t.Fatalf("add %s/%s: %v", tenant, k, addErr)
		}
		return r
	}
	add("acme", caseA, rcaresolution.KindReboot, now.Add(-time.Hour))
	newest := add("acme", caseA, rcaresolution.KindConfigRollback, now)
	add("globex", caseA, rcaresolution.KindHardwareReplace, now.Add(time.Hour)) // SAME case id, other tenant
	add("globex", caseB, rcaresolution.KindCapacityAdd, now)

	// Own-only list, newest first, round-tripping every field.
	la, err := st.List(ctx, "acme", false, caseA)
	if err != nil {
		t.Fatal(err)
	}
	if len(la) != 2 || la[0].ID != newest.ID || la[0].TenantID != "acme" {
		t.Fatalf("RLS LEAK or wrong order: acme's list = %+v", la)
	}
	if la[0].Kind != rcaresolution.KindConfigRollback || la[0].ChangeID != "CHG-1" || la[0].CreatedBy != "op@acme" ||
		la[0].Note != "recorded by the pg isolation test" || !la[0].CreatedAt.Equal(now) {
		t.Fatalf("row did not round-trip: %+v", la[0])
	}

	// Latest is the recall's read: acme's newest only, nothing of globex's —
	// not the shared case id's newer globex row, not globex's own case.
	latest, err := st.Latest(ctx, "acme", []string{caseA, caseB})
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 1 || latest[caseA].ID != newest.ID {
		t.Fatalf("RLS LEAK in Latest: %+v", latest)
	}

	// A forged owner inside a scoped transaction is refused by the policy
	// (SQLSTATE 42501) — the store's own guard is bypassed here on purpose.
	err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO rca_resolutions (tenant_id, id, correlation_id, kind)
		    VALUES ('globex', '99999999-9999-4999-8999-999999999999', $1, 'reboot')`, caseA)
		return execErr
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", err)
	}

	// The CHECK constraints hold below the API: an unknown kind and an
	// over-long note are refused by the database itself.
	for name, q := range map[string]string{
		"unknown kind":  `INSERT INTO rca_resolutions (tenant_id, id, correlation_id, kind) VALUES ('acme', '88888888-8888-4888-8888-888888888888', $1, 'magic')`,
		"note too long": `INSERT INTO rca_resolutions (tenant_id, id, correlation_id, kind, note) VALUES ('acme', '77777777-7777-4777-8777-777777777777', $1, 'reboot', repeat('x', 501))`,
	} {
		err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, q, caseA)
			return execErr
		})
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("%s: the CHECK must refuse it, got %v", name, err)
		}
	}

	// A tenant that owns nothing sees nothing (default-closed).
	if l, listErr := st.List(ctx, "initech", false, caseA); listErr != nil || len(l) != 0 {
		t.Fatalf("RLS LEAK: initech saw %+v (%v)", l, listErr)
	}
	if l, latestErr := st.Latest(ctx, "initech", []string{caseA, caseB}); latestErr != nil || len(l) != 0 {
		t.Fatalf("RLS LEAK: initech's Latest saw %+v (%v)", l, latestErr)
	}

	// The platform owner (cross) reads every tenant's rows for the case.
	if all, allErr := st.List(ctx, "", true, caseA); allErr != nil || len(all) != 3 {
		t.Fatalf("cross read = %d rows (%v), want 3", len(all), allErr)
	}
}
