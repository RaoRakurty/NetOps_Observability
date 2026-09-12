// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/saved"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestPgSavedWriteLeakage proves the saved_objects RLS WITH CHECK is a real
// backstop: a scoped tenant cannot write OUTSIDE its namespace even when it talks
// to the database directly (i.e. even if the app-layer handler authz were ever
// bypassed). saved_objects uses the permissive shared-visibility read model, so
// the WITH CHECK on writes is what stops cross-tenant / shared-row tampering.
//
// The store's own methods run platform-scoped on purpose (handler authz gates
// them); this test instead drives the DB as a scoped tenant via withTenant, run
// as the non-superuser app role so FORCE ROW LEVEL SECURITY actually bites.
// Gated on DATABASE_URL_TEST.
func TestPgSavedWriteLeakage(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres RLS write-leakage test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	s := saved.NewPGStore(ps.DB(), logError)
	body := json.RawMessage(`{"k":"v"}`)

	// Seed a global (tenant_id="") and a cross-tenant (globex) row at platform scope.
	glob, _ := s.Create("report", "Global Report", "admin", "", body)
	gx, _ := s.Create("report", "Globex Report", "u2", "globex", body)

	// 42501 = insufficient_privilege, the SQLSTATE Postgres raises on an RLS
	// WITH CHECK violation.
	rlsDenied := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "42501"
	}

	asAcme := func(fn func(tx pgx.Tx) error) error {
		return ps.DB().WithTenant(ctx, "acme", false, fn)
	}

	// 1) acme cannot INSERT a shared (tenant_id="") row.
	err = asAcme(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO saved_objects (id, tenant_id, type, data) VALUES ($1,$2,$3,$4)`,
			"leak-shared", "", "report", body)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("acme INSERT into the shared namespace must be RLS-denied (42501); got %v", err)
	}

	// 2) acme cannot INSERT into another tenant's (globex) namespace.
	err = asAcme(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO saved_objects (id, tenant_id, type, data) VALUES ($1,$2,$3,$4)`,
			"leak-globex", "globex", "report", body)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("acme INSERT into globex's namespace must be RLS-denied (42501); got %v", err)
	}

	// 3) acme CAN write into its own namespace (control — proves we're not just
	// failing every write).
	err = asAcme(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO saved_objects (id, tenant_id, type, data) VALUES ($1,$2,$3,$4)`,
			"acme-own", "acme", "report", body)
		return e
	})
	if err != nil {
		t.Fatalf("acme INSERT into its own namespace should succeed; got %v", err)
	}

	// 4) acme cannot UPDATE a shared row it can't see — RLS USING hides it, so the
	// statement touches zero rows (silent no-op, never another tenant's data).
	err = asAcme(func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE saved_objects SET type='hijacked' WHERE id=$1`, glob.ID)
		if e != nil {
			return e
		}
		if n := tag.RowsAffected(); n != 0 {
			return fmt.Errorf("acme UPDATE of a shared row affected %d rows; want 0", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("acme UPDATE of a shared row: %v", err)
	}

	// 5) acme cannot DELETE another tenant's row — likewise zero rows.
	err = asAcme(func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `DELETE FROM saved_objects WHERE id=$1`, gx.ID)
		if e != nil {
			return e
		}
		if n := tag.RowsAffected(); n != 0 {
			return fmt.Errorf("acme DELETE of globex's row affected %d rows; want 0", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("acme DELETE of globex's row: %v", err)
	}

	// 6) acme cannot re-home its OWN row out of its namespace (UPDATE WITH CHECK on
	// the new tenant_id="" fails) — closes the "move my row to shared" escape.
	err = asAcme(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE saved_objects SET tenant_id='' WHERE id=$1`, "acme-own")
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("acme re-homing its row to the shared namespace must be RLS-denied (42501); got %v", err)
	}

	// Confirm nothing actually changed: globex row intact, no shared leak rows.
	if all := s.List("report", "", true); len(all) != 3 { // global, globex, acme-own
		t.Fatalf("post-attack report count = %d, want 3 (no leak rows created/destroyed)", len(all))
	}
}
