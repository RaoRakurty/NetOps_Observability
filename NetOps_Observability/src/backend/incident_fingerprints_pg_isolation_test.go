// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// incident_fingerprints_pg_isolation_test.go — storage-layer proof for
// migration 0059 (tracker 337 N-F4): FORCE-RLS confines every read and write
// to the tenant, a forged tenant is refused, an older derivation is never
// compared, and a write-through replaces in place. Gated on DATABASE_URL_TEST.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/incidentfp"
	"netops/backend/internal/platformdb"
)

func TestIncidentFingerprintsRLSIsolationPG(t *testing.T) {
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
	st := incidentfp.NewPGStore(ps.DB())
	f := incidentfp.FromParts(incidentfp.Parts{CorrelationID: "c-1", Signature: "sig.a", Devices: []string{"edge-1"},
		ChainStepKinds: [][]string{{"interface_down"}}, SymptomKinds: []string{"loss"}, OccurredAt: time.Now()}, time.Now())
	if err := st.Put(ctx, "acme", f); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "acme", []string{"c-1", "missing"})
	if err != nil || len(got) != 1 || got["c-1"].Signature != "sig.a" || got["c-1"].ChainKey == "" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	// Another tenant: nothing.
	if other, err := st.Get(ctx, "globex", []string{"c-1"}); err != nil || len(other) != 0 {
		t.Fatalf("RLS LEAK: globex read acme's fingerprint (%v %v)", other, err)
	}
	var n int
	if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM incident_fingerprints`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("RLS LEAK: globex's session counts %d rows (%v)", n, err)
	}
	forge := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO incident_fingerprints (tenant_id, correlation_id, fp_version, fingerprint) VALUES ('globex','x',1,'{}')`)
		return err
	})
	if pgCodeOf(forge) != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", forge)
	}
	// Write-through replaces; an older derivation version is not returned.
	f.Signature = "sig.b"
	if err := st.Put(ctx, "acme", f); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, "acme", []string{"c-1"}); got["c-1"].Signature != "sig.b" {
		t.Fatalf("upsert: %+v", got)
	}
	if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE incident_fingerprints SET fp_version = 99 WHERE correlation_id = 'c-1'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, "acme", []string{"c-1"}); len(got) != 0 {
		t.Fatal("a fingerprint of another derivation version must be recomputed, not compared")
	}
}

func pgCodeOf(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
