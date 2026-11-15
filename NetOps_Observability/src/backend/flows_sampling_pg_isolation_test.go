// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// flows_sampling_pg_isolation_test.go — tracker 401 (c) against a real
// Postgres (migration 0077, FORCE RLS). Runs in CI's pgintegration leg.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/flowsampling"
	"netops/backend/internal/platformdb"
)

func TestFlowSamplingRLSIsolationPG(t *testing.T) {
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
	st := flowsampling.NewPGStore(ps.DB())

	// Two tenants behind ONE exporter address declare independently.
	if _, err := st.Put(ctx, "acme", flowsampling.Declaration{Exporter: "10.0.0.1", Rate: 100, Note: "acme sampler", UpdatedBy: "op@acme"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(ctx, "globex", flowsampling.Declaration{Exporter: "10.0.0.1", Rate: 7, UpdatedBy: "op@globex"}); err != nil {
		t.Fatal(err)
	}
	// Replacing keeps one row.
	if _, err := st.Put(ctx, "acme", flowsampling.Declaration{Exporter: "10.0.0.1", Rate: 1000, Note: "acme sampler", UpdatedBy: "op@acme"}); err != nil {
		t.Fatal(err)
	}
	a, err := st.List(ctx, "acme", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0].TenantID != "acme" || a[0].Rate != 1000 || a[0].Note != "acme sampler" || a[0].UpdatedBy != "op@acme" {
		t.Fatalf("RLS LEAK or no round trip: acme's list = %+v", a)
	}

	// acme cannot delete globex's declaration on the shared address.
	if err := st.Delete(ctx, "acme", "10.0.0.1"); err != nil {
		t.Fatalf("acme's own delete: %v", err)
	}
	if err := st.Delete(ctx, "acme", "10.0.0.1"); !errors.Is(err, flowsampling.ErrNotFound) {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
	if g, _ := st.List(ctx, "globex", false); len(g) != 1 || g[0].Rate != 7 {
		t.Fatalf("acme's delete reached globex: %+v", g)
	}

	// A forged owner inside a scoped transaction is refused by the policy.
	err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO flow_declared_sampling (tenant_id, exporter_addr, rate) VALUES ('globex', '10.0.0.9', 5)`)
		return execErr
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", err)
	}
	// The CHECKs hold below the API.
	for name, q := range map[string]string{
		"rate 1":        `INSERT INTO flow_declared_sampling (tenant_id, exporter_addr, rate) VALUES ('acme', '10.0.0.8', 1)`,
		"note too long": `INSERT INTO flow_declared_sampling (tenant_id, exporter_addr, rate, note) VALUES ('acme', '10.0.0.8', 5, repeat('x', 201))`,
	} {
		err = ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, q)
			return execErr
		})
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("%s: the CHECK must refuse it, got %v", name, err)
		}
	}
	// A tenant with nothing sees nothing; the platform owner sees every row.
	if l, _ := st.List(ctx, "initech", false); len(l) != 0 {
		t.Fatalf("RLS LEAK: initech saw %+v", l)
	}
	if all, _ := st.List(ctx, "", true); len(all) != 1 {
		t.Fatalf("cross read = %+v, want globex's one row", all)
	}
}
