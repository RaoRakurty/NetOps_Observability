// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/discovery"
	"netops/backend/internal/platformdb"
)

// openDiscoveredDevicesPG connects as the non-superuser app role on a freshly
// provisioned schema (migrations applied by NewPGStore). Gated on
// DATABASE_URL_TEST.
func openDiscoveredDevicesPG(t *testing.T) *platformdb.PGStore {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres discovered-device tests")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	t.Cleanup(func() { ps.DB().Close() })
	return ps
}

// TestPgDiscoveredDevicesSurviveARestart is runRestartScenario on Postgres.
func TestPgDiscoveredDevicesSurviveARestart(t *testing.T) {
	ps := openDiscoveredDevicesPG(t)
	runRestartScenario(t, discovery.NewPGFoundStore(ps.DB()))
}

// TestPgDiscoveredDevicesAreTenantIsolated proves migration 0063's FORCE-RLS is
// a real backstop, run as the app role: a write filed under another tenant is
// refused by WITH CHECK even when issued directly, a tenant never reads
// another's rows (nor the platform's), only '*' sees all, and a prune is
// confined to its own tenant.
func TestPgDiscoveredDevicesAreTenantIsolated(t *testing.T) {
	ps := openDiscoveredDevicesPG(t)
	ctx := context.Background()
	st := discovery.NewPGFoundStore(ps.DB())
	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	rec := func(tenant, addr, id string) discovery.FoundRecord {
		return discovery.FoundRecord{TenantID: tenant, Source: "snmp", Address: addr, DeviceID: id, Name: id,
			FirstFound: at, LastAnswered: at}
	}
	if err := st.Apply(ctx, []discovery.FoundRecord{
		rec("", "10.77.0.1", "plat"),
		rec("t_acme", "10.77.0.1", "acme"), // same address, another tenant: another row
		rec("t_globex", "10.77.0.2", "globex"),
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	ids := func(tenant string, cross bool) string {
		t.Helper()
		recs, err := st.Load(ctx, tenant, cross)
		if err != nil {
			t.Fatalf("Load(%q,%v): %v", tenant, cross, err)
		}
		var out []string
		for _, r := range recs {
			out = append(out, r.DeviceID)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := ids("t_acme", false); got != "acme" {
		t.Fatalf("CROSS-TENANT LEAK: acme reads %q", got)
	}
	if got := ids("", false); got != "plat" {
		t.Fatalf("the platform partition reads %q — '' is a partition, not a wildcard", got)
	}
	if got := ids("", true); got != "acme,globex,plat" {
		t.Fatalf("the '*' read sees %q, want all three", got)
	}

	// RLS is the backstop even for a query that forgets its WHERE.
	var n int
	if err := ps.DB().WithTenant(ctx, "t_acme", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM discovered_devices`).Scan(&n)
	}); err != nil || n != 1 {
		t.Fatalf("an unfiltered read in acme's scope counted %d rows (%v), want 1", n, err)
	}

	// WITH CHECK: a row filed under another tenant is refused in this scope.
	err := ps.DB().WithTenant(ctx, "t_acme", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO discovered_devices (tenant_id, source, address, device_id) VALUES ('t_globex','snmp','10.9.9.9','x')`)
		return e
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a write into another tenant must be RLS-denied (42501); got %v", err)
	}
	// Nor can a scope rewrite another tenant's row into itself.
	if err := ps.DB().WithTenant(ctx, "t_acme", false, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE discovered_devices SET name='pwned' WHERE tenant_id='t_globex'`)
		if e == nil && tag.RowsAffected() != 0 {
			return errors.New("updated another tenant's row")
		}
		return e
	}); err != nil {
		t.Fatalf("cross-tenant update: %v", err)
	}

	// Upsert semantics: stale on, first_found kept.
	r := rec("t_acme", "10.77.0.1", "acme")
	r.FirstFound = at.Add(time.Hour) // a later "first found" never moves it forward
	r.StaleSince = at.Add(2 * time.Hour)
	if err := st.Apply(ctx, []discovery.FoundRecord{r}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(ctx, "t_acme", false)
	if err != nil || len(got) != 1 || !got[0].FirstFound.Equal(at) || !got[0].StaleSince.Equal(at.Add(2*time.Hour)) {
		t.Fatalf("upsert round-trip: %v %+v", err, got)
	}

	// A prune is confined to its tenant: acme's prune of 10.77.0.1 leaves the
	// platform row with the same address.
	if err := st.Apply(ctx, nil, []discovery.FoundKey{{TenantID: "t_acme", Source: "snmp", Address: "10.77.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if got := ids("", true); got != "globex,plat" {
		t.Fatalf("after acme's prune: %q", got)
	}

	// A chunked upsert past one statement's worth stays atomic per tenant.
	big := make([]discovery.FoundRecord, 0, 1200)
	for i := 0; i < 1200; i++ {
		big = append(big, rec("t_bulk", "10.78."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250+1), "bulk-"+strconv.Itoa(i)))
	}
	if err := st.Apply(ctx, big, nil); err != nil {
		t.Fatalf("bulk Apply: %v", err)
	}
	if recs, err := st.Load(ctx, "t_bulk", false); err != nil || len(recs) != 1200 {
		t.Fatalf("bulk load: %v %d", err, len(recs))
	}
}
