package backend

// maintenance_pg_isolation_test.go — storage-layer RLS proof for the
// maintenance_windows table (migration 0031), mirroring
// business_service_isolation_test.go: the FORCE-RLS tenant_iso policy is the
// backstop even if every handler check were bypassed (§3a.4). Gated on
// DATABASE_URL_TEST like every pg integration test.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/maintenance"
)

func TestMaintenanceWindowRLSIsolation(t *testing.T) {
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
	st := maintenance.NewPGStore(ps.DB())

	now := time.Now().UTC()
	later := now.Add(2 * time.Hour)
	mk := func(tenant, name string) maintenance.Window {
		w, err := st.Create(ctx, tenant, false, maintenance.Window{
			TenantID: tenant, Name: name, Enabled: true, StartsAt: &now, EndsAt: &later,
		})
		if err != nil {
			t.Fatalf("create %s/%s: %v", tenant, name, err)
		}
		return w
	}
	wa := mk("acme", "acme change")
	wb := mk("globex", "globex change")

	// Own-only list.
	la, err := st.List(ctx, "acme", false)
	if err != nil || len(la) != 1 || la[0].ID != wa.ID {
		t.Fatalf("acme must list exactly its own window: %v %+v", err, la)
	}

	// Cross-tenant read/update/delete: zero visible rows.
	if _, found, _ := st.Get(ctx, "acme", false, wb.ID); found {
		t.Fatal("RLS LEAK: acme read globex's window")
	}
	if _, found, _ := st.Update(ctx, "acme", false, wb.ID, wb); found {
		t.Fatal("RLS LEAK: acme updated globex's window")
	}
	if found, _ := st.Delete(ctx, "acme", false, wb.ID); found {
		t.Fatal("RLS LEAK: acme deleted globex's window")
	}
	if _, found, _ := st.Get(ctx, "globex", false, wb.ID); !found {
		t.Fatal("globex's window must be intact")
	}

	// WITH CHECK forge: inserting a row claiming another tenant under a scoped
	// transaction must be refused by policy (SQLSTATE 42501).
	_, err = st.Create(ctx, "acme", false, maintenance.Window{
		TenantID: "globex", Name: "forged", Enabled: true, StartsAt: &now, EndsAt: &later,
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", err)
	}

	// Covering is scoped: acme's window never covers globex's alerts.
	at := now.Add(time.Minute)
	if _, cov, err := st.Covering(ctx, "acme", "dev", "", "rule", at); err != nil || !cov {
		t.Fatalf("acme's own window must cover: %v %v", cov, err)
	}
	if _, cov, _ := st.Covering(ctx, "initech", "dev", "", "rule", at); cov {
		t.Fatal("RLS LEAK: a window suppressed a tenant that owns none")
	}

	// Platform principal sees both.
	if all, _ := st.List(ctx, "", true); len(all) != 2 {
		t.Fatalf("platform principal must see both windows: %+v", all)
	}
}
