// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// business_service_isolation_test.go — CROSS-TENANT isolation for the Business
// Service mapping (CLAUDE.md §3a.5, REQUIRED with the feature). Drives the store
// as two scoped tenants through withTenant, run as the non-superuser app role so
// FORCE ROW LEVEL SECURITY actually bites — the storage-layer backstop even if a
// handler authz check were bypassed. Asserts: own-only list, cross-tenant
// get/assign/clear cannot see or touch another tenant's rows, and a scoped tenant
// cannot forge a row into another tenant's namespace (RLS WITH CHECK).
//
// Gated on DATABASE_URL_TEST (a superuser DSN that provisions a throwaway role).

import (
	"context"
	"errors"
	"netops/backend/cloud"
	"netops/backend/internal/platformdb"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestBusinessServiceCrossTenantIsolation(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres business-service isolation test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := cloud.NewBizSvcStore(ps.DB())

	// acme creates a named service and maps a resource to it.
	svc, err := st.CreateService(ctx, "acme", false,
		cloud.BusinessService{TenantID: "acme", Name: "payments", Owner: "payments-sre",
			RunbookURL: "https://runbooks.acme.example/payments", CreatedBy: "u-acme"})
	if err != nil {
		t.Fatalf("acme CreateService: %v", err)
	}
	if _, err := st.AssignResources(ctx, "acme", false, svc.BusinessServiceID, "payments", "u-acme",
		[]string{"/subscriptions/s/resourceGroups/rg-payments/providers/Microsoft.Compute/virtualMachines/web01"}); err != nil {
		t.Fatalf("acme AssignResources: %v", err)
	}

	// 1) own-only list: acme sees its service + mapping (owner round-trips).
	if svcs, _ := st.ListServices(ctx, "acme", false); len(svcs) != 1 {
		t.Fatalf("acme should see exactly its own service, got %d", len(svcs))
	} else if svcs[0].Owner != "payments-sre" {
		t.Fatalf("owner should round-trip, got %q", svcs[0].Owner)
	} else if svcs[0].RunbookURL != "https://runbooks.acme.example/payments" {
		t.Fatalf("runbook_url should round-trip, got %q", svcs[0].RunbookURL)
	}
	if maps, _ := st.ListMappings(ctx, "acme", false); len(maps) != 1 {
		t.Fatalf("acme should see exactly its own mapping, got %d", len(maps))
	}

	// 2) globex sees NEITHER — no cross-tenant leak.
	if svcs, err := st.ListServices(ctx, "globex", false); err != nil || len(svcs) != 0 {
		t.Fatalf("globex must see zero acme services, got %d err=%v", len(svcs), err)
	}
	if maps, err := st.ListMappings(ctx, "globex", false); err != nil || len(maps) != 0 {
		t.Fatalf("globex must see zero acme mappings, got %d err=%v", len(maps), err)
	}

	// 3) globex cannot rename/delete acme's service (RLS hides it → not found).
	if found, err := st.UpdateService(ctx, "globex", false, svc.BusinessServiceID,
		cloud.BusinessService{Name: "pwned"}); err != nil || found {
		t.Fatalf("globex UpdateService of acme's service: found=%v err=%v, want found=false", found, err)
	}
	if found, err := st.DeleteService(ctx, "globex", false, svc.BusinessServiceID); err != nil || found {
		t.Fatalf("globex DeleteService of acme's service: found=%v err=%v, want found=false", found, err)
	}

	// 4) globex cannot clear acme's mapping (invisible → zero rows).
	if found, err := st.ClearMapping(ctx, "globex", false,
		"/subscriptions/s/resourceGroups/rg-payments/providers/Microsoft.Compute/virtualMachines/web01"); err != nil || found {
		t.Fatalf("globex ClearMapping of acme's resource: found=%v err=%v, want found=false", found, err)
	}

	// 5) acme's data survived every cross-tenant attempt intact.
	if svcs, _ := st.ListServices(ctx, "acme", false); len(svcs) != 1 || svcs[0].Name != "payments" {
		t.Fatalf("acme service tampered: %+v", svcs)
	}
	if maps, _ := st.ListMappings(ctx, "acme", false); len(maps) != 1 {
		t.Fatalf("acme mapping tampered, got %d", len(maps))
	}

	// 6) RLS WITH CHECK backstop: a scoped tenant cannot forge a row directly into
	// another tenant's namespace even talking to the DB (42501 = insufficient_privilege).
	rlsDenied := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "42501"
	}
	err = ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO business_services (business_service_id, tenant_id, name)
		    VALUES (gen_random_uuid(), 'acme', 'forged')`)
		return e
	})
	if !rlsDenied(err) {
		t.Fatalf("globex forging a row into acme's namespace must be RLS-denied (42501); got %v", err)
	}

	// 7) platform cross-tenant view sees both tenants' rows (control).
	svc2, err := st.CreateService(ctx, "globex", false,
		cloud.BusinessService{TenantID: "globex", Name: "billing", CreatedBy: "u-globex"})
	if err != nil {
		t.Fatalf("globex CreateService: %v", err)
	}
	_ = svc2
	if all, _ := st.ListServices(ctx, "*", true); len(all) != 2 {
		t.Fatalf("platform cross view should see both services, got %d", len(all))
	}
}
