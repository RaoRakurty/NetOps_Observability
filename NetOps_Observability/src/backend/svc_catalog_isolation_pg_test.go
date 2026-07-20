package main

// svc_catalog_isolation_pg_test.go — CROSS-TENANT isolation for the #69 P2
// surfaces that ride the Postgres service catalog (CLAUDE.md §3a.5, REQUIRED):
// the rollup worker's cross-tenant selector enumeration must stamp each set
// with its OWNING tenant (that stamp is what the isolated per-tenant rollup
// statements are built from), and the store reads behind the backfill + the
// per-service health score must hide another tenant's service entirely (the
// handlers turn found=false into an honest 404).
//
// Runs the store as a freshly-provisioned NON-superuser role so FORCE ROW
// LEVEL SECURITY actually bites. Gated on DATABASE_URL_TEST like every live
// RLS test in this repo.

import (
	"context"
	"os"
	"testing"
)

func TestSvcCatalogCrossTenantIsolation(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres service-catalog isolation test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	st := &pgServiceStore{db: ps.db}

	mk := func(tenant, name string) Service {
		t.Helper()
		svc, err := st.CreateService(ctx, tenant, false, Service{TenantID: tenant, Name: name})
		if err != nil {
			t.Fatalf("%s CreateService: %v", tenant, err)
		}
		if _, err := st.AddSelector(ctx, tenant, false, svc.ServiceID,
			map[string]any{"ports": []any{float64(443)}}, "u-"+tenant); err != nil {
			t.Fatalf("%s AddSelector: %v", tenant, err)
		}
		return svc
	}
	acmeSvc := mk("acme", "acme-teams")
	globexSvc := mk("globex", "globex-sap")

	// 1) The worker's cross-tenant enumeration stamps each set with its OWNING
	// tenant — the invariant every per-tenant rollup statement is built from.
	sets, err := st.ActiveSelectorSets(ctx, 100)
	if err != nil {
		t.Fatalf("ActiveSelectorSets: %v", err)
	}
	owner := map[string]string{acmeSvc.ServiceID: "acme", globexSvc.ServiceID: "globex"}
	seen := 0
	for _, set := range sets {
		want, ours := owner[set.ServiceID]
		if !ours {
			continue // other tests' fixtures may share the database
		}
		seen++
		if set.TenantID != want {
			t.Fatalf("TENANT MIS-STAMP: service %s enumerated under %q, want %q", set.ServiceID, set.TenantID, want)
		}
		if set.Version != 1 || set.Spec == nil {
			t.Fatalf("selector set incomplete: %+v", set)
		}
	}
	if seen != 2 {
		t.Fatalf("enumeration missing fixtures: saw %d of 2", seen)
	}

	// 2) Cross-tenant GetService is invisible (backfill + service health 404 path).
	if _, found, err := st.GetService(ctx, "globex", false, acmeSvc.ServiceID); err != nil || found {
		t.Fatalf("globex must not see acme's service (found=%v err=%v)", found, err)
	}
	// 3) Cross-tenant selectors/bindings reads are empty, never another tenant's.
	if sels, err := st.ListSelectors(ctx, "globex", false, acmeSvc.ServiceID); err != nil || len(sels) != 0 {
		t.Fatalf("globex must not read acme's selectors (n=%d err=%v)", len(sels), err)
	}
	if binds, err := st.ListBindings(ctx, "globex", false, acmeSvc.ServiceID); err != nil || len(binds) != 0 {
		t.Fatalf("globex must not read acme's bindings (n=%d err=%v)", len(binds), err)
	}
	// 4) A tenant cannot append a selector version to another tenant's service
	// (the RLS-scoped existence probe reports not-found → handler 404).
	if _, err := st.AddSelector(ctx, "globex", false, acmeSvc.ServiceID, map[string]any{"ports": []any{float64(53)}}, "mallory"); err == nil {
		t.Fatal("globex appended a selector to acme's service — cross-tenant write leak")
	}
	// 5) Own-tenant view is intact after the attempts above.
	if svcs, err := st.ListServices(ctx, "acme", false, false); err != nil || len(svcs) != 1 || svcs[0].Name != "acme-teams" {
		t.Fatalf("acme's own view broken: %v err=%v", svcs, err)
	}
}
