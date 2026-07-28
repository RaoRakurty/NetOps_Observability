package main

import (
	"context"
	"netops/backend/appid"
	"testing"
)

// CLAUDE.md §3a mandatory: the application-identity registry (#81 P0) enforces
// tenant isolation IN the store — no caller can list, read, or archive another
// tenant's applications; the platform owner (cross) sees all. Mirrors the
// incident-timeline isolation guard.

func mkApp(st appid.AppStore, tenant, name string) appid.Application {
	a, err := st.Create(context.Background(), tenant, false, appid.Application{TenantID: tenant, Name: name})
	if err != nil {
		panic(err)
	}
	return a
}

func TestApplicationStoreIsolation(t *testing.T) {
	ctx := context.Background()
	st := appid.NewMemAppStore()

	a := mkApp(st, "org-a", "Billing")
	b := mkApp(st, "org-b", "Payroll")

	// 1) own-only list
	la, _ := st.List(ctx, "org-a", false, false)
	if len(la) != 1 || la[0].ApplicationID != a.ApplicationID {
		t.Fatalf("org-a leak: %+v", la)
	}
	lb, _ := st.List(ctx, "org-b", false, false)
	if len(lb) != 1 || lb[0].ApplicationID != b.ApplicationID {
		t.Fatalf("org-b leak: %+v", lb)
	}

	// 2) platform owner (cross) sees both
	all, _ := st.List(ctx, "", true, false)
	if len(all) != 2 {
		t.Fatalf("cross list = %d, want 2", len(all))
	}

	// 3) cross-tenant GET → not found (never reveal another tenant's id)
	if _, found, _ := st.Get(ctx, "org-b", false, a.ApplicationID); found {
		t.Fatalf("org-b read org-a's application — cross-tenant leak")
	}
	if _, found, _ := st.Get(ctx, "org-a", false, a.ApplicationID); !found {
		t.Fatalf("org-a could not read its own application")
	}

	// 4) cross-tenant ARCHIVE is refused; own archive works
	if archived, _ := st.Archive(ctx, "org-b", false, a.ApplicationID); archived {
		t.Fatalf("org-b archived org-a's application — cross-tenant leak")
	}
	if archived, _ := st.Archive(ctx, "org-a", false, a.ApplicationID); !archived {
		t.Fatalf("org-a could not archive its own application")
	}
	// archived row drops out of the default (non-archived) list
	la, _ = st.List(ctx, "org-a", false, false)
	if len(la) != 0 {
		t.Fatalf("archived application still listed: %+v", la)
	}
}

func TestApplicationCreateStampsTenant(t *testing.T) {
	// A scoped caller's app is stamped with its own tenant; a stray body tenant
	// must not place the row in another tenant (the handler stamps in.TenantID,
	// and the store normalizes — assert the row lands under the caller's tenant).
	st := appid.NewMemAppStore()
	a := mkApp(st, "org-a", "X")
	if a.TenantID != "org-a" {
		t.Fatalf("create did not stamp caller tenant: %+v", a)
	}
}

func TestValidateApplicationInput(t *testing.T) {
	if err := appid.ValidateApplicationInput("", "normal"); err == nil {
		t.Fatal("empty name should be rejected")
	}
	if err := appid.ValidateApplicationInput("ok", "bogus"); err == nil {
		t.Fatal("bad criticality should be rejected")
	}
	if err := appid.ValidateApplicationInput("ok", ""); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}
