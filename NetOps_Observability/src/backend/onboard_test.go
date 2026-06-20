package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestOnboardEndpoint: the operator one-step onboard mints an org + first tenant
// with opaque ids, refuses non-owners, validates input, and rolls the org back if
// the tenant fails.
func TestOnboardEndpoint(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// happy path
	st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
		"org_name": "Acme Corp", "home_region": "us-east",
		"tenant_name": "Acme Prod", "tenant_slug": "acme-prod",
	})
	if st != 201 {
		t.Fatalf("onboard: %d %s", st, b)
	}
	var resp onboardResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if !isOrgID(resp.Org.ID) || resp.Org.Slug != "acme-corp" {
		t.Errorf("org: want opaque id + slug acme-corp, got %+v", resp.Org)
	}
	if !isTenantID(resp.Tenant.ID) || resp.Tenant.Slug != "acme-prod" {
		t.Errorf("tenant: want opaque id + slug acme-prod, got %+v", resp.Tenant)
	}
	if resp.Tenant.OrgID != resp.Org.ID {
		t.Errorf("tenant.OrgID = %q, want the new org's opaque id %q", resp.Tenant.OrgID, resp.Org.ID)
	}

	// missing tenant_name → 400 (an org is never onboarded tenant-less)
	if st, _ := do(t, srv, "POST", "/api/onboard", admin, map[string]any{"org_name": "NoTenant Inc"}); st != 400 {
		t.Errorf("onboard without tenant_name: got %d, want 400", st)
	}

	// a non-owner cannot onboard
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "tu", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": resp.Tenant.ID,
	}); st != 201 {
		t.Fatalf("create tenant user: %d %s", st, b)
	}
	tu := login(t, srv, "tu", "Passw0rd!2345").Token
	if st, _ := do(t, srv, "POST", "/api/onboard", tu, map[string]any{
		"org_name": "Sneaky", "tenant_name": "Sneaky T",
	}); st != 403 {
		t.Errorf("non-owner onboard: got %d, want 403", st)
	}
}

// TestTenantSuspensionBlocksLogin: a suspended tenant's users cannot sign in;
// reactivation restores access; the platform owner is unaffected.
func TestTenantSuspensionBlocksLogin(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
		"org_name": "Acme Corp", "tenant_name": "Acme Prod", "tenant_slug": "acme-prod",
	})
	if st != 201 {
		t.Fatalf("onboard: %d %s", st, b)
	}
	var resp onboardResponse
	_ = json.Unmarshal(b, &resp)

	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "alice", "password": "Passw0rd!2345", "role": "operator", "tenant_id": resp.Tenant.ID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	// alice can sign in while the tenant is active.
	if got := login(t, srv, "alice", "Passw0rd!2345"); got.Token == "" {
		t.Fatal("alice should be able to sign in while active")
	}

	// suspend the tenant
	if st, b := do(t, srv, "PATCH", "/api/tenants/"+resp.Tenant.ID, admin, map[string]any{"status": "suspended"}); st != 200 {
		t.Fatalf("suspend tenant: %d %s", st, b)
	}
	// alice can no longer sign in (403 tenant suspended).
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "alice", "password": "Passw0rd!2345"}); st != 403 {
		t.Errorf("login into suspended tenant: got %d, want 403", st)
	}
	// the platform owner is unaffected.
	if got := login(t, srv, "admin", "Passw0rd!2345"); got.Token == "" {
		t.Error("platform owner must still sign in while a tenant is suspended")
	}

	// reactivate → alice can sign in again.
	if st, _ := do(t, srv, "PATCH", "/api/tenants/"+resp.Tenant.ID, admin, map[string]any{"status": "active"}); st != 200 {
		t.Fatalf("reactivate: %d", st)
	}
	if got := login(t, srv, "alice", "Passw0rd!2345"); got.Token == "" {
		t.Error("alice should sign in again after reactivation")
	}
}

// TestSetStatusGuards: invalid status rejected; the global tenant can't be suspended.
func TestSetStatusGuards(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	tn, _ := ts.Create("Acme", "acme", "", "", "")
	if _, err := ts.SetStatus("acme", "bogus"); err == nil {
		t.Error("invalid status should be rejected")
	}
	if got, err := ts.SetStatus(tn.ID, TenantStatusSuspended); err != nil || got.status() != TenantStatusSuspended {
		t.Errorf("suspend by id: %+v err=%v", got, err)
	}
	// resolve by slug too
	if got, err := ts.SetStatus("acme", TenantStatusActive); err != nil || got.status() != TenantStatusActive {
		t.Errorf("reactivate by slug: %+v err=%v", got, err)
	}
	if _, err := ts.SetStatus(TenantGlobal, TenantStatusSuspended); err == nil {
		t.Error("the global tenant must not be suspendable")
	}
}
