package main

import (
	"encoding/json"
	"testing"
)

// TestOrgHTTPLifecycle exercises the org REST surface end-to-end through the
// real router as the platform owner: create → list → patch → org-aware tenant
// create → delete guard → delete.
func TestOrgHTTPLifecycle(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// create
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{
		"name": "Acme Corp", "home_region": "eu-central", "sso_connection": "acme-okta",
	})
	if st != 201 {
		t.Fatalf("create org: %d: %s", st, b)
	}
	var org Org
	if err := json.Unmarshal(b, &org); err != nil {
		t.Fatal(err)
	}
	if org.Slug != "acme-corp" || org.HomeRegion != "eu-central" {
		t.Fatalf("unexpected org: %+v", org)
	}
	if org.ID == "acme-corp" || !isOrgID(org.ID) {
		t.Fatalf("org id should be opaque (org_…), not the slug: %+v", org)
	}

	// unknown region rejected
	if st, _ := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Bad", "home_region": "mars"}); st != 400 {
		t.Errorf("bad region: got %d, want 400", st)
	}

	// list contains Global + Acme
	st, b = do(t, srv, "GET", "/api/orgs", admin, nil)
	if st != 200 {
		t.Fatalf("list orgs: %d", st)
	}
	var orgs []Org
	if err := json.Unmarshal(b, &orgs); err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 2 || orgs[0].ID != OrgGlobal {
		t.Fatalf("expected [global, acme-corp], got %s", b)
	}

	// patch region
	st, b = do(t, srv, "PATCH", "/api/orgs/acme-corp", admin, map[string]any{"home_region": "us-west"})
	if st != 200 {
		t.Fatalf("patch org: %d: %s", st, b)
	}
	if err := json.Unmarshal(b, &org); err != nil {
		t.Fatal(err)
	}
	if org.HomeRegion != "us-west" {
		t.Errorf("patch region = %q, want us-west", org.HomeRegion)
	}

	// create a tenant under the org
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"})
	if st != 201 {
		t.Fatalf("create tenant in org: %d: %s", st, b)
	}
	var tn Tenant
	if err := json.Unmarshal(b, &tn); err != nil {
		t.Fatal(err)
	}
	// org_id slug is resolved to the opaque org id at the boundary; the tenant
	// stores the opaque id, not the slug.
	if tn.OrgID == "acme-corp" || !isOrgID(tn.OrgID) {
		t.Errorf("tenant org = %q, want the opaque org_ id (resolved from slug acme-corp)", tn.OrgID)
	}

	// tenant create with unknown org is rejected
	if st, _ := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Ghost", "org_id": "nope"}); st != 400 {
		t.Errorf("tenant in unknown org: got %d, want 400", st)
	}

	// delete guard: org still owns a tenant → 409
	if st, _ := do(t, srv, "DELETE", "/api/orgs/acme-corp", admin, nil); st != 409 {
		t.Errorf("delete populated org: got %d, want 409", st)
	}

	// remove the tenant, then the org deletes
	if st, _ := do(t, srv, "DELETE", "/api/tenants/acme-prod?confirm=Acme%20Prod", admin, nil); st != 204 {
		t.Fatalf("delete tenant: got %d", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/orgs/acme-corp", admin, nil); st != 204 {
		t.Errorf("delete empty org: got %d, want 204", st)
	}

	// Global org is permanent
	if st, _ := do(t, srv, "DELETE", "/api/orgs/global", admin, nil); st == 204 {
		t.Error("Global org should not be deletable")
	}
}

// TestOrgHTTPAuthz proves a tenant-scoped admin cannot create/patch/delete orgs
// and sees only its own org in the list.
func TestOrgHTTPAuthz(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// platform owner makes an org + a tenant in it + a tenant admin there.
	if st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Acme Corp"}); st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	if st, _ := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"}); st != 201 {
		t.Fatal("create tenant")
	}
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "alice", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": "acme-prod",
	}); st != 201 {
		t.Fatalf("create alice: %d %s", st, b)
	}
	alice := login(t, srv, "alice", "Passw0rd!2345").Token

	// alice cannot create or mutate orgs
	if st, _ := do(t, srv, "POST", "/api/orgs", alice, map[string]any{"name": "evil"}); st != 403 {
		t.Errorf("alice create org: got %d, want 403", st)
	}
	if st, _ := do(t, srv, "PATCH", "/api/orgs/global", alice, map[string]any{"note": "x"}); st != 403 {
		t.Errorf("alice patch org: got %d, want 403", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/orgs/acme-corp", alice, nil); st != 403 {
		t.Errorf("alice delete org: got %d, want 403", st)
	}

	// alice's org list shows only her org (acme-corp), not Global.
	st, b := do(t, srv, "GET", "/api/orgs", alice, nil)
	if st != 200 {
		t.Fatalf("alice list orgs: %d", st)
	}
	var orgs []Org
	if err := json.Unmarshal(b, &orgs); err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 1 || orgs[0].Slug != "acme-corp" {
		t.Fatalf("alice should see only acme-corp, got %s", b)
	}

	// /api/me surfaces the caller's org: alice → acme-corp, platform owner → global.
	st, b = do(t, srv, "GET", "/api/auth/me", alice, nil)
	if st != 200 {
		t.Fatalf("alice /me: %d", st)
	}
	var me struct {
		OrgID         string `json:"org_id"`
		PlatformAdmin bool   `json:"platform_admin"`
	}
	if err := json.Unmarshal(b, &me); err != nil {
		t.Fatal(err)
	}
	// alice's org is the opaque acme-corp id (not the slug, not the platform owner).
	if !isOrgID(me.OrgID) || me.OrgID == "acme-corp" || me.PlatformAdmin {
		t.Errorf("alice /me org_id=%q platform_admin=%v, want opaque acme-corp id / false", me.OrgID, me.PlatformAdmin)
	}
	_, b = do(t, srv, "GET", "/api/auth/me", admin, nil)
	_ = json.Unmarshal(b, &me)
	if me.OrgID != OrgGlobal || !me.PlatformAdmin {
		t.Errorf("admin /me org_id=%q platform_admin=%v, want global/true", me.OrgID, me.PlatformAdmin)
	}
}
