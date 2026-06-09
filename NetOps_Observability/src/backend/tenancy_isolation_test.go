package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTenantIsolationHTTP proves namespace-grade isolation through the real
// router: a tenant-bound super-admin sees ONLY its own tenant and can neither
// see/delete the platform admin nor mutate platform-wide resources (tenants,
// roles). The cross-tenant platform owner still sees everything. This is the
// regression guard for the reported leak (a tenant super-admin acting globally).
func TestTenantIsolationHTTP(t *testing.T) {
	srv := newTestServer(t) // seeds admin/Passw0rd!2345 = platform owner (super-admin, global)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Platform owner provisions two isolated tenants' admins.
	mk := func(user, tenant string) {
		st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": tenant,
		})
		if st != 201 {
			t.Fatalf("create %s: %d: %s", user, st, b)
		}
	}
	mk("alice", "acme")
	mk("bob", "globex")

	alice := login(t, srv, "alice", "Passw0rd!2345").Token

	// 1) alice (tenant=acme super-admin) sees ONLY herself — not the platform
	//    admin, not bob (globex).
	st, b := do(t, srv, "GET", "/api/users", alice, nil)
	if st != 200 {
		t.Fatalf("alice list users: %d", st)
	}
	var users []map[string]any
	if err := json.Unmarshal(b, &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0]["username"] != "alice" {
		t.Fatalf("tenant leak: alice should see only herself, got %s", b)
	}
	if strings.Contains(string(b), "\"admin\"") || strings.Contains(string(b), "bob") {
		t.Fatalf("tenant leak: alice sees other tenants' users: %s", b)
	}

	// 2) alice cannot see/delete the platform admin (404, not 403 — no existence leak).
	if st, _ := do(t, srv, "DELETE", "/api/users/admin", alice, nil); st != 404 {
		t.Fatalf("alice deleting platform admin: got %d, want 404", st)
	}
	// nor bob in another tenant
	if st, _ := do(t, srv, "DELETE", "/api/users/bob", alice, nil); st != 404 {
		t.Fatalf("alice deleting cross-tenant user: got %d, want 404", st)
	}

	// 3) alice cannot mutate platform-wide resources.
	if st, _ := do(t, srv, "POST", "/api/tenants", alice, map[string]string{"name": "evil"}); st != 403 {
		t.Fatalf("alice creating a tenant: got %d, want 403", st)
	}
	if st, _ := do(t, srv, "POST", "/api/roles", alice, map[string]any{"name": "evil"}); st != 403 {
		t.Fatalf("alice creating a role: got %d, want 403", st)
	}

	// 4) the platform owner still sees everyone (admin + alice + bob).
	st, b = do(t, srv, "GET", "/api/users", admin, nil)
	if st != 200 {
		t.Fatalf("admin list: %d", st)
	}
	if err := json.Unmarshal(b, &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Fatalf("platform owner should see all 3 users, got %d: %s", len(users), b)
	}
}
