package main

import (
	"context"
	"os"
	"testing"
)

// TestPgUsersStore exercises the Postgres user repository end to end against a
// live database. It is the #33 counterpart to TestPgAuditStore: it proves the
// per-request RLS-scoped List, the platform-scope (tenant-blind) Get the login
// path depends on, partial updates, the cross-tenant last-super-admin invariant,
// the MAX_USERS cap with its federated exemption, and password round-trips.
//
// Gated on DATABASE_URL_TEST (a superuser that provisions a non-superuser app
// role, so FORCE RLS actually enforces — a superuser would bypass it).
func TestPgUsersStore(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres users test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	s := &pgUsersStore{db: ps.db}

	// Seed two tenants' users (mixed case to prove tenant-id normalization), plus
	// a platform user with no tenant.
	if _, err := s.CreateFull(User{Username: "Alice", Role: RoleOperator, TenantID: "Acme"}, "password123"); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := s.CreateFull(User{Username: "carol", Role: RoleReadOnly, TenantID: "globex"}, "password123"); err != nil {
		t.Fatalf("create carol: %v", err)
	}
	if _, err := s.Create("root", "password123", RoleSuperAdmin); err != nil { // platform super-admin, no tenant
		t.Fatalf("create root: %v", err)
	}

	// ---- per-request RLS-scoped List ----
	if got := len(s.List("", true)); got != 3 {
		t.Errorf("platform List = %d, want 3 (sees all)", got)
	}
	acme := s.List("acme", false)
	if len(acme) != 1 || acme[0].Username != "Alice" {
		t.Errorf("acme List = %+v, want only Alice (RLS hides other tenants + platform)", acme)
	}
	for _, u := range acme {
		if normTenant(u.TenantID) != "acme" {
			t.Errorf("USER LEAK: acme scope saw tenant %q", u.TenantID)
		}
	}
	if got := len(s.List("globex", false)); got != 1 {
		t.Errorf("globex List = %d, want 1", got)
	}

	// ---- Get is platform-scope (tenant-blind): login must resolve any tenant's
	// user before a scope exists, and the lookup is case-insensitive. ----
	if u, ok := s.Get("ALICE"); !ok || normTenant(u.TenantID) != "acme" {
		t.Errorf("Get(ALICE) = %+v ok=%v, want acme user found", u, ok)
	}
	if u, ok := s.Get("carol"); !ok || !verifyPassword("password123", u.PasswordHash) {
		t.Errorf("Get(carol) should round-trip the password hash, got ok=%v", ok)
	}
	if _, ok := s.Get("nobody"); ok {
		t.Error("Get(nobody) should report not found")
	}

	// ---- duplicate rejection (case-insensitive) ----
	if _, err := s.CreateFull(User{Username: "alice", TenantID: "acme"}, "password123"); err == nil {
		t.Error("duplicate username (case-insensitive) must be rejected")
	}

	// ---- partial update: change one field, others preserved, tenant column tracks ----
	if _, err := s.Update("alice", User{DisplayName: "Alice Ops", Status: "disabled"}); err != nil {
		t.Fatalf("update alice: %v", err)
	}
	got, _ := s.Get("alice")
	if got.DisplayName != "Alice Ops" || got.Status != "disabled" || got.Role != RoleOperator {
		t.Errorf("partial update wrong: %+v (role should be preserved)", got)
	}

	// ---- last-super-admin invariant is platform-wide ----
	if _, err := s.Update("root", User{Role: RoleReadOnly}); err == nil {
		t.Error("demoting the last super-admin must be refused")
	}
	if err := s.Delete("root"); err == nil {
		t.Error("deleting the last super-admin must be refused")
	}
	// With a second super-admin present, the first may be demoted.
	if _, err := s.CreateFull(User{Username: "root2", Role: RoleSuperAdmin}, "password123"); err != nil {
		t.Fatalf("create root2: %v", err)
	}
	if _, err := s.Update("root", User{Role: RoleReadOnly}); err != nil {
		t.Errorf("demote with a spare super-admin should succeed: %v", err)
	}

	// ---- password change round-trips ----
	if err := s.ChangePassword("carol", "newpassword456"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if u, _ := s.Get("carol"); !verifyPassword("newpassword456", u.PasswordHash) || verifyPassword("password123", u.PasswordHash) {
		t.Error("password change did not take effect")
	}
	if err := s.ChangePassword("carol", "short"); err == nil {
		t.Error("short password must be rejected")
	}

	// ---- delete a non-last-super-admin ----
	if err := s.Delete("carol"); err != nil {
		t.Errorf("deleting a regular user should succeed: %v", err)
	}
	if _, ok := s.Get("carol"); ok {
		t.Error("carol should be gone after delete")
	}
}

// TestPgUsersStoreCapAndFederated checks the MAX_USERS cap blocks local creates
// while federated JIT provisioning stays exempt — the same rule the file store
// enforces, so SSO can never be locked out at the cap.
func TestPgUsersStoreCapAndFederated(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres users cap test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	s := &pgUsersStore{db: ps.db, maxUsers: 2}

	if _, err := s.Create("alice", "password123", RoleReadOnly); err != nil {
		t.Fatalf("1st create: %v", err)
	}
	if _, err := s.CreateFull(User{Username: "bob", Role: RoleReadOnly}, "password123"); err != nil {
		t.Fatalf("2nd create: %v", err)
	}
	if _, err := s.Create("carol", "password123", RoleReadOnly); err == nil {
		t.Error("Create past the cap must fail")
	}
	if _, err := s.CreateFull(User{Username: "dave", Role: RoleReadOnly}, "password123"); err == nil {
		t.Error("CreateFull past the cap must fail")
	}

	// Federated provisioning is cap-exempt; first login creates, second refreshes.
	ext, err := s.UpsertFederated("ext-user", "e@x.com", "Ext", RoleReadOnly, "oidc", "acme")
	if err != nil {
		t.Fatalf("federated provisioning should bypass the cap: %v", err)
	}
	if ext.AuthSource != "oidc" || normTenant(ext.TenantID) != "acme" {
		t.Errorf("federated user wrong: %+v", ext)
	}
	if again, err := s.UpsertFederated("ext-user", "new@x.com", "Ext2", RoleOperator, "oidc", "acme"); err != nil {
		t.Errorf("federated refresh: %v", err)
	} else if again.Email != "new@x.com" || again.Role != RoleOperator {
		t.Errorf("federated refresh did not sync IdP attributes: %+v", again)
	}
}
