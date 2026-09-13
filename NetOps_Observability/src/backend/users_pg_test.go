// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/token"
	"netops/backend/internal/users"
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
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	s, err := users.NewPGStore(ps.DB(), userDeps())
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}

	// Seed two tenants' users (mixed case to prove tenant-id normalization), plus
	// a platform user with no tenant. Tracker 300 §2.1: the account's key is the
	// opaque principal id on the RETURNED User — the login name is a handle, so
	// every mutator below is called with u.ID, never with the typed name.
	alice, err := s.CreateFull(User{Username: "Alice", Role: RoleOperator, TenantID: "Acme"}, "Passw0rd!2345")
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	carol, err := s.CreateFull(User{Username: "carol", Role: RoleReadOnly, TenantID: "globex"}, "Passw0rd!2345")
	if err != nil {
		t.Fatalf("create carol: %v", err)
	}
	root, err := s.Create("root", "Passw0rd!2345", RoleSuperAdmin) // platform super-admin, no tenant
	if err != nil {
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
	// user before a scope exists. It is keyed by the immutable principal id
	// (tracker 300 §2.1); the login HANDLE is resolved through the identity table
	// (§2.5), which is where the case-insensitivity now lives. ----
	if u, ok := s.Get(alice.ID); !ok || normTenant(u.TenantID) != "acme" {
		t.Errorf("Get(%q) = %+v ok=%v, want acme user found", alice.ID, u, ok)
	}
	// Tenant-blind, case-insensitive resolution of the typed name: the unbound
	// login form (§2.5 LookupLocalAny) — exactly one account, alice's.
	if got, ok := s.LookupLocalAny("ALICE"); !ok || len(got) != 1 || got[0].ID != alice.ID || normTenant(got[0].TenantID) != "acme" {
		t.Errorf("LookupLocalAny(ALICE) = %+v ok=%v, want exactly alice (%q) in acme", got, ok, alice.ID)
	}
	// …and bound to one tenant when the per-tenant sign-in URL supplies it.
	if u, ok := s.LookupLocal("Acme", "ALICE"); !ok || u.ID != alice.ID {
		t.Errorf("LookupLocal(Acme, ALICE) = %+v ok=%v, want alice (%q)", u, ok, alice.ID)
	}
	// A local handle belongs to ONE tenant: alice must not resolve inside globex.
	if u, ok := s.LookupLocal("globex", "alice"); ok {
		t.Errorf("USER LEAK: LookupLocal(globex, alice) resolved %+v from another tenant", u)
	}
	if u, ok := s.Get(carol.ID); !ok || !token.VerifyPassword("Passw0rd!2345", u.PasswordHash) {
		t.Errorf("Get(carol) should round-trip the password hash, got ok=%v", ok)
	}
	if _, ok := s.Get("nobody"); ok {
		t.Error("Get(nobody) should report not found")
	}
	if _, ok := s.LookupLocalAny("nobody"); ok {
		t.Error("LookupLocalAny(nobody) should report not found")
	}

	// ---- duplicate rejection (case-insensitive, within the tenant) ----
	if _, err := s.CreateFull(User{Username: "alice", TenantID: "acme"}, "Passw0rd!2345"); err == nil {
		t.Error("duplicate username (case-insensitive) must be rejected")
	}

	// ---- partial update: change one field, others preserved, tenant column tracks ----
	if _, err := s.Update(alice.ID, User{DisplayName: "Alice Ops", Status: "disabled"}); err != nil {
		t.Fatalf("update alice: %v", err)
	}
	got, _ := s.Get(alice.ID)
	if got.DisplayName != "Alice Ops" || got.Status != "disabled" || got.Role != RoleOperator {
		t.Errorf("partial update wrong: %+v (role should be preserved)", got)
	}

	// ---- last-super-admin invariant is platform-wide ----
	if _, err := s.Update(root.ID, User{Role: RoleReadOnly}); err == nil {
		t.Error("demoting the last super-admin must be refused")
	}
	if err := s.Delete(root.ID); err == nil {
		t.Error("deleting the last super-admin must be refused")
	}
	// With a second super-admin present, the first may be demoted.
	if _, err := s.CreateFull(User{Username: "root2", Role: RoleSuperAdmin}, "Passw0rd!2345"); err != nil {
		t.Fatalf("create root2: %v", err)
	}
	if _, err := s.Update(root.ID, User{Role: RoleReadOnly}); err != nil {
		t.Errorf("demote with a spare super-admin should succeed: %v", err)
	}

	// ---- password change round-trips ----
	if err := s.ChangePassword(carol.ID, "newpassword456"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if u, _ := s.Get(carol.ID); !token.VerifyPassword("newpassword456", u.PasswordHash) || token.VerifyPassword("Passw0rd!2345", u.PasswordHash) {
		t.Error("password change did not take effect")
	}
	if err := s.ChangePassword(carol.ID, "short"); err == nil {
		t.Error("short password must be rejected")
	}

	// ---- delete a non-last-super-admin ----
	if err := s.Delete(carol.ID); err != nil {
		t.Errorf("deleting a regular user should succeed: %v", err)
	}
	if _, ok := s.Get(carol.ID); ok {
		t.Error("carol should be gone after delete")
	}
	// The login handle goes with the account: nothing resolves it any more.
	if _, ok := s.LookupLocal("globex", "carol"); ok {
		t.Error("carol's local handle should be released by delete")
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
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	d := userDeps()
	d.MaxUsers = 2
	s, err := users.NewPGStore(ps.DB(), d)
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}

	if _, err := s.Create("alice", "Passw0rd!2345", RoleReadOnly); err != nil {
		t.Fatalf("1st create: %v", err)
	}
	if _, err := s.CreateFull(User{Username: "bob", Role: RoleReadOnly}, "Passw0rd!2345"); err != nil {
		t.Fatalf("2nd create: %v", err)
	}
	if _, err := s.Create("carol", "Passw0rd!2345", RoleReadOnly); err == nil {
		t.Error("Create past the cap must fail")
	}
	if _, err := s.CreateFull(User{Username: "dave", Role: RoleReadOnly}, "Passw0rd!2345"); err == nil {
		t.Error("CreateFull past the cap must fail")
	}

	// Federated provisioning is cap-exempt; first login creates, second refreshes.
	// Resolved by the canonical tuple (tracker 300), so the SAME tuple twice is
	// one account and the profile is what gets refreshed.
	extAssertion := func(email, display, role string) users.Assertion {
		return users.Assertion{
			Identity: users.Identity{
				TenantID: "acme", Issuer: "https://kc.example.test/realms/x",
				Subject: "kc-sub-ext", Protocol: users.ProtocolOIDC,
			},
			Email: email, DisplayName: display, Role: role,
		}
	}
	ext, err := s.ResolveFederatedUnbound(extAssertion("e@x.com", "Ext", RoleReadOnly))
	if err != nil {
		t.Fatalf("federated provisioning should bypass the cap: %v", err)
	}
	if ext.AuthSource != "oidc" || normTenant(ext.TenantID) != "acme" {
		t.Errorf("federated user wrong: %+v", ext)
	}
	if again, err := s.ResolveFederatedUnbound(extAssertion("new@x.com", "Ext2", RoleOperator)); err != nil {
		t.Errorf("federated refresh: %v", err)
	} else if again.ID != ext.ID {
		t.Errorf("the same tuple resolved to a second account: %q then %q", ext.ID, again.ID)
	} else if again.Email != "new@x.com" || again.Role != RoleOperator {
		t.Errorf("federated refresh did not sync IdP attributes: %+v", again)
	}
}
