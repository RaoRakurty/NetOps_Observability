package main

import (
	"path/filepath"
	"testing"
)

func TestBuiltinRolesPermissions(t *testing.T) {
	rs, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}
	// Super-admin (and the legacy "admin" alias) passes everything.
	if !rs.Allows(RoleSuperAdmin, "administration", LevelAdmin) {
		t.Error("super-admin should allow administration:admin")
	}
	if !rs.Allows("admin", "administration", LevelAdmin) {
		t.Error("legacy 'admin' should map to super-admin")
	}
	// Operator can write alerts but not touch administration.
	if !rs.Allows(RoleOperator, "alerts", LevelWrite) {
		t.Error("operator should allow alerts:write")
	}
	if rs.Allows(RoleOperator, "administration", LevelAdmin) {
		t.Error("operator must NOT allow administration:admin")
	}
	// Read-only can read overview but not write.
	if !rs.Allows(RoleReadOnly, "overview", LevelRead) {
		t.Error("read-only should allow overview:read")
	}
	if rs.Allows(RoleReadOnly, "alerts", LevelWrite) {
		t.Error("read-only must NOT allow alerts:write")
	}
}

func TestCustomRoleUpsertAndProtectBuiltin(t *testing.T) {
	rs, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}
	r, err := rs.Upsert(Role{Name: "NOC Engineer", Permissions: map[string]int{"alerts": LevelAdmin, "topology": LevelWrite}})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if r.ID != "noc-engineer" || r.Builtin {
		t.Errorf("unexpected custom role: %+v", r)
	}
	if !rs.Allows(r.ID, "alerts", LevelAdmin) || rs.Allows(r.ID, "overview", LevelRead) {
		t.Error("custom role permissions not applied correctly")
	}
	// Cannot overwrite or delete a built-in role.
	if _, err := rs.Upsert(Role{ID: RoleSuperAdmin, Name: "hijack"}); err == nil {
		t.Error("expected error overwriting built-in role")
	}
	if err := rs.Delete(RoleSuperAdmin); err == nil {
		t.Error("expected error deleting built-in role")
	}
}

func TestUserStoreAdminSafe(t *testing.T) {
	us, err := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("newUserStore: %v", err)
	}
	if _, err := us.CreateFull(User{Username: "root", Role: RoleSuperAdmin}, "password123"); err != nil {
		t.Fatalf("create super-admin: %v", err)
	}
	// The last super-admin can't be deleted or demoted.
	if err := us.Delete("root"); err == nil {
		t.Error("expected refusal deleting last super-admin")
	}
	if _, err := us.Update("root", User{Role: RoleReadOnly}); err == nil {
		t.Error("expected refusal demoting last super-admin")
	}
	// Add a second super-admin; now the first can be demoted.
	if _, err := us.CreateFull(User{Username: "root2", Role: RoleSuperAdmin}, "password123"); err != nil {
		t.Fatalf("create second super-admin: %v", err)
	}
	if _, err := us.Update("root", User{Role: RoleReadOnly}); err != nil {
		t.Errorf("demote with a spare super-admin should succeed: %v", err)
	}
}

func TestUserCRUD(t *testing.T) {
	us, err := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("newUserStore: %v", err)
	}
	u, err := us.CreateFull(User{Username: "Dana", Role: RoleOperator, Email: "dana@x.io", TenantID: "acme"}, "")
	if err != nil {
		t.Fatalf("CreateFull: %v", err)
	}
	if u.Status != "active" || u.AuthSource != "local" {
		t.Errorf("defaults not applied: %+v", u)
	}
	if got := us.List(); len(got) != 1 {
		t.Fatalf("List len = %d, want 1", len(got))
	}
	if _, err := us.Update("dana", User{DisplayName: "Dana Ops", Status: "disabled"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := us.Get("dana")
	if got.DisplayName != "Dana Ops" || got.Status != "disabled" {
		t.Errorf("update not persisted: %+v", got)
	}
	if err := us.Delete("dana"); err != nil {
		t.Errorf("Delete operator should succeed: %v", err)
	}
}

func TestTenantStore(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	if _, ok := ts.Get(TenantGlobal); !ok {
		t.Fatal("Global tenant should be seeded")
	}
	if err := ts.Delete(TenantGlobal); err == nil {
		t.Error("expected refusal deleting Global tenant")
	}
	tn, err := ts.Create("Acme Corp", "isolated")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tn.ID != "acme-corp" {
		t.Errorf("slug = %q, want acme-corp", tn.ID)
	}
	if err := ts.Delete(tn.ID); err != nil {
		t.Errorf("delete custom tenant: %v", err)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	ks, err := newAPIKeyStore(filepath.Join(t.TempDir(), "apikeys.json"))
	if err != nil {
		t.Fatalf("newAPIKeyStore: %v", err)
	}
	rec, secret, err := ks.Create("acme", "ci", "root", []string{"read:metrics"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if secret == "" || rec.ID == "" {
		t.Fatal("expected a secret + id")
	}
	if _, ok := ks.Verify(secret); !ok {
		t.Error("freshly created key should verify")
	}
	if _, ok := ks.Verify("ntk_wrong"); ok {
		t.Error("bogus key must not verify")
	}
	if err := ks.Revoke(rec.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := ks.Verify(secret); ok {
		t.Error("revoked key must not verify")
	}
}
