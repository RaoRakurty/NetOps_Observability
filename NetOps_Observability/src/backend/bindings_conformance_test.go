package main

import (
	"netops/backend/internal/users"
	"testing"
	"time"
)

// newPBACTestServer builds a minimal server with the identity stores wired for
// binding/scope unit tests (no HTTP).
func newPBACTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	us, err := users.NewFileStore(dir+"/users.json", userDeps())
	if err != nil {
		t.Fatal(err)
	}
	ts, err := newTenantStore(dir + "/tenants.json")
	if err != nil {
		t.Fatal(err)
	}
	os, err := newOrgStore(dir + "/orgs.json")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := newBindingStore(dir + "/role_bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	return &server{users: us, tenants: ts, orgs: os, bindings: bs}
}

// TestBindingConformance is the Phase-A safety proof: for every user, the
// binding-derived (tenant, cross) MUST equal the legacy claims path
// (principalTenant + isPlatformOwner). If this passes, switching the decider to
// read bindings (Phase B) changes no decision.
func TestBindingConformance(t *testing.T) {
	s := newPBACTestServer(t)
	if err := s.users.SeedAdmin("admin", "Passw0rd!2345"); err != nil {
		t.Fatal(err)
	}
	// A spread of users across tenants/roles.
	mk := func(name, role, tenant string) {
		if _, err := s.users.CreateFull(User{Username: name, Role: role, TenantID: tenant}, "Passw0rd!2345"); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("acme-admin", "super-admin", "acme")
	mk("acme-op", "operator", "acme")
	mk("globex-ro", "read-only", "globex")
	mk("global-op", "operator", "global") // operator in global is NOT a platform owner

	s.backfillBindings()

	for _, u := range s.users.List(TenantGlobal, true) {
		// Legacy path: build the claim the login flow would mint.
		c := jwtClaims{Sub: u.Username, Role: u.Role, Tenant: u.TenantID}
		wantTenant, wantCross := principalTenant(c)
		wantOwner := isPlatformOwner(c)

		// Binding path.
		gotTenant, gotCross := s.bindingDerivedScope(u.Username)

		if gotCross != wantCross || gotCross != wantOwner {
			t.Errorf("%s: binding cross=%v, principalTenant cross=%v, isPlatformOwner=%v", u.Username, gotCross, wantCross, wantOwner)
		}
		// For a scoped (non-cross) principal the tenant must match exactly.
		if !wantCross && gotTenant != wantTenant {
			t.Errorf("%s: binding tenant=%q, want %q", u.Username, gotTenant, wantTenant)
		}
	}
}

// TestBindingSyncOnRoleChange proves the mirror re-syncs when a user's role or
// tenant changes (no stale binding left behind — exactly one per principal).
func TestBindingSyncOnRoleChange(t *testing.T) {
	s := newPBACTestServer(t)
	u, err := s.users.CreateFull(User{Username: "alice", Role: "operator", TenantID: "acme"}, "Passw0rd!2345")
	if err != nil {
		t.Fatal(err)
	}
	s.syncUserBinding(u)
	if got := s.bindings.ListByPrincipal("alice"); len(got) != 1 || got[0].RoleID != "operator" || got[0].ScopeID != scopeTenant("acme") {
		t.Fatalf("initial binding wrong: %+v", got)
	}
	v1 := s.bindings.Version("alice")

	// Promote alice to super-admin and move her to globex.
	u2, err := s.users.Update("alice", User{Role: "super-admin", TenantID: "globex"})
	if err != nil {
		t.Fatal(err)
	}
	s.syncUserBinding(u2)
	got := s.bindings.ListByPrincipal("alice")
	if len(got) != 1 {
		t.Fatalf("expected exactly one binding after re-sync, got %d: %+v", len(got), got)
	}
	if got[0].RoleID != "super-admin" || got[0].ScopeID != scopeTenant("globex") {
		t.Errorf("re-synced binding wrong: %+v", got[0])
	}
	if s.bindings.Version("alice") <= v1 {
		t.Error("bindings_version should bump on re-sync")
	}

	// Delete drops the binding.
	s.removeUserBindings("alice")
	if got := s.bindings.ListByPrincipal("alice"); len(got) != 0 {
		t.Errorf("bindings should be gone after delete, got %+v", got)
	}
}

// TestScopeAncestor proves ancestor-or-self traversal over the derived tree.
func TestScopeAncestor(t *testing.T) {
	s := newPBACTestServer(t)
	if _, err := s.orgs.Create("Acme Corp", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tenants.Create("Acme Prod", "", "", "", "acme-corp"); err != nil {
		t.Fatal(err)
	}
	tenantScope := scopeTenant("acme-prod")
	orgScope := scopeOrg("acme-corp")

	cases := []struct {
		anc, desc string
		want      bool
	}{
		{ScopePlatform, tenantScope, true},      // platform is ancestor of everything
		{orgScope, tenantScope, true},           // org is ancestor of its tenant
		{tenantScope, tenantScope, true},        // self
		{tenantScope, orgScope, false},          // tenant is NOT ancestor of its org
		{scopeOrg("other"), tenantScope, false}, // unrelated org
	}
	for _, c := range cases {
		if got := s.scopeAncestorOrSelf(c.anc, c.desc); got != c.want {
			t.Errorf("ancestorOrSelf(%q,%q)=%v, want %v", c.anc, c.desc, got, c.want)
		}
	}
}

// TestBindingExpiry proves time-bounded (break-glass) bindings are inactive
// outside their window — the mechanic Phase B/C break-glass relies on.
func TestBindingExpiry(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	expired := RoleBinding{ExpiresAt: &past}
	if expired.active(now) {
		t.Error("expired binding should be inactive")
	}
	notYet := RoleBinding{NotBefore: &future}
	if notYet.active(now) {
		t.Error("not-yet-active binding should be inactive")
	}
	live := RoleBinding{NotBefore: &past, ExpiresAt: &future}
	if !live.active(now) {
		t.Error("in-window binding should be active")
	}
}
