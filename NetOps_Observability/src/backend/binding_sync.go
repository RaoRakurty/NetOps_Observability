package main

// binding_sync.go — Phase A glue that keeps the role_binding store (bindings.go)
// a faithful mirror of the legacy single-(role,tenant) user model, so the
// auditable artifact lands WITHOUT changing any authorization decision.
//
// Each user ⇒ one principal (id = username) ⇒ one allow binding at its tenant
// scope. The platform owner (super-admin in the global tenant) maps to a
// super-admin binding at tenant:global, which bindingDerivedScope resolves back
// to cross-tenant — identical to isPlatformOwner. A conformance test
// (bindings_conformance_test.go) proves the round-trip for every user.
//
// Phase B flips the authoritative decider to read these bindings (union) and
// lets a principal hold many; this file is where create/update/delete user
// mutations re-sync the mirror in the meantime.

import (
	"strings"
	"time"
)

// userBindingScope is the canonical scope id for a user's single Phase-A binding:
// its tenant (blank tenant → the Global tenant, matching isPlatformOwner).
func userBindingScope(u User) string {
	t := strings.ToLower(strings.TrimSpace(u.TenantID))
	if t == "" {
		t = TenantGlobal
	}
	return scopeTenant(t)
}

// syncUserBinding makes the binding store reflect the user's current role+tenant:
// it drops any stale bindings for the principal and writes the single mirror
// binding. Idempotent (deterministic binding id), safe to call repeatedly.
func (s *server) syncUserBinding(u User) {
	if s.bindings == nil || strings.TrimSpace(u.Username) == "" {
		return
	}
	pid := strings.ToLower(strings.TrimSpace(u.Username))
	want := bindingID(pid, u.Role, userBindingScope(u), EffectAllow)
	// Remove any binding for this principal that isn't the desired mirror (so a
	// role/tenant change re-syncs cleanly). Phase A holds exactly one per user.
	for _, b := range s.bindings.ListByPrincipal(pid) {
		if b.ID != want {
			_ = s.bindings.Remove(b.ID)
		}
	}
	_, _ = s.bindings.Add(RoleBinding{
		PrincipalID: pid,
		RoleID:      u.Role,
		ScopeType:   scopeTypeTenant,
		ScopeID:     userBindingScope(u),
		Effect:      EffectAllow,
		GrantedBy:   "system:sync",
		Reason:      "Phase A mirror of legacy user role+tenant",
	})
}

// removeUserBindings drops a deleted user's bindings.
func (s *server) removeUserBindings(username string) {
	if s.bindings == nil {
		return
	}
	_ = s.bindings.RemoveByPrincipal(username)
}

// backfillBindings ensures every existing user has its mirror binding. Called
// once at startup; idempotent.
func (s *server) backfillBindings() {
	if s.bindings == nil || s.users == nil {
		return
	}
	for _, u := range s.users.List(TenantGlobal, true) { // cross-tenant: every user
		s.syncUserBinding(u)
	}
}

// bindingDerivedScope resolves a principal's active bindings into the same
// (tenant, crossTenant) pair the legacy claims path produces (principalTenant +
// isPlatformOwner). Phase A: a principal has one allow binding; a super-admin
// binding at the global tenant ⇒ cross-tenant platform owner. This is the
// conformance bridge and the seed of the Phase-B union decider.
func (s *server) bindingDerivedScope(principalID string) (tenant string, crossTenant bool) {
	if s.bindings == nil {
		return "", false
	}
	now := time.Now().UTC()
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if b.Effect != EffectAllow || !b.active(now) {
			continue
		}
		st, slug := parseScope(b.ScopeID)
		// A super-admin at platform, or at the global tenant, is the cross-tenant
		// platform owner.
		if isSuperAdminRole(b.RoleID) && (st == ScopePlatform || (st == scopeTypeTenant && (slug == "" || slug == TenantGlobal))) {
			return TenantGlobal, true
		}
		if st == scopeTypeTenant {
			return slug, false
		}
	}
	return "", false
}
