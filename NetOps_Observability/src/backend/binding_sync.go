// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"fmt"
	"strings"
	"time"

	"netops/backend/internal/rbac"
)

// userBindingScope is the canonical scope id for a user's single mirror binding.
// PBAC Phase C — the control-plane realm split: the PLATFORM OWNER (a super-admin
// in the global/blank tenant) is bound at the `platform` scope, not at a customer
// tenant, so control-plane identity is no longer expressed as "a customer tenant
// that happens to be god." Everyone else is bound at their tenant scope. This is
// behaviour-neutral: reachesAllTenants / accessibleTenants / bindingDerivedScope
// all already treat super-admin@platform identically to the legacy
// super-admin@tenant:global (isPlatformOwner).
func userBindingScope(u User) string {
	t := strings.ToLower(strings.TrimSpace(u.TenantID))
	if t == "" {
		t = TenantGlobal
	}
	if t == TenantGlobal && isSuperAdminRole(u.Role) {
		return ScopePlatform
	}
	return scopeTenant(t)
}

// syncUserBinding makes the binding store reflect the user's current role+tenant:
// it drops any stale bindings for the principal and writes the single mirror
// binding. Idempotent (deterministic binding id), safe to call repeatedly.
// Returns an error rather than swallowing one. Found by the widened
// TestNoVoidPersistFuncs: both store writes below discarded their error, so a
// failed re-sync left the binding mirror describing the user's OLD role or
// tenant while the user record showed the new one — and nothing said so. On an
// authorization mirror that is the worst possible place for a silent write.
//
// Callers that cannot fail the operation (SSO/LDAP/TACACS provisioning, where
// refusing the login would be worse than a stale mirror) must still LOG it —
// see logBindingSync.
func (s *server) syncUserBinding(u User) error {
	if s.bindings == nil || strings.TrimSpace(u.Username) == "" {
		return nil
	}
	pid := strings.ToLower(strings.TrimSpace(u.Username))
	want := rbac.BindingID(pid, u.Role, userBindingScope(u), EffectAllow)
	// Remove any binding for this principal that isn't the desired mirror (so a
	// role/tenant change re-syncs cleanly). Phase A holds exactly one per user.
	for _, b := range s.bindings.ListByPrincipal(pid) {
		if b.ID != want {
			if err := s.bindings.Remove(b.ID); err != nil {
				return fmt.Errorf("remove stale binding %s: %w", b.ID, err)
			}
		}
	}
	if _, err := s.bindings.Add(RoleBinding{
		PrincipalID: pid,
		RoleID:      u.Role,
		ScopeID:     userBindingScope(u), // ScopeType derived by Add (tenant or platform)
		Effect:      EffectAllow,
		GrantedBy:   "system:sync",
		Reason:      "mirror of legacy user role+tenant",
	}); err != nil {
		return fmt.Errorf("add binding for %s: %w", pid, err)
	}
	return nil
}

// logBindingSync runs the mirror and logs any failure. For the federated
// provisioning paths, where the sign-in itself must still succeed: a stale
// mirror is recoverable, a login outage during an IdP migration is not. The
// point is that the failure is now VISIBLE rather than discarded.
func (s *server) logBindingSync(u User, source string) {
	if err := s.syncUserBinding(u); err != nil {
		logError("bindings", "role-binding mirror out of sync", map[string]any{
			"user": u.Username, "role": u.Role, "tenant": u.TenantID,
			"source": source, "err": err.Error(),
		})
	}
}

// removeUserBindings drops a deleted user's bindings.
func (s *server) removeUserBindings(username string) {
	if s.bindings == nil {
		return
	}
	if err := s.bindings.RemoveByPrincipal(username); err != nil {
		// The user is gone but their role bindings may remain — a stale-grant
		// hazard that must be visible, not discarded.
		logError("bindings", "removing a deleted user's bindings failed", map[string]any{
			"user": username, "err": err.Error()})
	}
}

// backfillBindings ensures every existing user has its mirror binding. Called
// once at startup; idempotent.
func (s *server) backfillBindings() {
	if s.bindings == nil || s.users == nil {
		return
	}
	failed := 0
	for _, u := range s.users.List(TenantGlobal, true) { // cross-tenant: every user
		if err := s.syncUserBinding(u); err != nil {
			logError("bindings", "backfill mirror failed", map[string]any{
				"user": u.Username, "err": err.Error(),
			})
			failed++
		}
	}
	// A partial backfill leaves some users authorized by the legacy path alone.
	// Boot continues (refusing to start over one bad row would be worse), but it
	// must not do so quietly.
	if failed > 0 {
		logWarn("bindings", "role-binding backfill incomplete", map[string]any{"failed": failed})
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
		if b.Effect != EffectAllow || !b.Active(now) {
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
