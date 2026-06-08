package main

// access.go — PBAC Phase B: binding-based scope reachability.
//
// Phase A made the role_binding store a faithful mirror of the legacy single
// (role,tenant) user. Phase B uses it as the source of truth for the question
// "which tenants/orgs may this principal act in?" — generalising reachability
// from one tenant_id to the UNION of the principal's bindings (deny-wins). This
// delivers the multi-tenant / MSP / SRE / consultant P0: a principal can hold
// many bindings and switch its active scope among them.
//
// Scope of the change is deliberately contained: bindings answer WHERE (which
// tenants are reachable / switchable); the role permission grid (rbac.go can())
// still answers WHAT (read/write/admin level). Per-binding role granularity is
// Phase D. Single-binding principals resolve identically to Phase A — proven by
// the conformance test.

import (
	"sort"
	"strings"
	"time"
)

// reachesTenant reports whether the principal holds an active binding whose
// scope is ancestor-or-self of tenant:<tenantID>, with no covering deny.
// Deny-wins: a deny at any covering scope blocks regardless of allows (§2).
func (s *server) reachesTenant(principalID, tenantID string) bool {
	if s.bindings == nil {
		return false
	}
	target := scopeTenant(tenantID)
	now := time.Now().UTC()
	allow := false
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if !b.active(now) || !s.scopeAncestorOrSelf(b.ScopeID, target) {
			continue
		}
		if b.Effect == EffectDeny {
			return false // deny-wins for this tenant
		}
		// An org-scope binding only confers reach over its tenants for admin-grade
		// roles (super-admin / org-admin); a tenant-scope binding always does.
		st, _ := parseScope(b.ScopeID)
		if st == scopeTypeOrg && !isOrgManagerRole(b.RoleID) {
			continue
		}
		allow = true
	}
	return allow
}

// reachesAllTenants reports the platform-owner case: an active super-admin
// binding at platform scope or at the global tenant. Mirrors isPlatformOwner.
func (s *server) reachesAllTenants(principalID string) bool {
	if s.bindings == nil {
		return false
	}
	now := time.Now().UTC()
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if b.Effect != EffectAllow || !b.active(now) || !isSuperAdminRole(b.RoleID) {
			continue
		}
		st, slug := parseScope(b.ScopeID)
		if st == ScopePlatform || (st == scopeTypeTenant && (slug == "" || slug == TenantGlobal)) {
			return true
		}
	}
	return false
}

// accessibleTenants returns the tenant ids a principal may act in (sorted,
// Global-first), and all=true when it reaches every tenant (platform owner).
// Feeds the top-bar scope selector and /api/me. Empty + all=false ⇒ no access.
func (s *server) accessibleTenants(principalID string) (tenants []string, all bool) {
	if s.bindings == nil || s.tenants == nil {
		return nil, false
	}
	now := time.Now().UTC()
	set := map[string]bool{}
	deny := map[string]bool{}
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if !b.active(now) {
			continue
		}
		st, slug := parseScope(b.ScopeID)
		// platform / global super-admin reaches everything.
		if b.Effect == EffectAllow && isSuperAdminRole(b.RoleID) &&
			(st == ScopePlatform || (st == scopeTypeTenant && (slug == "" || slug == TenantGlobal))) {
			return nil, true
		}
		switch st {
		case scopeTypeTenant:
			if b.Effect == EffectDeny {
				deny[slug] = true
			} else {
				set[slug] = true
			}
		case scopeTypeOrg:
			if !isOrgManagerRole(b.RoleID) {
				continue
			}
			for _, tn := range s.tenants.ListByOrg(slug) {
				if b.Effect == EffectDeny {
					deny[tn.ID] = true
				} else {
					set[tn.ID] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		if !deny[id] { // deny-wins
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i] == TenantGlobal) != (out[j] == TenantGlobal) {
			return out[i] == TenantGlobal
		}
		return out[i] < out[j]
	})
	return out, false
}

// orgAdminOrgs returns the org ids a principal administers (an active allow
// org-admin/super-admin binding at org scope). Used to let an org-admin manage
// users/tenants within its org without being the platform owner.
func (s *server) orgAdminOrgs(principalID string) []string {
	if s.bindings == nil {
		return nil
	}
	now := time.Now().UTC()
	set := map[string]bool{}
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if b.Effect != EffectAllow || !b.active(now) {
			continue
		}
		if st, slug := parseScope(b.ScopeID); st == scopeTypeOrg && isOrgManagerRole(b.RoleID) {
			set[slug] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// isOrgAdminOf reports whether the principal administers the given org.
func (s *server) isOrgAdminOf(principalID, orgID string) bool {
	orgID = strings.ToLower(strings.TrimSpace(orgID))
	for _, o := range s.orgAdminOrgs(principalID) {
		if o == orgID {
			return true
		}
	}
	return false
}
