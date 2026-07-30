package rbac

// access.go — PBAC Phase B: binding-based scope reachability (deny-wins).
//
// Phase A made the role_binding store a faithful mirror of the legacy single
// (role,tenant) user. Phase B uses it as the source of truth for the question
// "which tenants/orgs may this principal act in?" — generalising reachability
// from one tenant_id to the UNION of the principal's bindings (deny-wins). This
// delivers the multi-tenant / MSP / SRE / consultant P0: a principal can hold
// many bindings and switch its active scope among them.
//
// Scope of the algorithms is deliberately contained: bindings answer WHERE
// (which tenants are reachable / switchable); the role permission grid (roles.go
// can()) still answers WHAT (read/write/admin level). Per-binding role
// granularity is Phase D.
//
// The functions here are PURE over a principal's binding slice: live org/tenant
// resolution is injected through Directory, and the containment-tree walk
// (which reads the live stores and stays with the server) arrives as a closure.
// The package never touches storage and never sees a principal token.

import (
	"sort"
	"strings"
	"time"
)

// Directory is the live org/tenant lookup seam the reachability algorithms
// read through. Zero-value closures fail closed: a nil ResolveTenantID leaves
// legacy slugs unresolved (they still dedup against themselves), a nil
// TenantIDsByOrg confers no org-scope reach, a nil CanonicalOrgID falls back to
// bare normalization (an unknown ref won't match a real opaque id).
type Directory struct {
	ResolveTenantID func(ref string) (id string, ok bool) // tenant slug-or-id → opaque id
	TenantIDsByOrg  func(orgID string) []string           // opaque org id → its tenants' opaque ids
	CanonicalOrgID  func(ref string) string               // org slug-or-id → opaque id
	GlobalTenant    string                                // the Global tenant id (sorted first)
}

func (d Directory) canonicalOrgID(ref string) string {
	if d.CanonicalOrgID != nil {
		return d.CanonicalOrgID(ref)
	}
	return strings.ToLower(strings.TrimSpace(ref))
}

// ReachesTenant reports whether the principal's bindings hold an active binding
// whose scope is ancestor-or-self of tenant:<tenantID>, with no covering deny.
// Deny-wins: a deny at any covering scope blocks regardless of allows (§2).
// ancestorOrSelf is the server's containment-tree walk (it reads live stores).
func ReachesTenant(bindings []RoleBinding, now time.Time, tenantID string, ancestorOrSelf func(ancestor, descendant string) bool) bool {
	if ancestorOrSelf == nil {
		return false
	}
	target := ScopeTenant(tenantID)
	allow := false
	for _, b := range bindings {
		if !b.Active(now) || !ancestorOrSelf(b.ScopeID, target) {
			continue
		}
		if b.Effect == EffectDeny {
			return false // deny-wins for this tenant
		}
		// An org-scope binding only confers reach over its tenants for admin-grade
		// roles (super-admin / org-admin); a tenant-scope binding always does.
		st, _ := ParseScope(b.ScopeID)
		if st == ScopeTypeOrg && !IsOrgManagerRole(b.RoleID) {
			continue
		}
		allow = true
	}
	return allow
}

// AccessibleTenants returns the tenant ids a principal's bindings may act in
// (sorted, Global-first), and all=true when they reach every tenant (platform
// owner). Feeds the top-bar scope selector and /api/me. Empty + all=false ⇒ no
// access.
func AccessibleTenants(bindings []RoleBinding, now time.Time, dir Directory) (tenants []string, all bool) {
	set := map[string]bool{}
	deny := map[string]bool{}
	for _, b := range bindings {
		if !b.Active(now) {
			continue
		}
		st, slug := ParseScope(b.ScopeID)
		// platform / global super-admin reaches everything.
		if b.Effect == EffectAllow && IsSuperAdminRole(b.RoleID) &&
			(st == ScopePlatform || (st == ScopeTypeTenant && (slug == "" || slug == dir.GlobalTenant))) {
			return nil, true
		}
		switch st {
		case ScopeTypeTenant:
			// Canonicalize the (possibly legacy slug) tenant ref to its opaque id so
			// the reachable set dedups against org-scope reach (which already uses
			// opaque ids) — never two entries for the same tenant.
			id := slug
			if dir.ResolveTenantID != nil {
				if rid, ok := dir.ResolveTenantID(slug); ok {
					id = rid
				}
			}
			if b.Effect == EffectDeny {
				deny[id] = true
			} else {
				set[id] = true
			}
		case ScopeTypeOrg:
			if !IsOrgManagerRole(b.RoleID) {
				continue
			}
			if dir.TenantIDsByOrg == nil {
				continue
			}
			// Canonicalize the (possibly slug) org ref so it matches tenants stored
			// under the opaque org id.
			for _, id := range dir.TenantIDsByOrg(dir.canonicalOrgID(slug)) {
				if b.Effect == EffectDeny {
					deny[id] = true
				} else {
					set[id] = true
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
		if (out[i] == dir.GlobalTenant) != (out[j] == dir.GlobalTenant) {
			return out[i] == dir.GlobalTenant
		}
		return out[i] < out[j]
	})
	return out, false
}

// CanManageBinding reports whether a caller may grant/revoke a binding at the
// given (scope, role) — the no-escalation rule of the bindings API. Platform
// owner: always. Anyone else: never platform scope, never a super-admin role,
// and only within an org the caller administers. orgOfScope resolves the org
// owning a scope (it reads live stores and stays with the server); isOrgAdmin
// is the caller's org-admin predicate. Nil closures fail closed. The string is
// the human reason surfaced by the API.
func CanManageBinding(platformOwner bool, scopeID, roleID string, orgOfScope func(scopeID string) string, isOrgAdmin func(orgID string) bool) (bool, string) {
	if platformOwner {
		return true, "platform owner"
	}
	st, _ := ParseScope(scopeID)
	if st == ScopePlatform {
		return false, "platform-scope bindings require the platform owner"
	}
	if IsSuperAdminRole(roleID) {
		return false, "cannot grant super-admin"
	}
	if orgOfScope == nil || isOrgAdmin == nil {
		return false, "not an administrator of this organization"
	}
	org := orgOfScope(scopeID)
	if org == "" || !isOrgAdmin(org) {
		return false, "not an administrator of this organization"
	}
	return true, "org administrator"
}

// OrgAdminOrgs returns the org ids a principal's bindings administer (an active
// allow org-admin/super-admin binding at org scope), canonicalized to opaque
// org ids. Used to let an org-admin manage users/tenants within its org without
// being the platform owner.
func OrgAdminOrgs(bindings []RoleBinding, now time.Time, dir Directory) []string {
	set := map[string]bool{}
	for _, b := range bindings {
		if b.Effect != EffectAllow || !b.Active(now) {
			continue
		}
		if st, slug := ParseScope(b.ScopeID); st == ScopeTypeOrg && IsOrgManagerRole(b.RoleID) {
			set[dir.canonicalOrgID(slug)] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
