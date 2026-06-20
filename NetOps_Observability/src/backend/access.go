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
	"errors"
	"net/http"
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
			// Canonicalize the (possibly legacy slug) tenant ref to its opaque id so
			// the reachable set dedups against org-scope reach (which already uses
			// opaque ids) — never two entries for the same tenant.
			id := slug
			if t, ok := s.tenants.Resolve(slug); ok {
				id = t.ID
			}
			if b.Effect == EffectDeny {
				deny[id] = true
			} else {
				set[id] = true
			}
		case scopeTypeOrg:
			if !isOrgManagerRole(b.RoleID) {
				continue
			}
			// Canonicalize the (possibly slug) org ref so it matches tenants stored
			// under the opaque org id.
			for _, tn := range s.tenants.ListByOrg(s.canonicalOrgID(slug)) {
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

// canonicalOrgID resolves an UNTRUSTED org reference (id or slug) to its opaque
// org id, so every org comparison is opaque-to-opaque regardless of whether the
// source carried a slug (legacy binding / API input) or the opaque id. Unknown
// refs pass through normalized (fail-closed: won't match a real opaque id).
func (s *server) canonicalOrgID(ref string) string {
	if s.orgs != nil {
		if o, ok := s.orgs.Resolve(ref); ok {
			return o.ID
		}
	}
	return strings.ToLower(strings.TrimSpace(ref))
}

// orgAdminOrgs returns the org ids a principal administers (an active allow
// org-admin/super-admin binding at org scope), canonicalized to opaque org ids.
// Used to let an org-admin manage users/tenants within its org without being the
// platform owner.
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
			set[s.canonicalOrgID(slug)] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ScopeDetail is one selectable scope for the top-bar Org|Region|Tenant selector.
type ScopeDetail struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	OrgID      string `json:"org_id"`
	OrgName    string `json:"org_name"`
	Region     string `json:"region"`
}

// accessibleScopeDetails resolves the principal's reachable tenants into rich,
// named, org-grouped entries for the scope selector (platform owner → all).
func (s *server) accessibleScopeDetails(principalID string) (scopes []ScopeDetail, all bool) {
	if s.tenants == nil {
		return nil, false
	}
	ids, allTenants := s.accessibleTenants(principalID)
	var list []Tenant
	if allTenants {
		list = s.tenants.List()
	} else {
		for _, id := range ids {
			if t, ok := s.tenants.Get(id); ok {
				list = append(list, t)
			}
		}
	}
	out := make([]ScopeDetail, 0, len(list))
	for _, t := range list {
		org := orgOf(t)
		orgName := org
		if s.orgs != nil {
			if o, ok := s.orgs.Get(org); ok {
				orgName = o.Name
			}
		}
		out = append(out, ScopeDetail{TenantID: t.ID, TenantName: t.Name, OrgID: org, OrgName: orgName, Region: s.effectiveTenantRegion(t)})
	}
	return out, allTenants
}

// handleMyScopes serves the authenticated caller's selectable scopes.
func (s *server) handleMyScopes(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	scopes, all := s.accessibleScopeDetails(claims.Sub)
	writeJSON(w, http.StatusOK, map[string]any{"scopes": scopes, "all_tenants": all})
}

// isOrgAdminOf reports whether the principal administers the given org. The org
// reference (id or slug) is canonicalized so a slug and its opaque id match.
func (s *server) isOrgAdminOf(principalID, orgID string) bool {
	orgID = s.canonicalOrgID(orgID)
	for _, o := range s.orgAdminOrgs(principalID) {
		if o == orgID {
			return true
		}
	}
	return false
}
