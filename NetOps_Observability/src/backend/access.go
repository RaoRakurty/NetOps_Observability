package backend

// access.go — main-side adapters for the PBAC Phase-B reachability algorithms
// (internal/rbac/access.go, P2 W4.15). The deny-wins union over a principal's
// bindings lives in the package; this file constructs its live-store Directory
// seam, keeps the nil-store fail-closed guards, and hosts the scope-selector
// view assembly + handler (they read live tenant/org/region state).

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/rbac"
)

// accessDirectory builds the live org/tenant lookup seam the rbac reachability
// algorithms read through. Closures nil-check the stores so a partially wired
// server (tests) fails closed.
func (s *server) accessDirectory() rbac.Directory {
	return rbac.Directory{
		ResolveTenantID: func(ref string) (string, bool) {
			if s.tenants == nil {
				return "", false
			}
			t, ok := s.tenants.Resolve(ref)
			if !ok {
				return "", false
			}
			return t.ID, true
		},
		TenantIDsByOrg: func(orgID string) []string {
			if s.tenants == nil {
				return nil
			}
			tns := s.tenants.ListByOrg(orgID)
			ids := make([]string, 0, len(tns))
			for _, tn := range tns {
				ids = append(ids, tn.ID)
			}
			return ids
		},
		CanonicalOrgID: s.canonicalOrgID,
		GlobalTenant:   TenantGlobal,
	}
}

// reachesTenant reports whether the principal holds an active binding whose
// scope is ancestor-or-self of tenant:<tenantID>, with no covering deny.
func (s *server) reachesTenant(principalID, tenantID string) bool {
	if s.bindings == nil {
		return false
	}
	return rbac.ReachesTenant(s.bindings.ListByPrincipal(principalID), time.Now().UTC(), tenantID, s.scopeAncestorOrSelf)
}

// accessibleTenants returns the tenant ids a principal may act in (sorted,
// Global-first), and all=true when it reaches every tenant (platform owner).
func (s *server) accessibleTenants(principalID string) (tenants []string, all bool) {
	if s.bindings == nil || s.tenants == nil {
		return nil, false
	}
	return rbac.AccessibleTenants(s.bindings.ListByPrincipal(principalID), time.Now().UTC(), s.accessDirectory())
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
func (s *server) orgAdminOrgs(principalID string) []string {
	if s.bindings == nil {
		return nil
	}
	return rbac.OrgAdminOrgs(s.bindings.ListByPrincipal(principalID), time.Now().UTC(), s.accessDirectory())
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
