package backend

// access_explain.go — the L3 "Explain" surface (docs/design/saas-identity-pbac.md
// §1 / UI L3): answer "what can this principal access, and WHY?" by resolving its
// bindings into reachable tenants and naming, per tenant, the exact binding that
// grants the reach. This is the decider made transparent — the same union/deny
// logic access.go uses, surfaced as an explanation instead of a yes/no.
//
//	GET /api/access/explain?principal=<id>            full access map for a principal
//	GET /api/access/explain?principal=<id>&tenant=<t> a focused "why (not)?" answer
//
// Authz: the platform owner explains anyone; an org-admin explains principals
// that touch its org(s); anyone may explain itself.

import (
	"net/http"
	"strings"
	"time"
)

// GrantReason names one binding that contributes to a reach decision.
type GrantReason struct {
	RoleID     string `json:"role_id"`
	ScopeID    string `json:"scope_id"`
	Effect     string `json:"effect"`
	GrantedBy  string `json:"granted_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
	BreakGlass bool   `json:"break_glass,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// TenantReach is one tenant a principal can reach, with the binding(s) that grant
// it — the "why" for that tenant.
type TenantReach struct {
	TenantID   string        `json:"tenant_id"`
	TenantName string        `json:"tenant_name"`
	OrgID      string        `json:"org_id"`
	OrgName    string        `json:"org_name"`
	GrantedBy  []GrantReason `json:"granted_by"`
}

// AccessExplanation is the full answer for one principal.
type AccessExplanation struct {
	Principal  string        `json:"principal"`
	AllTenants bool          `json:"all_tenants"` // platform owner — reaches everything
	OrgAdminOf []string      `json:"org_admin_of"`
	Bindings   []RoleBinding `json:"bindings"`
	Reaches    []TenantReach `json:"reaches"`
}

// grantsFor returns the active bindings that grant reach to a tenant (the why),
// honoring the same rules as reachesTenant (org bindings need an org-manager role).
func (s *server) grantsFor(principalID, tenantID string) []GrantReason {
	target := scopeTenant(tenantID)
	now := time.Now().UTC()
	var out []GrantReason
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if !b.Active(now) || !s.scopeAncestorOrSelf(b.ScopeID, target) {
			continue
		}
		st, _ := parseScope(b.ScopeID)
		if st == scopeTypeOrg && b.Effect == EffectAllow && !isOrgManagerRole(b.RoleID) {
			continue
		}
		g := GrantReason{RoleID: b.RoleID, ScopeID: b.ScopeID, Effect: b.Effect, GrantedBy: b.GrantedBy, Reason: b.Reason, BreakGlass: b.IsBreakGlass()}
		if b.ExpiresAt != nil {
			g.ExpiresAt = b.ExpiresAt.Format(time.RFC3339)
		}
		out = append(out, g)
	}
	return out
}

// explainAccess builds the full access map for a principal.
func (s *server) explainAccess(principalID string) AccessExplanation {
	scopes, all := s.accessibleScopeDetails(principalID)
	exp := AccessExplanation{
		Principal:  principalID,
		AllTenants: all,
		OrgAdminOf: s.orgAdminOrgs(principalID),
		Bindings:   s.bindings.ListByPrincipal(principalID),
	}
	for _, sc := range scopes {
		exp.Reaches = append(exp.Reaches, TenantReach{
			TenantID: sc.TenantID, TenantName: sc.TenantName,
			OrgID: sc.OrgID, OrgName: sc.OrgName,
			GrantedBy: s.grantsFor(principalID, sc.TenantID),
		})
	}
	return exp
}

// canExplainPrincipal gates who may see a principal's access map.
func (s *server) canExplainPrincipal(claims jwtClaims, target string) bool {
	if isPlatformOwner(claims) || strings.EqualFold(claims.Sub, target) {
		return true
	}
	// An org-admin may explain a principal that holds any binding in its org(s).
	admin := map[string]bool{}
	for _, o := range s.orgAdminOrgs(claims.Sub) {
		admin[o] = true
	}
	if len(admin) == 0 {
		return false
	}
	for _, b := range s.bindings.ListByPrincipal(target) {
		if admin[s.orgOfScope(b.ScopeID)] {
			return true
		}
	}
	return false
}

func (s *server) handleAccessExplain(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("principal")))
	if target == "" {
		target = strings.ToLower(claims.Sub) // default: explain myself
	}
	if !s.canExplainPrincipal(claims, target) {
		// Don't leak existence — return an empty map rather than 403.
		writeJSON(w, http.StatusOK, AccessExplanation{Principal: target})
		return
	}
	exp := s.explainAccess(target)

	// Focused mode: ?tenant=<t> answers "does the principal reach this tenant, and
	// why (or why not)?" deny-wins, mirroring reachesTenant.
	if tn := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tenant"))); tn != "" {
		grants := s.grantsFor(target, tn)
		denied := false
		for _, g := range grants {
			if g.Effect == EffectDeny {
				denied = true
			}
		}
		allowed := s.reachesTenant(target, tn) || (exp.AllTenants && !denied)
		writeJSON(w, http.StatusOK, map[string]any{
			"principal": target, "tenant": tn, "allowed": allowed,
			"all_tenants": exp.AllTenants, "granted_by": grants,
		})
		return
	}
	writeJSON(w, http.StatusOK, exp)
}
