package backend

// bindings_api.go — REST for role bindings (PBAC Phase B). This is the data
// behind the L2 governance screen /admin/bindings (a principal's access list).
//
//	GET    /api/bindings[?principal=<id>]   list bindings the caller may see
//	POST   /api/bindings                    grant a binding
//	DELETE /api/bindings/{id}               revoke a binding
//
// Authz (zero-trust, no escalation):
//   - the platform owner may grant/revoke anything;
//   - an org-admin may grant/revoke ONLY within its own org(s) and ONLY
//     non-escalating roles (never super-admin, never platform scope).

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/rbac"
)

type grantBindingRequest struct {
	PrincipalID   string         `json:"principal_id"`
	PrincipalType string         `json:"principal_type"` // user (default) | service_account | agent | device
	RoleID        string         `json:"role_id"`
	ScopeID       string         `json:"scope_id"`
	Effect        string         `json:"effect"`     // allow (default) | deny
	ExpiresAt     *time.Time     `json:"expires_at"` // optional (break-glass)
	Reason        string         `json:"reason"`
	Condition     map[string]any `json:"condition,omitempty"`
}

// scopeOrg resolves the org id that owns a scope (for org-admin authz). platform
// → "" (only the platform owner may touch it); org:X → X; tenant:Y → orgOf(Y).
func (s *server) orgOfScope(scopeID string) string {
	st, slug := parseScope(scopeID)
	switch st {
	case scopeTypeOrg:
		return s.canonicalOrgID(slug)
	case scopeTypeTenant:
		if s.tenants != nil {
			if t, ok := s.tenants.Get(slug); ok {
				return s.canonicalOrgID(orgOf(t))
			}
		}
		return OrgGlobal
	default:
		return ""
	}
}

// canManageBinding reports whether the caller may grant/revoke a binding at the
// given (scope, role). Platform owner: always. Org-admin: within its org, no
// escalation. The policy lives in rbac.CanManageBinding (P2 W4.16); this
// adapter binds it to the caller's claims and the live-store org resolution.
func (s *server) canManageBinding(claims jwtClaims, scopeID, roleID string) (bool, string) {
	return rbac.CanManageBinding(isPlatformOwner(claims), scopeID, roleID, s.orgOfScope,
		func(orgID string) bool { return s.isOrgAdminOf(claims.Sub, orgID) })
}

func (s *server) handleBindings(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		principal := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("principal")))
		var list []RoleBinding
		if principal != "" {
			list = s.bindings.ListByPrincipal(principal)
		} else {
			list = s.bindings.List()
		}
		// Filter to what the caller may see: platform owner sees all; an org-admin
		// sees bindings within its org(s); anyone else sees only their own.
		owner := isPlatformOwner(claims)
		orgs := map[string]bool{}
		for _, o := range s.orgAdminOrgs(claims.Sub) {
			orgs[o] = true
		}
		out := make([]RoleBinding, 0, len(list))
		for _, b := range list {
			switch {
			case owner:
			case orgs[s.orgOfScope(b.ScopeID)]:
			case strings.EqualFold(b.PrincipalID, claims.Sub):
			default:
				continue
			}
			out = append(out, b)
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req grantBindingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req.PrincipalID = strings.ToLower(strings.TrimSpace(req.PrincipalID))
		// Validate referents (zero-trust on input). A user principal must exist as
		// an account; machine principals (service_account/agent/device) reference an
		// API token / SVID identity verified elsewhere, so are accepted by id.
		if req.PrincipalType == "" || req.PrincipalType == PrincipalUser {
			if _, ok := s.users.Get(req.PrincipalID); !ok {
				writeError(w, http.StatusBadRequest, errors.New("unknown principal"))
				return
			}
		}
		if _, ok := s.roles.Get(req.RoleID); !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown role"))
			return
		}
		if err := s.validateScopeExists(req.ScopeID); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if allowed, why := s.canManageBinding(claims, req.ScopeID, req.RoleID); !allowed {
			writeError(w, http.StatusForbidden, errors.New(why))
			return
		}
		b, err := s.bindings.Add(RoleBinding{
			PrincipalID: req.PrincipalID, PrincipalType: req.PrincipalType, RoleID: req.RoleID, ScopeID: req.ScopeID,
			Effect: req.Effect, ExpiresAt: req.ExpiresAt, Condition: req.Condition,
			GrantedBy: claims.Sub, Reason: req.Reason,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("bindings", "binding granted", map[string]any{
			"principal": b.PrincipalID, "role": b.RoleID, "scope": b.ScopeID,
			"effect": b.Effect, "by": claims.Sub,
		})
		writeJSON(w, http.StatusCreated, b)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleBindingByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/bindings/")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("invalid binding id"))
		return
	}
	// Find the binding to authorize the revoke against its scope/role.
	var target *RoleBinding
	for _, b := range s.bindings.List() {
		if b.ID == id {
			bb := b
			target = &bb
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, errors.New("binding not found"))
		return
	}
	if allowed, why := s.canManageBinding(claims, target.ScopeID, target.RoleID); !allowed {
		writeError(w, http.StatusForbidden, errors.New(why))
		return
	}
	if err := s.bindings.Remove(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logInfo("bindings", "binding revoked", map[string]any{"id": id, "by": claims.Sub})
	w.WriteHeader(http.StatusNoContent)
}

// validateScopeExists confirms a scope id refers to a real platform/org/tenant.
// Resource scopes are accepted syntactically (lazy creation). Zero-trust: a
// binding can't point at a tenant/org that doesn't exist.
func (s *server) validateScopeExists(scopeID string) error {
	st, slug := parseScope(scopeID)
	switch st {
	case ScopePlatform:
		return nil
	case scopeTypeOrg:
		if s.orgs != nil {
			if _, ok := s.orgs.Get(slug); ok {
				return nil
			}
		}
		return errors.New("unknown organization scope")
	case scopeTypeTenant:
		if s.tenants != nil {
			if _, ok := s.tenants.Get(slug); ok {
				return nil
			}
		}
		return errors.New("unknown tenant scope")
	case scopeTypeResource:
		return nil
	default:
		return errors.New("invalid scope id")
	}
}
