package main

// breakglass.go — PBAC Phase C: access-as-an-event for the platform operator.
//
// Ratified posture (§7.1): operators have NO standing access to a tenant whose
// data is marked OperatorRestricted (the compliance switch). When an operator
// genuinely needs in — incident response — they open a BREAK-GLASS session: a
// time-boxed, fully audited allow binding at that tenant's scope, carrying a
// mandatory reason and a short expiry. It self-expires; nothing lingers.
//
// This is purely additive and behaviour-preserving by default: with no active
// break-glass binding, a restricted tenant stays hidden from the operator exactly
// as before. A live session temporarily un-hides ONLY that tenant, ONLY for its
// window, and every grant/use is on the record.
//
// The live re-pointing of RLS / OpenSearch / VictoriaMetrics off the global
// tenant onto a dedicated system scope is deferred (it needs the regional data
// plane + a staged rollout) — see docs/design/saas-identity-pbac.md §6 Phase C.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/rbac"
)

// breakGlassDefaultTTL bounds a session if the caller doesn't specify one; the
// max keeps a session from being effectively standing access.
const (
	breakGlassDefaultTTL = 60 * time.Minute
	breakGlassMaxTTL     = 8 * time.Hour
)

// conditionBreakGlass marks a binding as an emergency-access grant. The
// predicate is RoleBinding.IsBreakGlass (internal/rbac).
const conditionBreakGlass = rbac.ConditionBreakGlass

// hasBreakGlass reports whether the principal holds an ACTIVE break-glass binding
// that reaches the given tenant.
func (s *server) hasBreakGlass(principalID, tenantID string) bool {
	if s.bindings == nil {
		return false
	}
	target := scopeTenant(tenantID)
	now := time.Now().UTC()
	for _, b := range s.bindings.ListByPrincipal(principalID) {
		if b.Effect == EffectAllow && b.IsBreakGlass() && b.Active(now) && s.scopeAncestorOrSelf(b.ScopeID, target) {
			return true
		}
	}
	return false
}

// effectiveRestrictedIDs returns the OperatorRestricted tenant ids that remain
// hidden from THIS operator right now — i.e. restricted tenants MINUS the ones it
// currently holds a live break-glass session into. This is what the telemetry
// visibility gate consults, so break-glass transparently un-hides a tenant for
// the duration of the session and no longer afterwards.
func (s *server) effectiveRestrictedIDs(principalID string) []string {
	if s.tenants == nil {
		return nil
	}
	restricted := s.tenants.RestrictedIDs()
	if len(restricted) == 0 {
		return nil
	}
	out := make([]string, 0, len(restricted))
	for _, id := range restricted {
		if !s.hasBreakGlass(principalID, id) {
			out = append(out, id)
		}
	}
	return out
}

type breakGlassRequest struct {
	TenantID       string `json:"tenant_id"`
	Reason         string `json:"reason"`
	DurationMinute int    `json:"duration_minutes"`
}

// handleBreakGlass: POST opens a session, GET lists the caller's active sessions.
// Platform owner only — it is the operator elevating itself into a restricted
// tenant. A tenant's own users never need it (they already see their own data).
func (s *server) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !isPlatformOwner(claims) {
		writeError(w, http.StatusForbidden, errors.New("platform operator required"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		now := time.Now().UTC()
		out := make([]RoleBinding, 0)
		for _, b := range s.bindings.ListByPrincipal(claims.Sub) {
			if b.IsBreakGlass() && b.Active(now) {
				out = append(out, b)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req breakGlassRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant := strings.ToLower(strings.TrimSpace(req.TenantID))
		if tenant == "" || tenant == TenantGlobal {
			writeError(w, http.StatusBadRequest, errors.New("a specific tenant is required"))
			return
		}
		if _, ok := s.tenants.Get(tenant); !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown tenant"))
			return
		}
		if strings.TrimSpace(req.Reason) == "" {
			writeError(w, http.StatusBadRequest, errors.New("a reason is required for break-glass access"))
			return
		}
		ttl := time.Duration(req.DurationMinute) * time.Minute
		if ttl <= 0 {
			ttl = breakGlassDefaultTTL
		}
		if ttl > breakGlassMaxTTL {
			ttl = breakGlassMaxTTL
		}
		exp := time.Now().UTC().Add(ttl)
		b, err := s.bindings.Add(RoleBinding{
			PrincipalID: claims.Sub,
			RoleID:      RoleSuperAdmin,
			ScopeID:     scopeTenant(tenant),
			Effect:      EffectAllow,
			Condition:   map[string]any{conditionBreakGlass: true},
			ExpiresAt:   &exp,
			GrantedBy:   claims.Sub,
			Reason:      strings.TrimSpace(req.Reason),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// First-class audited event (also captured by the audit middleware).
		logWarn("breakglass", "break-glass session opened", map[string]any{
			"operator": claims.Sub, "tenant": tenant, "reason": b.Reason,
			"expires_at": exp.Format(time.RFC3339),
		})
		writeJSON(w, http.StatusCreated, b)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBreakGlassByID: DELETE ends a session early.
func (s *server) handleBreakGlassByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/breakglass/")
	// A caller may only end its own break-glass session.
	var target *RoleBinding
	for _, b := range s.bindings.ListByPrincipal(claims.Sub) {
		if b.ID == id && b.IsBreakGlass() {
			bb := b
			target = &bb
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, errors.New("break-glass session not found"))
		return
	}
	if err := s.bindings.Remove(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	logWarn("breakglass", "break-glass session ended", map[string]any{"operator": claims.Sub, "id": id})
	w.WriteHeader(http.StatusNoContent)
}
