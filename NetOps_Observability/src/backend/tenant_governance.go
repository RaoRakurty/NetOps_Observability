package main

// tenant_governance.go — per-tenant GOVERNANCE settings (Wave 4 #11, the real
// Settings editors). Sibling of tenant_display.go: the same file-backed,
// tenant-keyed store pattern (§3a for file/kv stores — the record read or
// written is ALWAYS the caller's principal tenant; no unscoped listing exists),
// holding the cloud-governance knobs the backlog names:
//
//   required tags           — drives missingTags + the coverage/compliance report
//   RCA read window         — default window_hours for the cloud signal surfaces
//   attribution precedence  — per-tenant ordering of the appid resolver classes
//
//   GET /api/settings/required-tags — any authenticated user (the UI renders it)
//   PUT /api/settings/required-tags — administration:admin (tenant admin), audited
//
// All PUTs are governance writes: requireAdmin (administration:admin) — never a
// weaker permission — tenant stamped from the principal, bounded body, closed
// validation, audited with a distinct action per setting.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/audit"
	"os"
	"strings"

	"netops/backend/appid"
	"netops/backend/cloud"

	tenantpkg "netops/backend/internal/tenant"
)

// The governance store moved to internal/tenant/governance.go (Phase-2 W3.2).
type (
	tenantGovernanceConfig = tenantpkg.GovernanceConfig
	tenantGovernanceStore  = tenantpkg.GovernanceStore
	seamOwnerEntry         = tenantpkg.SeamOwnerEntry
)

func newTenantGovernanceStore(path string) *tenantGovernanceStore {
	return tenantpkg.NewGovernanceStore(path)
}

func isSeamOwnerClass(c string) bool { return tenantpkg.IsSeamOwnerClass(c) }

func tenantGovernancePath() string {
	if p := strings.TrimSpace(os.Getenv("TENANT_GOVERNANCE_PATH")); p != "" {
		return p
	}
	return "/data/tenant_governance.json"
}

// load reads the stored per-tenant governance config. THREE states, never two
// (the cloud_monitor_eval.go shape): the store did not answer (error) / it
// answered with nothing (absent key or empty blob) / loaded.
func (s *server) handleRcaWindowSettings(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string) {
		hours, custom := s.governance.RcaWindowHours(tenant)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":        tenant,
			"rca_window_hours": hours,
			"is_default":       !custom,
			"default_hours":    cloudSignalWindowHours,
			"max_hours":        cloudSignalWindowMaxHours,
		})
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := userFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		tenant, _ := principalTenant(claims)
		writeState(tenant)
	case http.MethodPut:
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var body struct {
			RcaWindowHours int  `json:"rca_window_hours"`
			Reset          bool `json:"reset,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		hours := 0
		if !body.Reset {
			var err error
			if hours, err = tenantpkg.NormalizeRcaWindowHours(body.RcaWindowHours); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		tenant, cross := principalTenant(claims)
		if err := s.governance.SetRcaWindowHours(tenant, hours); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("rca window was not saved"))
			return
		}
		if s.audit != nil {
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{"action": "set_rca_window", "rca_window_hours": hours, "reset": body.Reset},
			})
		}
		writeState(tenant)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

// attributionPrecedence returns the tenant's precedence order and whether it
// is a custom override. nil order (default) makes the resolver use the
// intrinsic ladder — exactly the pre-editor behavior. A stored order that no
// longer validates (e.g. after a class-vocabulary change) reads as default
// rather than being trusted (§3: never trust cached data without validation).
// Nil-safe.
func (s *server) handleAttributionPrecedenceSettings(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string) {
		order, custom := s.governance.AttributionPrecedence(tenant)
		if !custom {
			order = appid.PrecedenceClasses()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":              tenant,
			"attribution_precedence": order,
			"is_default":             !custom,
			"default_precedence":     appid.PrecedenceClasses(),
		})
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := userFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		tenant, _ := principalTenant(claims)
		writeState(tenant)
	case http.MethodPut:
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var body struct {
			AttributionPrecedence []string `json:"attribution_precedence"`
			Reset                 bool     `json:"reset,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		var order []string
		if !body.Reset {
			var err error
			// Closed vocabulary: must be a PERMUTATION of the known classes.
			if order, err = appid.NormalizePrecedence(body.AttributionPrecedence); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			if appid.IsDefaultPrecedence(order) {
				order = nil // storing the default order IS the default — one truth
			}
		}
		tenant, cross := principalTenant(claims)
		if err := s.governance.SetAttributionPrecedence(tenant, order); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("attribution precedence was not saved"))
			return
		}
		if s.audit != nil {
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{"action": "set_attribution_precedence", "attribution_precedence": order, "reset": body.Reset || order == nil},
			})
		}
		writeState(tenant)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

// seamOwners returns the tenant's registry (nil when unset) and whether it is
// a custom override. A stored key outside today's class vocabulary is dropped
// on read rather than trusted (§3: never trust cached data without validation).
// Nil-safe.
func (s *server) handleSeamOwnersSettings(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string) {
		owners, custom := s.governance.SeamOwners(tenant)
		if owners == nil {
			owners = map[string]seamOwnerEntry{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":   tenant,
			"seam_owners": owners,
			"is_default":  !custom,
			"classes":     tenantpkg.SeamOwnerClasses,
		})
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := userFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		tenant, _ := principalTenant(claims)
		writeState(tenant)
	case http.MethodPut:
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var body struct {
			SeamOwners map[string]seamOwnerEntry `json:"seam_owners"`
			Reset      bool                      `json:"reset,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		var owners map[string]seamOwnerEntry
		if !body.Reset {
			var err error
			if owners, err = tenantpkg.NormalizeSeamOwners(body.SeamOwners); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		tenant, cross := principalTenant(claims)
		if err := s.governance.SetSeamOwners(tenant, owners); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("seam owners was not saved"))
			return
		}
		if s.audit != nil {
			classes := make([]string, 0, len(owners))
			for k := range owners {
				classes = append(classes, k)
			}
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{"action": "set_seam_owners", "classes": classes, "reset": body.Reset},
			})
		}
		writeState(tenant)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

// isGovernanceAuditAction reports whether an audit Detail action is one of the
// tenant-governance settings writes this view surfaces (closed list — the
// audit trail itself stays admin-visible in full at /api/audit).
const governanceAuditDefaultLimit = 50

// handleGovernanceAudit serves GET /api/settings/governance-audit — the
// read-only "who changed which governance setting, when" view (Wave 4 #11
// slice 5). Reuses auditScopedList, so visibility is exactly the caller's
// audit scope (§3a: tenant admin → own tenant; org admin → its org's tenants;
// platform owner → all) filtered to the governance actions. Bounded: scans at
// most one max-size audit page, returns at most ?limit= (default 50) events.
func (s *server) handleGovernanceAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	// Fail closed on a malformed/out-of-range limit (F-71/F-74 rule): it used
	// to be discarded, so `?limit=abc` silently became the default.
	limit, lerr := intQuery(r, "limit", governanceAuditDefaultLimit, 1, audit.MaxQueryLimit)
	if lerr != nil {
		writeError(w, http.StatusBadRequest, lerr)
		return
	}
	if limit > audit.DefaultLimit {
		limit = audit.DefaultLimit
	}
	// One bounded page of the caller-visible trail, newest-first, then filter.
	// If governance writes are older than the newest audit.MaxQueryLimit events
	// the view is honest about being a recent-changes window, not an archive.
	events, err := s.auditScopedList(claims, auditQuery{Limit: audit.MaxQueryLimit})
	if err != nil {
		// F-73: same rule as /api/audit — an unreadable trail must not render
		// as "no governance changes were made".
		logError("audit", "governance audit read failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusServiceUnavailable,
			errors.New("governance trail is temporarily unreadable; retry"))
		return
	}
	out := make([]AuditEvent, 0, limit)
	for _, e := range events {
		if e.Detail == nil || !tenantpkg.IsGovernanceAuditAction(e.Detail["action"]) {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "count": len(out)})
}

// normalizeRequiredTags validates a caller's list: 1..32 entries, each a
// bounded tag key (lowercased; letters/digits/._:/- like real cloud tag keys),
// de-duplicated preserving order. Anything off-spec fails the request — never a
// silent trim to something the caller didn't say.
func (s *server) handleRequiredTagsSettings(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string) {
		tags, custom := s.governance.RequiredTags(tenant)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":     tenant,
			"required_tags": tags,
			"is_default":    !custom,
			"default_tags":  cloud.DefaultRequiredTags(),
		})
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := userFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		tenant, _ := principalTenant(claims)
		writeState(tenant)
	case http.MethodPut:
		// Governance write → scope-aware admin gate (§3a rule 3): a tenant admin
		// sets its OWN tenant's requirement, never another tenant's by id.
		claims, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		var body struct {
			RequiredTags []string `json:"required_tags"`
			Reset        bool     `json:"reset,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
			return
		}
		var tags []string
		if !body.Reset {
			var err error
			if tags, err = tenantpkg.NormalizeRequiredTags(body.RequiredTags); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		tenant, cross := principalTenant(claims)
		if err := s.governance.SetRequiredTags(tenant, tags); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("required tags was not saved"))
			return
		}
		if s.audit != nil {
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
				Remote: auditClientIP(r),
				Detail: map[string]any{"action": "set_required_tags", "required_tags": tags, "reset": body.Reset},
			})
		}
		writeState(tenant)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}
