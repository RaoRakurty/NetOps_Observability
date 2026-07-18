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
	"os"
	"strconv"
	"strings"
	"sync"

	"netops/backend/appid"
	"netops/backend/cloud"
)

const (
	requiredTagsMax   = 32 // bounded list — a governance list, not a dumping ground
	requiredTagMaxLen = 64
)

// tenantGovernanceConfig is one tenant's governance record. Zero values mean
// "unset → platform default" (the exact behavior that predates the editors).
type tenantGovernanceConfig struct {
	TenantID     string   `json:"tenant_id"`
	RequiredTags []string `json:"required_tags,omitempty"`
	// RcaWindowHours: default read window for the tenant-scoped cloud signal /
	// RCA surfaces when a request names none. 0 = unset → platform default.
	RcaWindowHours int `json:"rca_window_hours,omitempty"`
	// AttributionPrecedence: tenant ordering of the appid precedence classes
	// (a validated permutation of appid.PrecedenceClasses). nil = unset →
	// the intrinsic default ladder.
	AttributionPrecedence []string `json:"attribution_precedence,omitempty"`
}

// tenantGovernanceStore is a file-backed per-tenant map, keyed by tenant in the
// store itself (§3a). Mirrors tenantDisplayStore — nothing here is a secret.
type tenantGovernanceStore struct {
	mu   sync.RWMutex
	cfgs map[string]tenantGovernanceConfig
	path string
}

func newTenantGovernanceStore(path string) *tenantGovernanceStore {
	s := &tenantGovernanceStore{cfgs: map[string]tenantGovernanceConfig{}, path: path}
	s.load()
	return s
}

// tenantGovernancePath resolves the store's kv key (env-overridable like every
// other file-backed store; blank env keeps the default).
func tenantGovernancePath() string {
	if p := strings.TrimSpace(os.Getenv("TENANT_GOVERNANCE_PATH")); p != "" {
		return p
	}
	return "tenant_governance.json"
}

func (s *tenantGovernanceStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var m map[string]tenantGovernanceConfig
	if json.Unmarshal(b, &m) != nil {
		return
	}
	for id, c := range m {
		c.TenantID = id
		m[id] = c
	}
	s.cfgs = m
}

// saveLocked persists the map. Caller holds s.mu. Blank path = in-memory only.
func (s *tenantGovernanceStore) saveLocked() {
	if s.path == "" {
		return
	}
	if b, err := json.MarshalIndent(s.cfgs, "", "  "); err == nil {
		if err := kvSave(s.path, b); err != nil {
			logWarn("settings", "persist tenant governance failed", map[string]any{"err": err.Error()})
		}
	}
}

// requiredTags returns the tenant's EFFECTIVE required-tag list and whether it
// is a custom (tenant-set) list. Unconfigured tenants — and a server built
// without the store — get the platform default (nil-safe).
func (s *tenantGovernanceStore) requiredTags(tenant string) ([]string, bool) {
	if s == nil {
		return cloud.DefaultRequiredTags(), false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cfgs[tenant]; ok && len(c.RequiredTags) > 0 {
		return append([]string(nil), c.RequiredTags...), true
	}
	return cloud.DefaultRequiredTags(), false
}

// setRequiredTags stamps the tenant FROM THE PRINCIPAL (callers pass the
// principalTenant result, never body input) and persists. tags==nil resets the
// tenant to the platform default.
func (s *tenantGovernanceStore) setRequiredTags(tenant string, tags []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	c.RequiredTags = tags
	s.cfgs[tenant] = c
	s.saveLocked()
}

// rcaWindowHours returns the tenant's EFFECTIVE default read window (hours)
// for the cloud signal surfaces and whether it is a custom override. The
// platform default is cloudSignalWindowHours — exactly the pre-editor
// behavior. Values are clamped defensively on read too (safety on a hand-
// edited store file). Nil-safe.
func (s *tenantGovernanceStore) rcaWindowHours(tenant string) (int, bool) {
	if s == nil {
		return cloudSignalWindowHours, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cfgs[tenant]; ok && c.RcaWindowHours > 0 {
		if c.RcaWindowHours > cloudSignalWindowMaxHours {
			return cloudSignalWindowMaxHours, true
		}
		return c.RcaWindowHours, true
	}
	return cloudSignalWindowHours, false
}

// setRcaWindowHours stamps the tenant FROM THE PRINCIPAL and persists.
// hours==0 resets the tenant to the platform default.
func (s *tenantGovernanceStore) setRcaWindowHours(tenant string, hours int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	c.RcaWindowHours = hours
	s.cfgs[tenant] = c
	s.saveLocked()
}

// normalizeRcaWindowHours validates a caller's window: a whole number of hours
// within the same safe bounds the signal surfaces clamp to (1..168). Off-bounds
// fails the request — the editor never silently stores a window the read path
// would refuse to honor.
func normalizeRcaWindowHours(n int) (int, error) {
	if n < 1 || n > cloudSignalWindowMaxHours {
		return 0, fmt.Errorf("rca_window_hours must be 1..%d", cloudSignalWindowMaxHours)
	}
	return n, nil
}

// handleRcaWindowSettings serves GET/PUT /api/settings/rca-window.
func (s *server) handleRcaWindowSettings(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string) {
		hours, custom := s.governance.rcaWindowHours(tenant)
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
			if hours, err = normalizeRcaWindowHours(body.RcaWindowHours); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		tenant, cross := principalTenant(claims)
		s.governance.setRcaWindowHours(tenant, hours)
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
func (s *tenantGovernanceStore) attributionPrecedence(tenant string) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cfgs[tenant]; ok && len(c.AttributionPrecedence) > 0 {
		if order, err := appid.NormalizePrecedence(c.AttributionPrecedence); err == nil {
			return order, true
		}
	}
	return nil, false
}

// setAttributionPrecedence stamps the tenant FROM THE PRINCIPAL and persists.
// order==nil resets the tenant to the default ladder.
func (s *tenantGovernanceStore) setAttributionPrecedence(tenant string, order []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	c.AttributionPrecedence = order
	s.cfgs[tenant] = c
	s.saveLocked()
}

// handleAttributionPrecedenceSettings serves GET/PUT /api/settings/attribution-precedence.
func (s *server) handleAttributionPrecedenceSettings(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string) {
		order, custom := s.governance.attributionPrecedence(tenant)
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
		s.governance.setAttributionPrecedence(tenant, order)
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

// isGovernanceAuditAction reports whether an audit Detail action is one of the
// tenant-governance settings writes this view surfaces (closed list — the
// audit trail itself stays admin-visible in full at /api/audit).
func isGovernanceAuditAction(action any) bool {
	switch action {
	case "set_required_tags", "set_rca_window", "set_attribution_precedence", "set_time_display":
		return true
	}
	return false
}

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
	limit := governanceAuditDefaultLimit
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > auditDefaultLimit {
		limit = auditDefaultLimit
	}
	// One bounded page of the caller-visible trail, newest-first, then filter.
	// If governance writes are older than the newest auditMaxQueryLimit events
	// the view is honest about being a recent-changes window, not an archive.
	events := s.auditScopedList(claims, auditQuery{Limit: auditMaxQueryLimit})
	out := make([]AuditEvent, 0, limit)
	for _, e := range events {
		if e.Detail == nil || !isGovernanceAuditAction(e.Detail["action"]) {
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
func normalizeRequiredTags(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("required_tags must list at least one tag")
	}
	if len(raw) > requiredTagsMax {
		return nil, fmt.Errorf("required_tags: at most %d tags", requiredTagsMax)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		tag := strings.ToLower(strings.TrimSpace(t))
		if tag == "" || len(tag) > requiredTagMaxLen {
			return nil, fmt.Errorf("required_tags: each tag must be 1..%d characters", requiredTagMaxLen)
		}
		for _, c := range tag {
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
				c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
			if !ok {
				return nil, fmt.Errorf("required_tags: invalid tag key %q (letters, digits, . _ : / - only)", tag)
			}
		}
		if seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	return out, nil
}

// handleRequiredTagsSettings serves GET/PUT /api/settings/required-tags.
func (s *server) handleRequiredTagsSettings(w http.ResponseWriter, r *http.Request) {
	writeState := func(tenant string) {
		tags, custom := s.governance.requiredTags(tenant)
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
			if tags, err = normalizeRequiredTags(body.RequiredTags); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		tenant, cross := principalTenant(claims)
		s.governance.setRequiredTags(tenant, tags)
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
