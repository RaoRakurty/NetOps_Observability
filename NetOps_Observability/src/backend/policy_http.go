package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"netops/backend/policy"
)

// policy_http.go — Phase 3 of the Security Policy Configuration System: the
// admin HTTP surface over the Phase-2 store (the engine's Source).
//
// Endpoints (all admin-gated; mutating routes are auto-audited by withAudit):
//   GET  /api/policy/catalog    the self-describing control catalog (UI cards)
//   GET  /api/policy/effective  resolved effective policy for a subject — this
//                               IS the Policy Simulator: pass any tenant/role/user
//                               and see the effective value + full inheritance
//                               trail per setting, with no persistence.
//   GET  /api/policy/documents  list the override documents the caller may see
//   GET  /api/policy/document   read one scope's raw overrides (for the editor)
//   PUT  /api/policy/document   set/replace one override (zero-trust validated)
//   DEL  /api/policy/document   clear one override (revert to inherited)
//   POST /api/policy/validate   dry-run a proposed override (write pre-flight)
//
// Authorization layers on top of the store's structural tenancy: the store
// guarantees a (scope,selector,tenant) reference is internally consistent and
// that resolution never crosses the tenant boundary; THIS layer decides WHO may
// read/write WHICH scope. System-scope and global-tenant policy are platform
// property — only the cross-tenant platform owner may write them. A tenant admin
// may read + edit only its own tenant/role/user scopes, and may read (but not
// write) the system baseline it inherits.

// ---- request/response shapes ----------------------------------------------

type policyCatalogResponse struct {
	Scopes  []policy.Scope        `json:"scopes"`
	Domains []policyCatalogDomain `json:"domains"`
}

type policyCatalogDomain struct {
	Domain   policy.Domain    `json:"domain"`
	Settings []policy.Setting `json:"settings"`
}

// policyOverrideRequest is the PUT body: a single typed override for one key.
type policyOverrideRequest struct {
	Key    string       `json:"key"`
	Value  policy.Value `json:"value"`
	Locked bool         `json:"locked"`
}

// policyValidateRequest is the POST body for the no-write pre-flight.
type policyValidateRequest struct {
	Scope    policy.Scope `json:"scope"`
	Selector string       `json:"selector"`
	Tenant   string       `json:"tenant"`
	Key      string       `json:"key"`
	Value    policy.Value `json:"value"`
	Locked   bool         `json:"locked"`
}

// ---- authorization helpers --------------------------------------------------

// policyOwningTenant returns the tenant that OWNS the policy at a scope
// reference: "" for the system (platform) scope, the selector for the tenant
// scope, and the tenant param for role/user scopes. Always lower-cased so it
// compares cleanly with principalTenant's normalised tenant.
func policyOwningTenant(scope policy.Scope, selector, tenant string) string {
	switch scope {
	case policy.ScopeTenant:
		return strings.ToLower(strings.TrimSpace(selector))
	case policy.ScopeRole, policy.ScopeUser:
		return strings.ToLower(strings.TrimSpace(tenant))
	default: // system
		return ""
	}
}

// authorizePolicyWrite enforces who may MUTATE a scope. System and global-tenant
// policy are platform property (platform owner only); every other scope is
// writable by that tenant's own admin (or the platform owner).
func (s *server) authorizePolicyWrite(c jwtClaims, scope policy.Scope, selector, tenant string) error {
	owning := policyOwningTenant(scope, selector, tenant)
	callerTenant, cross := principalTenant(c)
	if owning == "" || owning == TenantGlobal {
		if !cross {
			return errors.New("platform administrator required for system/global policy")
		}
		return nil
	}
	if cross {
		return nil
	}
	if owning != callerTenant {
		return errors.New("forbidden: policy belongs to another tenant")
	}
	return nil
}

// authorizePolicyRead enforces who may READ a scope. The platform owner sees all;
// a scoped admin sees its own tenant's scopes plus the system baseline it
// inherits (read-only).
func (s *server) authorizePolicyRead(c jwtClaims, scope policy.Scope, selector, tenant string) error {
	callerTenant, cross := principalTenant(c)
	if cross {
		return nil
	}
	owning := policyOwningTenant(scope, selector, tenant)
	if owning == "" { // system baseline is readable by any admin (it is inherited)
		return nil
	}
	if owning != callerTenant {
		return errors.New("forbidden: policy belongs to another tenant")
	}
	return nil
}

// parsePolicyScope validates the scope query/body value against the known set.
func parsePolicyScope(v string) (policy.Scope, error) {
	switch sc := policy.Scope(strings.TrimSpace(v)); sc {
	case policy.ScopeSystem, policy.ScopeTenant, policy.ScopeRole, policy.ScopeUser:
		return sc, nil
	default:
		return "", errors.New("invalid scope (want system|tenant|role|user)")
	}
}

// ---- handlers ---------------------------------------------------------------

// handlePolicyCatalog: GET /api/policy/catalog. The immutable control catalog,
// grouped by domain in catalog order, plus the scope hierarchy. Any admin.
func (s *server) handlePolicyCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	// Group by domain, preserving first-seen (catalog) order.
	var order []policy.Domain
	byDomain := map[policy.Domain][]policy.Setting{}
	for _, st := range s.secPolicy.Catalog().All() {
		if _, seen := byDomain[st.Domain]; !seen {
			order = append(order, st.Domain)
		}
		byDomain[st.Domain] = append(byDomain[st.Domain], st)
	}
	domains := make([]policyCatalogDomain, 0, len(order))
	for _, d := range order {
		domains = append(domains, policyCatalogDomain{Domain: d, Settings: byDomain[d]})
	}
	writeJSON(w, http.StatusOK, policyCatalogResponse{
		Scopes:  []policy.Scope{policy.ScopeSystem, policy.ScopeTenant, policy.ScopeRole, policy.ScopeUser},
		Domains: domains,
	})
}

// handlePolicyEffective: GET /api/policy/effective?tenant=&role=&user=. Resolves
// the effective policy for a subject — the Policy Simulator. A scoped admin may
// only simulate within its own tenant; the platform owner may target any tenant.
func (s *server) handlePolicyEffective(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	callerTenant, cross := principalTenant(claims)
	reqTenant := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tenant")))
	if !cross {
		if reqTenant != "" && reqTenant != callerTenant {
			writeError(w, http.StatusForbidden, errors.New("forbidden: cannot simulate another tenant"))
			return
		}
		reqTenant = callerTenant
	}
	sub := policy.Subject{
		Tenant: reqTenant,
		Role:   strings.TrimSpace(r.URL.Query().Get("role")),
		User:   strings.TrimSpace(r.URL.Query().Get("user")),
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":  sub,
		"resolved": s.secPolicy.Resolve(sub),
	})
}

// handlePolicyDocuments: GET /api/policy/documents. Lists the override documents
// the caller is entitled to see: everything for the platform owner, system +
// own-tenant documents for a scoped admin.
func (s *server) handlePolicyDocuments(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	callerTenant, cross := principalTenant(claims)
	var docs []policy.Document
	if cross {
		docs = s.secPolicy.AllDocuments()
	} else {
		docs = s.secPolicy.Documents(callerTenant)
	}
	if docs == nil {
		docs = []policy.Document{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"documents": docs})
}

// handlePolicyDocument: GET/PUT/DELETE /api/policy/document?scope=&selector=&tenant=.
// GET reads one scope's raw overrides; PUT sets a single validated override;
// DELETE clears one override (?key=, optional ?prune=true).
func (s *server) handlePolicyDocument(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	scope, err := parsePolicyScope(q.Get("scope"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	selector, tenant := q.Get("selector"), q.Get("tenant")

	switch r.Method {
	case http.MethodGet:
		if err := s.authorizePolicyRead(claims, scope, selector, tenant); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		doc, found, err := s.secPolicy.Document(scope, selector, tenant)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"document": doc, "found": found})

	case http.MethodPut:
		if err := s.authorizePolicyWrite(claims, scope, selector, tenant); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		var req policyOverrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ov := policy.Override{Value: req.Value, Locked: req.Locked}
		resolved, err := s.secPolicy.SetOverride(scope, selector, tenant, req.Key, ov, claims.Sub)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("policy", "override set", map[string]any{
			"actor": claims.Sub, "scope": scope, "selector": selector, "tenant": tenant, "key": req.Key,
		})
		writeJSON(w, http.StatusOK, map[string]any{"resolved": resolved})

	case http.MethodDelete:
		if err := s.authorizePolicyWrite(claims, scope, selector, tenant); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		key := strings.TrimSpace(q.Get("key"))
		if key == "" {
			writeError(w, http.StatusBadRequest, errors.New("key is required"))
			return
		}
		prune := strings.EqualFold(strings.TrimSpace(q.Get("prune")), "true")
		if err := s.secPolicy.ClearOverride(scope, selector, tenant, key, claims.Sub, prune); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("policy", "override cleared", map[string]any{
			"actor": claims.Sub, "scope": scope, "selector": selector, "tenant": tenant, "key": key,
		})
		w.WriteHeader(http.StatusNoContent)

	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

// handlePolicyValidate: POST /api/policy/validate. Runs the full write gate for a
// proposed override WITHOUT persisting, so the UI can preview acceptance and
// surface the exact rejection reason on the right card. Returns 200 with
// {ok, error?}; authorization failures are still 403.
func (s *server) handlePolicyValidate(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var req policyValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := parsePolicyScope(string(req.Scope)); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.authorizePolicyWrite(claims, req.Scope, req.Selector, req.Tenant); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	ov := policy.Override{Value: req.Value, Locked: req.Locked}
	if err := s.secPolicy.Validate(req.Scope, req.Selector, req.Tenant, req.Key, ov); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// methodNotAllowed writes a 405 with the Allow header set.
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
