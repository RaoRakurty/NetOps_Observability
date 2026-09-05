package backend

// identity_handlers.go — admin CRUD for users, roles, tenants and API keys.
// All routes here require the caller to hold administration:admin (super-admin
// always qualifies). See docs/IDENTITY_ACCESS.md + docs/API_ACCESS.md.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/apikey"
	// LICENCE-BEGIN
	"netops/backend/internal/entitlement"
	// LICENCE-END
	"netops/backend/internal/rbac"
	"strings"
	"time"
)

// requirePerm gates a handler on a (module, level). Returns the caller's claims
// on success; writes 401/403 and returns ok=false otherwise.
func (s *server) requirePerm(w http.ResponseWriter, r *http.Request, module string, level int) (jwtClaims, bool) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return jwtClaims{}, false
	}
	if !s.roles.Allows(claims.Role, module, level) {
		writeError(w, http.StatusForbidden, errors.New(module+" "+rbac.LevelName(level)+" permission required"))
		return jwtClaims{}, false
	}
	return claims, true
}

// requireAdmin gates a handler on administration:admin.
func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	return s.requirePerm(w, r, "administration", LevelAdmin)
}

// requirePlatformAdmin gates an action to the cross-tenant PLATFORM OWNER
// (a super-admin in the global tenant). Used for platform-wide resources a
// tenant admin must never mutate: role definitions, the tenant registry,
// platform SSO config, etc.
func (s *server) requirePlatformAdmin(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return claims, false
	}
	// Platform-wide capability is an IDENTITY question — is the caller the platform
	// owner? Use isPlatformOwner, NOT principalTenant/can(): the latter honor the
	// "view as tenant" override and would falsely deny the owner while scoped into
	// a tenant (which broke the bundled NetBox config + platform admin pages).
	if !isPlatformOwner(claims) {
		writeError(w, http.StatusForbidden, errors.New("platform administrator required"))
		return claims, false
	}
	return claims, true
}

// handlePermissions returns the caller's effective module→level grid so the
// SPA can gate navigation. Available to any authenticated user.
func (s *server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	perms := map[string]int{}
	for _, m := range rbac.Modules {
		switch {
		case isSuperAdminRole(claims.Role):
			perms[m] = LevelAdmin
		default:
			if role, ok := s.roles.Get(claims.Role); ok {
				perms[m] = role.Permissions[m]
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": claims.Role, "permissions": perms})
}

// ---- users -----------------------------------------------------------------

type createUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	TenantID    string `json:"tenant_id"`
	Status      string `json:"status"`
}

func (s *server) handleUsers(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		// Strict isolation is enforced in the repo: List returns only the caller's
		// tenant (RLS-scoped on the pg backend; the same sameTenant filter on file).
		users := s.users.List(tenant, cross)
		out := make([]publicUser, 0, len(users))
		for _, u := range users {
			out = append(out, toPublic(u))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A tenant admin may only create users inside its own tenant; only the
		// platform owner may target an arbitrary tenant.
		if !cross {
			req.TenantID = tenant
		}
		role := req.Role
		if role == "" {
			role = RoleReadOnly
		}
		if _, ok := s.roles.Get(role); !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown role"))
			return
		}
		// Enforce the target scope's resolved password policy on admin-create — same
		// rules the user's own change-password enforces, so an admin can't seed a
		// weaker password than the policy allows. (Empty password = invited/passwordless
		// account; CreateFull permits it and login simply never matches.)
		if req.Password != "" {
			rules := s.callerPasswordRules(jwtClaims{Sub: req.Username, Role: role, Tenant: req.TenantID})
			if err := validatePasswordAgainstPolicy(req.Password, rules); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		u, err := s.users.CreateFull(User{
			Username: req.Username, Role: role, Email: req.Email,
			DisplayName: req.DisplayName, TenantID: req.TenantID, Status: req.Status,
		}, req.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.logBindingSync(u, "user-create") // keep the role_binding mirror in sync (PBAC Phase A)
		logInfo("identity", "user created", map[string]any{"user": u.Username, "role": u.Role})
		writeJSON(w, http.StatusCreated, toPublic(u))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type updateUserRequest struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	TenantID    string `json:"tenant_id"`
	Status      string `json:"status"`
	Password    string `json:"password"` // optional admin reset
}

func (s *server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid username"))
		return
	}
	tenant, cross := principalTenant(claims)
	// Strict isolation: a tenant admin may only act on users inside its own
	// tenant. Resolve the target first and 404 (not 403) when it is out of scope,
	// so a tenant admin can neither see nor delete the platform admin / other
	// tenants' users — and existence isn't leaked.
	target, found := s.users.Get(id)
	if !found || !sameTenant(target.TenantID, tenant, cross) {
		writeError(w, http.StatusNotFound, errors.New("user not found"))
		return
	}
	switch r.Method {
	case http.MethodPatch, http.MethodPut:
		var req updateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Role != "" {
			if _, ok := s.roles.Get(req.Role); !ok {
				writeError(w, http.StatusBadRequest, errors.New("unknown role"))
				return
			}
		}
		// #146b: the IdP owns a federated account's credential. Setting a local
		// password here would stamp PasswordChangedAt/PasswordHistory onto a
		// record whose lifecycle rules never evaluate them — dead, misleading
		// state that login can never reach. Refused BEFORE the profile patch so
		// a mixed request doesn't half-apply. (Self-service change-password
		// already refuses federated accounts the same way.)
		if req.Password != "" && !isLocalAccount(target.AuthSource) {
			writeError(w, http.StatusBadRequest, errors.New("password is managed by the identity provider for this account"))
			return
		}
		// A tenant admin cannot move a user out of its own tenant.
		tid := req.TenantID
		if !cross {
			tid = target.TenantID
		}
		u, err := s.users.Update(id, User{
			Role: req.Role, Email: req.Email, DisplayName: req.DisplayName,
			TenantID: tid, Status: req.Status,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Password != "" {
			if err := s.users.ResetPassword(id, req.Password); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		s.logBindingSync(u, "user-update") // re-sync the role_binding mirror (PBAC Phase A)
		writeJSON(w, http.StatusOK, toPublic(u))
	case http.MethodDelete:
		if err := s.users.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.removeUserBindings(id) // drop the deleted principal's bindings (PBAC Phase A)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PATCH, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- roles -----------------------------------------------------------------

func (s *server) handleRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		// Role definitions are platform-wide; a tenant admin may read them (to
		// assign to its own users) but not change them.
		writeJSON(w, http.StatusOK, map[string]any{"modules": rbac.Modules, "roles": s.roles.List()})
	case http.MethodPost:
		if _, ok := s.requirePlatformAdmin(w, r); !ok {
			return
		}
		var role Role
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		saved, err := s.roles.Upsert(role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, saved)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleRoleByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid role id"))
		return
	}
	switch r.Method {
	case http.MethodPut:
		var role Role
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		role.ID = id
		saved, err := s.roles.Upsert(role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if err := s.roles.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- tenants ---------------------------------------------------------------

type createTenantRequest struct {
	Name string `json:"name"`
	// Slug is the optional human URL handle. Blank → derived from Name. Validated
	// + globally unique + immutable. The tenant's security key is the opaque id
	// minted server-side, never this slug.
	Slug          string `json:"slug"`
	Note          string `json:"note"`
	IsolationMode string `json:"isolation_mode"`
	// OrgID is the Organization the new tenant belongs to (id OR slug — resolved
	// server-side to the opaque org id). Blank → Global org.
	OrgID string `json:"org_id"`
	// Region assigns the tenant to a data-residency region. Blank → inherit org.
	Region string `json:"region"`
	// OperatorRestricted hides the tenant's data from the global/operator view from
	// the moment it's created (data-privacy / compliance) — see Tenant.OperatorRestricted.
	OperatorRestricted bool `json:"operator_restricted"`
}

func (s *server) handleTenants(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		all := s.tenants.List()
		if cross {
			writeJSON(w, http.StatusOK, all)
			return
		}
		// A tenant admin sees only its own tenant in the registry.
		out := make([]Tenant, 0, 1)
		for _, t := range all {
			if strings.EqualFold(t.ID, tenant) {
				out = append(out, t)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		if !cross {
			writeError(w, http.StatusForbidden, errors.New("platform administrator required"))
			return
		}
		var req createTenantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Resolve the org reference (id OR slug — UNTRUSTED) to the canonical opaque
		// org id before creating the tenant under it (zero-trust on input). Blank
		// org → Global, which always exists.
		if req.OrgID != "" {
			o, ok := s.orgs.Resolve(req.OrgID)
			if !ok {
				writeError(w, http.StatusBadRequest, errors.New("unknown organization"))
				return
			}
			req.OrgID = o.ID // store the opaque org id, never the slug
		}
		// LICENCE-BEGIN — MSP / fleet management of MANY tenants is the commercial
		// capability (owner spec, 2026-09-04). Read the scope carefully, because
		// the line matters:
		//
		//   NOT gated — tenant ISOLATION itself, and normal SINGLE-tenant
		//   operation. Isolation is a safety property of every tier and is never
		//   an entitlement; the seeded Global tenant always exists and a
		//   deployment always has one working tenant.
		//
		//   GATED — running a FLEET of them from one platform, which is the MSP
		//   product. So the SECOND real tenant is the one that asks.
		//
		// The gate is semantic (Entitled(FeatureMSPManagement)), never a tier
		// comparison: a licence may grant fleet management at any tier, and the
		// file decides, not the label.
		if !entitlement.Entitled(s.entitlements, entitlement.FeatureMSPManagement) {
			if n := countRealTenants(s.tenants.List()); n >= 1 {
				entitlement.WriteRefusal(w, entitlement.Require(s.entitlements, entitlement.FeatureMSPManagement))
				return
			}
		}
		// LICENCE-END
		t, err := s.tenants.Create(req.Name, req.Slug, req.Note, req.IsolationMode, req.OrgID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Assign the data-residency region at creation time, if provided.
		if req.Region != "" {
			updated, e := s.tenants.SetRegion(t.ID, req.Region)
			if e != nil {
				writeError(w, http.StatusBadRequest, e)
				return
			}
			t = updated
		}
		// Apply the "hide from global view" setting at creation time, if requested.
		//
		// F-81: the error used to be discarded (`if …; e == nil`), so a failed
		// write returned 201 with operator_restricted:false. This is the
		// data-privacy switch — the tenant's telemetry is visible to the global
		// operator view from the moment it exists. Failing OPEN on a privacy
		// control while reporting success is the worst available outcome, so a
		// failure now removes the half-created tenant rather than leaving one
		// that is exposed and believed to be restricted.
		if req.OperatorRestricted {
			updated, e := s.tenants.SetOperatorRestricted(t.ID, true)
			if e != nil {
				logError("tenants", "operator_restricted could not be applied — rolling back the tenant",
					map[string]any{"tenant_id": t.ID, "err": e.Error()})
				if derr := s.tenants.Delete(t.ID); derr != nil {
					logError("tenants", "ROLLBACK FAILED — tenant exists and is NOT operator-restricted",
						map[string]any{"tenant_id": t.ID, "err": derr.Error()})
				}
				writeError(w, http.StatusInternalServerError,
					errors.New("tenant not created: the operator-visibility restriction could not be applied"))
				return
			}
			t = updated
		}
		logInfo("tenants", "tenant created", map[string]any{"tenant_id": t.ID, "tenant_slug": t.Slug, "org_id": orgOf(t)})
		s.recordIdentityAudit(r, claims, "TENANT_CREATED", auditTenantDetail(t))
		writeJSON(w, http.StatusCreated, t)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleTenantByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	ref := strings.TrimPrefix(r.URL.Path, "/api/tenants/")
	if ref == "" || strings.Contains(ref, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid tenant id"))
		return
	}
	// The path segment is UNTRUSTED (id or slug). Resolve to the canonical opaque
	// tenant id before any mutation; fail closed if it doesn't resolve.
	resolved, found := s.tenants.Resolve(ref)
	if !found {
		writeError(w, http.StatusNotFound, errors.New("tenant not found"))
		return
	}
	id := resolved.ID
	switch r.Method {
	case http.MethodPatch:
		// Update mutable tenant settings: operator-visibility (compliance) and/or
		// data-residency region.
		var req struct {
			OperatorRestricted *bool   `json:"operator_restricted"`
			Region             *string `json:"region"`
			Status             *string `json:"status"`          // active | suspended (lifecycle)
			DefaultLanding     *string `json:"default_landing"` // admin-configurable landing route
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.OperatorRestricted == nil && req.Region == nil && req.Status == nil && req.DefaultLanding == nil {
			writeError(w, http.StatusBadRequest, errors.New("no updatable field provided"))
			return
		}
		var t Tenant
		var err error
		if req.Status != nil {
			if t, err = s.tenants.SetStatus(id, *req.Status); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			logWarn("tenants", "lifecycle status changed", map[string]any{"tenant_id": id, "status": *req.Status})
		}
		if req.Region != nil {
			if t, err = s.tenants.SetRegion(id, *req.Region); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			logInfo("tenants", "region changed", map[string]any{"tenant_id": id, "region": *req.Region})
		}
		if req.OperatorRestricted != nil {
			if t, err = s.tenants.SetOperatorRestricted(id, *req.OperatorRestricted); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			logInfo("tenants", "operator visibility changed", map[string]any{"tenant_id": id, "operator_restricted": *req.OperatorRestricted})
		}
		if req.DefaultLanding != nil {
			if t, err = s.tenants.SetDefaultLanding(id, *req.DefaultLanding); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			logInfo("tenants", "default landing changed", map[string]any{"tenant_id": id, "default_landing": t.DefaultLanding})
		}
		s.recordIdentityAudit(r, claims, "TENANT_UPDATED", auditTenantDetail(t))
		writeJSON(w, http.StatusOK, t)
	case http.MethodDelete:
		t := resolved
		// Guard a high-impact, irreversible action (GitHub/AWS/GCP pattern), enforced
		// server-side so the API can't be hit without the safeguards:
		// 1) Type-to-confirm — the caller must echo the EXACT tenant name.
		if !strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("confirm")), t.Name) {
			writeError(w, http.StatusBadRequest, errors.New("deletion not confirmed — re-enter the exact tenant name"))
			return
		}
		// 2) Refuse a populated tenant unless explicitly forced — deleting it orphans
		//    its users/data. Surface the impact so removal is a deliberate decision.
		force := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("force")), "true")
		if n := len(s.users.List(id, false)); n > 0 && !force {
			writeError(w, http.StatusConflict, fmt.Errorf("tenant still has %d user(s) — reassign or remove them first, or confirm a force delete", n))
			return
		}
		if err := s.tenants.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logWarn("tenants", "tenant deleted", map[string]any{"tenant_id": id, "name": t.Name, "forced": force})
		detail := auditTenantDetail(t)
		detail["forced"] = force
		s.recordIdentityAudit(r, claims, "TENANT_DELETED", detail)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PATCH, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- api keys --------------------------------------------------------------

type createAPIKeyRequest struct {
	Label           string     `json:"label"`
	TenantID        string     `json:"tenant_id"`
	Scopes          []string   `json:"scopes"`
	RateLimitPerMin int        `json:"rate_limit_per_min"`
	GrantTypes      []string   `json:"grant_types"`
	ClientURI       string     `json:"client_uri"`
	LogoURI         string     `json:"logo_uri"`
	Contacts        []string   `json:"contacts"`
	ContactPhone    string     `json:"contact_phone"`
	SourceCIDRs     []string   `json:"source_cidrs"`
	ClientExpiresAt *time.Time `json:"client_expires_at"`
	SecretExpiresAt *time.Time `json:"secret_expires_at"`
}

func (s *server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		all := s.apiKeys.List()
		out := make([]apikey.Public, 0, len(all))
		for _, k := range all {
			if sameTenant(k.TenantID, tenant, cross) {
				out = append(out, k)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req createAPIKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A tenant admin can only mint keys bound to its own tenant.
		if !cross {
			req.TenantID = tenant
		}
		rec, secret, err := s.apiKeys.Create(apikey.Input{
			TenantID:        req.TenantID,
			Label:           req.Label,
			Scopes:          req.Scopes,
			RateLimitPerMin: req.RateLimitPerMin,
			GrantTypes:      req.GrantTypes,
			ClientURI:       req.ClientURI,
			LogoURI:         req.LogoURI,
			Contacts:        req.Contacts,
			ContactPhone:    req.ContactPhone,
			SourceCIDRs:     req.SourceCIDRs,
			ClientExpiresAt: req.ClientExpiresAt,
			SecretExpiresAt: req.SecretExpiresAt,
		}, claims.Sub)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("identity", "api key created", map[string]any{"id": rec.ID, "by": claims.Sub})
		// The plaintext secret is returned exactly once here.
		writeJSON(w, http.StatusCreated, map[string]any{"key": rec, "secret": secret})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/apikeys/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid key id"))
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Strict isolation: a tenant admin may only revoke keys bound to its own
	// tenant. 404 when out of scope so other tenants' key ids aren't probeable.
	tenant, cross := principalTenant(claims)
	visible := false
	for _, k := range s.apiKeys.List() {
		if k.ID == id {
			visible = sameTenant(k.TenantID, tenant, cross)
			break
		}
	}
	if !visible {
		writeError(w, http.StatusNotFound, errors.New("key not found"))
		return
	}
	if err := s.apiKeys.Revoke(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LICENCE-BEGIN
// countRealTenants counts tenants excluding the seeded Global root.
//
// Global is platform scaffolding that always exists — counting it would make
// the FIRST tenant an operator creates look like the second and refuse a
// perfectly ordinary single-tenant install.
func countRealTenants(all []Tenant) int {
	n := 0
	for _, t := range all {
		if t.ID != TenantGlobal {
			n++
		}
	}
	return n
}

// LICENCE-END
