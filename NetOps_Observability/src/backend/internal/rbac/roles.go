// Package rbac is the role/permission domain for PBAC: the module-level role
// model with its monotonic permission ladder, the compiled rule-bundle view,
// the file-backed role store, the role_binding store (bindings.go) and the
// scope identity vocabulary (scopes.go). See docs/IDENTITY_ACCESS.md and
// docs/design/saas-identity-pbac.md for the model.
//
// File-backed (roles.json) in the same spirit as the user/saved stores: no
// database dependency, swappable to Postgres later behind the same methods.
// Modules map to product nav sections; permission levels form a monotonic
// ladder none<read<write<admin.
package rbac

import (
	"encoding/json"
	"errors"
	"netops/backend/internal/platformdb"
	"os"
	"sort"
	"strings"
	"sync"
)

// ModuleSensitiveData gates reversible masking (Sealed Fields). It is its OWN
// module rather than a level of `administration` on purpose: revealing a card
// number is a different capability from configuring the platform, and an
// infrastructure or alerting admin must not acquire it by being an admin of
// something else. On the monotonic ladder:
//
//	read  → see that a field is sealed, and its masked display form
//	write → create and edit `seal` processors
//	admin → REVEAL plaintext through the audited unseal endpoint
const ModuleSensitiveData = "sensitive_data"

// Modules are the gated product areas (match the frontend nav sections).
var Modules = []string{
	"overview", "explore", "alerts", "infrastructure", "topology", "reports", "administration",
	ModuleSensitiveData,
}

// Permission levels (monotonic — each implies the ones below it).
const (
	LevelNone  = 0
	LevelRead  = 1
	LevelWrite = 2
	LevelAdmin = 3
)

// LevelName renders a permission level for views/audit lines.
func LevelName(l int) string {
	switch l {
	case LevelAdmin:
		return "admin"
	case LevelWrite:
		return "write"
	case LevelRead:
		return "read"
	default:
		return "none"
	}
}

// RoleRule is the rule-bundle form of a role's grant (PBAC Phase D, §1.4): a
// role is a named bundle of rules, not a frozen module→level matrix. Today rules
// are COMPILED from the Permissions grid so nothing changes; tomorrow custom and
// tenant-defined roles can be authored directly as validated rule bundles, and
// the decider can grow resource/action/condition granularity without a breaking
// interface change. The decider takes rules; a role is just a rule source.
type RoleRule struct {
	Effect       string   `json:"effect"`        // allow | deny
	ResourceType string   `json:"resource_type"` // a Module (product area)
	Actions      []string `json:"actions"`       // view | write | admin
}

// actionsForLevel maps a monotonic permission level to the rule actions it grants.
func actionsForLevel(level int) []string {
	switch {
	case level >= LevelAdmin:
		return []string{"view", "write", "admin"}
	case level >= LevelWrite:
		return []string{"view", "write"}
	case level >= LevelRead:
		return []string{"view"}
	default:
		return nil
	}
}

// compileRoleRules derives the rule-bundle view from a module→level grid. Pure;
// the grid stays authoritative for can()/requirePerm, so this is non-behavioural.
func compileRoleRules(perms map[string]int) []RoleRule {
	out := make([]RoleRule, 0, len(Modules))
	for _, mod := range Modules {
		if acts := actionsForLevel(perms[mod]); len(acts) > 0 {
			out = append(out, RoleRule{Effect: EffectAllow, ResourceType: mod, Actions: acts})
		}
	}
	return out
}

// Role is a named permission grid. Built-in roles are seeded and protected.
type Role struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Builtin     bool           `json:"builtin"`
	Description string         `json:"description"`
	Permissions map[string]int `json:"permissions"` // module -> level (authoritative)
	// Rules is the compiled rule-bundle view (PBAC Phase D), populated on read.
	// Forward representation; the grid above stays authoritative.
	Rules []RoleRule `json:"rules,omitempty"`
}

// withRules returns a copy of the role with its compiled rule bundle attached.
func (r Role) withRules() Role {
	r.Rules = compileRoleRules(r.Permissions)
	return r
}

// Built-in role IDs.
const (
	RoleSuperAdmin = "super-admin"
	RoleOrgAdmin   = "org-admin" // admin WITHIN one org (bound at org scope; PBAC Phase B)
	RoleOperator   = "operator"
	RoleReadOnly   = "read-only"
	RoleAuditor    = "auditor"    // compliance: read everything incl. the audit trail, change nothing
	RoleAPIClient  = "api-client" // least-privilege machine identity for programmatic access
	// RoleIngest is the ZERO-permission machine identity (tracker 254): it may
	// do only what a dedicated `ingest:*` scope explicitly admits, and it reads
	// nothing at all through the RBAC grid.
	//
	// It exists because a first-party RUM key is served inside a public web
	// page, so it must be assumed public. Before this role, an ingest-only key
	// derived RoleReadOnly (roleFromScopes) and could therefore READ the
	// tenant's entire operational surface — devices, flows, alerts, topology —
	// from any browser that viewed source. A credential whose only job is to
	// POST evidence must be able to do only that.
	RoleIngest = "ingest"
)

// IsOrgManagerRole reports whether a role, when bound at an org scope, lets the
// principal manage that org's tenants/users (an org administrator). The platform
// super-admin also qualifies. Used by access.go reachability.
func IsOrgManagerRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == RoleOrgAdmin || IsSuperAdminRole(role)
}

// IsSuperAdminRole maps both the new role id and the legacy "admin" value onto
// super-admin, so pre-existing users.json accounts keep full access.
func IsSuperAdminRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == RoleSuperAdmin || r == "admin"
}

// legacyRoleAlias normalizes the historical "admin"/"viewer" values onto the
// new built-in role ids during permission resolution.
func legacyRoleAlias(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return RoleSuperAdmin
	case "viewer", "":
		return RoleReadOnly
	default:
		return role
	}
}

func builtinRoles() []Role {
	all := func(l int) map[string]int {
		m := map[string]int{}
		for _, mod := range Modules {
			m[mod] = l
		}
		return m
	}
	operator := all(LevelRead)
	operator["alerts"] = LevelWrite
	operator["infrastructure"] = LevelWrite
	operator["administration"] = LevelNone
	readonly := all(LevelRead)
	readonly["administration"] = LevelNone
	// Auditor: like read-only, but ALSO reads the administration area (the audit
	// trail + config) — the one non-super role that can. Still zero write anywhere.
	auditor := all(LevelRead)
	// API client: least-privilege machine identity. Reads operational data only;
	// no reports, no administration. Narrow further per token via API-token scopes
	// (#23). Distinct from read-only (which can read reports) by intent + tighter grid.
	apiClient := all(LevelRead)
	apiClient["reports"] = LevelNone
	apiClient["administration"] = LevelNone
	// Ingest: NOTHING through the grid. Its authority comes entirely from the
	// dedicated `ingest:*` scope its holder carries, checked by the one gate
	// that honours that scope. Every other handler in the product refuses it,
	// which is what makes such a key safe to publish.
	ingest := all(LevelNone)
	// Org admin: full administration, but only ever bound at an org scope — its
	// reach is the tenants inside that org (access.go), never platform plumbing
	// (Authorize blocks ResInfraStack for any non-platform-owner). Same grid as
	// super-admin; the SCOPE is the limiter.
	orgAdmin := all(LevelAdmin)
	return []Role{
		{ID: RoleSuperAdmin, Name: "Super Admin", Builtin: true,
			Description: "Full control across all tenants, including identity.", Permissions: all(LevelAdmin)},
		{ID: RoleOrgAdmin, Name: "Org Admin", Builtin: true,
			Description: "Administers the tenants and people within a single organization.", Permissions: orgAdmin},
		{ID: RoleOperator, Name: "Operator", Builtin: true,
			Description: "Acknowledge/silence alerts, run discovery, manage devices.", Permissions: operator},
		{ID: RoleReadOnly, Name: "Read-only", Builtin: true,
			Description: "View everything, change nothing.", Permissions: readonly},
		{ID: RoleAuditor, Name: "Auditor", Builtin: true,
			Description: "Read-only across all areas including the audit trail; cannot change anything.", Permissions: auditor},
		{ID: RoleAPIClient, Name: "API Client", Builtin: true,
			Description: "Least-privilege machine identity for programmatic API access (telemetry, alerts, topology); narrow further with API-token scopes.", Permissions: apiClient},
		{ID: RoleIngest, Name: "Ingest", Builtin: true,
			Description: "Machine identity that may only POST the evidence its ingest scope names, and can read nothing at all. Used by credentials that are published — the first-party RUM snippet's key lives in a public page.", Permissions: ingest},
	}
}

// RoleStore is the file-backed role registry (roles.json).
type RoleStore struct {
	mu    sync.RWMutex
	path  string
	roles map[string]Role
}

// NewRoleStore opens (or creates) the store and (re)seeds the built-in roles so
// upgrades pick up new defaults; custom roles are preserved.
func NewRoleStore(path string) (*RoleStore, error) {
	if path == "" {
		path = "/data/roles.json"
	}
	s := &RoleStore{path: path, roles: make(map[string]Role)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	changed := false
	for _, r := range builtinRoles() {
		if _, ok := s.roles[r.ID]; !ok {
			s.roles[r.ID] = r
			changed = true
		}
	}
	if changed {
		if err := s.flushLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *RoleStore) load() error {
	b, err := platformdb.Load(s.path)
	if err != nil {
		return err
	}
	var list []Role
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, r := range list {
		s.roles[r.ID] = r
	}
	return nil
}

func (s *RoleStore) flushLocked() error {
	list := make([]Role, 0, len(s.roles))
	for _, r := range s.roles {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *RoleStore) List() []Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Role, 0, len(s.roles))
	for _, r := range s.roles {
		out = append(out, r.withRules()) // attach the compiled rule bundle
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin // built-ins first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *RoleStore) Get(id string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[legacyRoleAlias(id)]
	return r, ok
}

// slugify is the role-id form of a role name. Deliberately duplicated from
// main's identity slug helper (the no-utils rule): the package must not reach
// back into main, and the two may diverge.
func slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// Upsert creates or replaces a custom role. Built-in roles cannot be created
// or overwritten through this path.
func (s *RoleStore) Upsert(r Role) (Role, error) {
	if strings.TrimSpace(r.Name) == "" {
		return Role{}, errors.New("role name required")
	}
	if r.ID == "" {
		r.ID = slugify(r.Name)
	}
	if r.ID == "" {
		return Role{}, errors.New("role name must contain letters or digits")
	}
	r.Builtin = false
	clean := map[string]int{}
	for _, mod := range Modules {
		clean[mod] = r.Permissions[mod] // defaults to 0 (none)
	}
	r.Permissions = clean
	r.Rules = nil // never persist the compiled view; it is derived on read
	// Sandbox (PBAC Phase D, §7.2): a CUSTOM role can never grant administration
	// at admin level — platform/identity control (minting roles, tenants, users
	// platform-wide) is reserved for the built-in super-admin / org-admin. This
	// keeps custom and (future) tenant-authored roles from being an escalation
	// path. Operational admin within a scope is still expressible via write.
	if err := validateCustomRole(r); err != nil {
		return Role{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.roles[r.ID]; ok && existing.Builtin {
		return Role{}, errors.New("cannot overwrite a built-in role")
	}
	s.roles[r.ID] = r
	if err := s.flushLocked(); err != nil {
		return Role{}, err
	}
	return r, nil
}

// validateCustomRole enforces the sandbox for non-built-in roles (§7.2): no
// administration:admin (the escalation vector). Returns a clear error so the UI
// can explain the rejection.
func validateCustomRole(r Role) error {
	if r.Permissions["administration"] >= LevelAdmin {
		return errors.New("a custom role cannot grant administration at admin level — that is reserved for built-in administrators")
	}
	return nil
}

func (s *RoleStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[id]
	if !ok {
		return errors.New("no such role")
	}
	if r.Builtin {
		return errors.New("cannot delete a built-in role")
	}
	delete(s.roles, id)
	return s.flushLocked()
}

// Allows reports whether a role grants at least `need` on a module. Super-admin
// (and the legacy "admin" value) always passes.
func (s *RoleStore) Allows(roleID, module string, need int) bool {
	if IsSuperAdminRole(roleID) {
		return true
	}
	r, ok := s.Get(roleID)
	if !ok {
		return false
	}
	return r.Permissions[module] >= need
}
