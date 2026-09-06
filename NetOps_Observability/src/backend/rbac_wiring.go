package backend

// rbac_wiring.go — main-side aliases for the extracted internal/rbac domain
// (P2 W4.14): the role model + store, the role_binding store and the scope-id
// vocabulary live in internal/rbac; these aliases keep main's call sites
// stable (the jwtClaims technique). The scope TREE walkers stay in scopes.go —
// they read the live org/tenant stores.

import "netops/backend/internal/rbac"

type (
	Role         = rbac.Role
	RoleRule     = rbac.RoleRule
	RoleBinding  = rbac.RoleBinding
	roleStore    = rbac.RoleStore
	bindingStore = rbac.BindingStore
)

const (
	LevelNone  = rbac.LevelNone
	LevelRead  = rbac.LevelRead
	LevelWrite = rbac.LevelWrite
	LevelAdmin = rbac.LevelAdmin

	RoleSuperAdmin = rbac.RoleSuperAdmin
	RoleOrgAdmin   = rbac.RoleOrgAdmin
	RoleOperator   = rbac.RoleOperator
	RoleReadOnly   = rbac.RoleReadOnly
	RoleAuditor    = rbac.RoleAuditor
	RoleAPIClient  = rbac.RoleAPIClient
	RoleIngest     = rbac.RoleIngest

	EffectAllow = rbac.EffectAllow
	EffectDeny  = rbac.EffectDeny

	PrincipalUser    = rbac.PrincipalUser
	PrincipalService = rbac.PrincipalService
	PrincipalAgent   = rbac.PrincipalAgent
	PrincipalDevice  = rbac.PrincipalDevice

	ScopePlatform     = rbac.ScopePlatform
	scopeTypeOrg      = rbac.ScopeTypeOrg
	scopeTypeTenant   = rbac.ScopeTypeTenant
	scopeTypeResource = rbac.ScopeTypeResource
)

func newRoleStore(path string) (*roleStore, error) { return rbac.NewRoleStore(path) }

func newBindingStore(path string) (*bindingStore, error) { return rbac.NewBindingStore(path) }

func isSuperAdminRole(role string) bool { return rbac.IsSuperAdminRole(role) }

func isOrgManagerRole(role string) bool { return rbac.IsOrgManagerRole(role) }

func scopeOrg(id string) string { return rbac.ScopeOrg(id) }

func scopeTenant(id string) string { return rbac.ScopeTenant(id) }

func parseScope(id string) (scopeType, rest string) { return rbac.ParseScope(id) }
