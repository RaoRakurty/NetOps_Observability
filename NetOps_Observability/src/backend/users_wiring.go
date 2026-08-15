package backend

// users_wiring.go — composition root + source-compat shims for internal/users.
//
// The identity store owns account records and the invariants that must hold
// across both backends; what it must NOT own are its cross-domain inputs —
// persistence, structured logging, the SR-025 federated-role guard, the role
// predicate behind the last-super-admin floor, account_policy's password-change
// stamping, and the env-derived limits — so those are supplied here.

import (
	"netops/backend/internal/platformdb"
	"os"
	"strings"

	"netops/backend/internal/users"
)

// Type shims (the jwtClaims-alias technique): User fans into ~59 files.
type (
	User      = users.User
	usersRepo = users.Repo
)

// guardFederatedRole prevents a federated identity from SILENTLY becoming the
// platform owner (global tenant + super-admin) via an IdP role/tenant mapping
// (SR-025). A mis-mapped IdP group must not seize cross-tenant control; require
// an explicit FEDERATION_ALLOW_PLATFORM_OWNER=true opt-in, otherwise downgrade.
//
// H1c: the predicate must match isPlatformOwner's exactly, or the guard has
// holes the owner check does not — tenant is normalized (lowercase/trim) and ""
// counts as the global/platform realm, and the role goes through
// isSuperAdminRole so the legacy "admin" alias (which grants full super-admin
// everywhere else) cannot slip past a literal RoleSuperAdmin comparison.
func guardFederatedRole(role, tenant, username, source string) string {
	t := strings.ToLower(strings.TrimSpace(tenant))
	if (t == "" || t == TenantGlobal) && isSuperAdminRole(role) && os.Getenv("FEDERATION_ALLOW_PLATFORM_OWNER") != "true" {
		logWarn("auth", "refused federated platform-owner mapping — downgrading role; set FEDERATION_ALLOW_PLATFORM_OWNER=true to allow",
			map[string]any{"user": username, "source": source})
		return RoleReadOnly
	}
	return role
}

// maxUsersLimit reads the configurable account cap from MAX_USERS (0/unset =
// unlimited). Negative/garbage → 0 (unlimited), preserving existing behavior.
func maxUsersLimit() int {
	if v := os.Getenv("MAX_USERS"); v != "" {
		if n, err := parseIntStrict(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// userDeps supplies the store's injected cross-domain dependencies.
func userDeps() users.Deps {
	return users.Deps{
		KV:                  platformKV{},
		Errorf:              logError,
		GuardRole:           guardFederatedRole,
		IsSuperAdmin:        isSuperAdminRole,
		ApplyPasswordChange: applyPasswordChange,
		DefaultTenant:       TenantGlobal,
		MaxUsers:            maxUsersLimit(),
	}
}

// newUsersStore selects the user-store backend: under STORE_BACKEND=postgres
// the per-row RLS-backed PGStore; otherwise the file-backed store.
func newUsersStore(path string) (usersRepo, error) {
	if ps, ok := platformdb.ActivePG(); ok {
		return users.NewPGStore(ps.DB(), userDeps())
	}
	return users.NewFileStore(path, userDeps())
}
