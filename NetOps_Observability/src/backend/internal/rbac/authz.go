package rbac

// authz.go — the single authorization decision point (extracted P2 RA.1).
//
// Every tenant/role check in the API funnels through Authorize(principal,
// action, resource). Centralizing the policy means a new endpoint inherits
// isolation by asking one function instead of re-deriving "can this caller see
// this?" by hand — the class of bug that let the dashboard, collectors and SNMP
// credentials leak across tenants. The entrypoint's leaf helpers (canSeeDevice,
// canSeeSaved, sameTenant, requireCrossTenant, requirePlatformAdmin) are thin
// adapters over this layer, so the rule lives in exactly one place.
//
// Authorize is pure (no IO) so it is trivially testable and reused identically
// by HTTP handlers, the WebSocket hub, and background jobs. The 404-vs-403
// existence-hiding rule stays with the HTTP adapter in the entrypoint.

import "strings"

// Action is the verb a principal is attempting on a resource.
type Action string

const (
	ActionView   Action = "view"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// ResourceType identifies the kind of thing being acted on. Kept as a closed
// set so the policy switch is exhaustive and a typo can't silently allow.
type ResourceType string

const (
	ResDevice     ResourceType = "device"
	ResSaved      ResourceType = "saved_object"
	ResUser       ResourceType = "user"
	ResTenant     ResourceType = "tenant"
	ResRole       ResourceType = "role"
	ResAPIKey     ResourceType = "api_key"         // #nosec G101 -- ResourceType enum value, not a credential
	ResSNMPCred   ResourceType = "snmp_credential" // #nosec G101 -- ResourceType enum value, not a credential
	ResAlert      ResourceType = "alert"
	ResInfraStack ResourceType = "infra_stack" // platform plumbing: stack health, collectors, raw tools
)

// Principal is the authenticated actor, resolved once from token claims. Cross
// marks the platform owner (a super-admin in the global/platform tenant), who
// sees and governs everything. It must be set ONLY from the entrypoint's
// canonical principalTenant resolution — never from request input.
type Principal struct {
	Subject string
	Role    string
	Tenant  string
	Cross   bool
}

// Resource is the target of an action. Tenant is the owning tenant id, where
// "" / global means platform-owned (visible to the platform owner only).
type Resource struct {
	Type   ResourceType
	Tenant string
}

// Decision is the outcome; Reason is for logs/audit (Phase 3).
type Decision struct {
	Allow  bool
	Reason string
}

// Authorize is THE policy.
func Authorize(p Principal, a Action, r Resource) Decision {
	// The platform owner is unrestricted.
	if p.Cross {
		return Decision{true, "platform owner"}
	}

	switch r.Type {
	// Platform plumbing is never visible to a tenant-scoped principal.
	case ResInfraStack:
		return Decision{false, "platform administrator required"}

	// Role definitions are platform-wide: readable by tenant admins (to assign
	// to their own users) but mutable only by the platform owner.
	case ResRole:
		if a == ActionView {
			return Decision{true, "role definitions are readable"}
		}
		return Decision{false, "platform administrator required"}

	// The tenant registry: a tenant admin may view its own tenant; creating or
	// changing tenants is platform-owner only.
	case ResTenant:
		if a == ActionView && SameTenantStrict(r.Tenant, p.Tenant) {
			return Decision{true, "own tenant"}
		}
		if a == ActionView {
			return Decision{false, "not your tenant"}
		}
		return Decision{false, "platform administrator required"}

	// Everything tenant-scoped (devices, saved objects, users, api keys, snmp
	// credentials, alerts): exact tenant match. Global/untagged is platform-owned.
	default:
		if SameTenantStrict(r.Tenant, p.Tenant) {
			return Decision{true, "same tenant"}
		}
		return Decision{false, "cross-tenant access denied"}
	}
}

// SameTenantStrict compares two tenant ids for an already-scoped principal
// (case/space-insensitive, exact match; global/untagged never matches a scoped
// tenant). The cross-tenant short-circuit lives in Authorize.
func SameTenantStrict(resourceTenant, principalTenant string) bool {
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(principalTenant))
}
