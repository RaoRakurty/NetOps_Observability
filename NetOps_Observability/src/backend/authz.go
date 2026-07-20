package main

import (
	"errors"
	"net/http"
	"strings"
)

// authz.go — the single authorization decision point.
//
// Every tenant/role check in the API funnels through Authorize(principal,
// action, resource). Centralizing the policy means a new endpoint inherits
// isolation by asking one function instead of re-deriving "can this caller see
// this?" by hand — the class of bug that let the dashboard, collectors and SNMP
// credentials leak across tenants. The leaf helpers (canSeeDevice, canSeeSaved,
// sameTenant, requireCrossTenant, requirePlatformAdmin) are now thin adapters
// over this layer, so the rule lives in exactly one place.
//
// This is Phase 1 of the enterprise-isolation roadmap; later phases (audit, RLS)
// hang off the same chokepoint. See docs/TRACKER.md and the strict-tenancy model.

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

// Principal is the authenticated actor, resolved once from token claims. cross
// marks the platform owner (a super-admin in the global/platform tenant), who
// sees and governs everything.
type Principal struct {
	Subject string
	Role    string
	Tenant  string
	cross   bool
}

// principalFrom resolves the caller into a Principal using the canonical
// tenant/cross rule (principalTenant), so authz and the rest of the code agree
// on who is the platform owner.
func principalFrom(c jwtClaims) Principal {
	tenant, cross := principalTenant(c)
	return Principal{Subject: c.Sub, Role: c.Role, Tenant: tenant, cross: cross}
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

// Authorize is THE policy. It is pure (no IO) so it is trivially testable and
// reused identically by HTTP handlers, the WebSocket hub, and background jobs.
func Authorize(p Principal, a Action, r Resource) Decision {
	// The platform owner is unrestricted.
	if p.cross {
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
		if a == ActionView && sameTenantStrict(r.Tenant, p.Tenant) {
			return Decision{true, "own tenant"}
		}
		if a == ActionView {
			return Decision{false, "not your tenant"}
		}
		return Decision{false, "platform administrator required"}

	// Everything tenant-scoped (devices, saved objects, users, api keys, snmp
	// credentials, alerts): exact tenant match. Global/untagged is platform-owned.
	default:
		if sameTenantStrict(r.Tenant, p.Tenant) {
			return Decision{true, "same tenant"}
		}
		return Decision{false, "cross-tenant access denied"}
	}
}

// sameTenantStrict compares two tenant ids for an already-scoped principal
// (case/space-insensitive, exact match; global/untagged never matches a scoped
// tenant). The cross-tenant short-circuit lives in Authorize.
func sameTenantStrict(resourceTenant, principalTenant string) bool {
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(principalTenant))
}

// can is the boolean convenience for non-HTTP call sites (hub, jobs).
func (s *server) can(c jwtClaims, a Action, r Resource) bool {
	return Authorize(principalFrom(c), a, r).Allow
}

// authorize is the HTTP convenience: it resolves the caller, evaluates the
// policy, and writes the standard response on denial — 404 (not 403) for a
// cross-tenant resource so existence isn't leaked, 403 for a platform-only
// resource the caller could legitimately know exists. Returns (principal, true)
// only when allowed.
//
//nolint:unused // tenant-aware HTTP gate (404-vs-403 existence hiding); handlers still use requirePerm — migration target
//lint:ignore U1000 migration target — handlers still use requirePerm (see nolint above)
func (s *server) authorize(w http.ResponseWriter, r *http.Request, a Action, res Resource) (Principal, bool) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return Principal{}, false
	}
	p := principalFrom(claims)
	d := Authorize(p, a, res)
	if d.Allow {
		return p, true
	}
	if res.Type == ResInfraStack || res.Type == ResRole || res.Type == ResTenant {
		// Platform-only / role / tenant-registry denials are not about hiding a
		// specific row's existence → 403 with the reason.
		writeError(w, http.StatusForbidden, errors.New(d.Reason))
		return p, false
	}
	// A tenant-scoped resource the caller can't see → 404, no existence leak.
	writeError(w, http.StatusNotFound, errors.New("not found"))
	return p, false
}
