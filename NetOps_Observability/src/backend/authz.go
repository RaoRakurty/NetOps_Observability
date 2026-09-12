// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// authz.go — main-side adapters for the central authorization policy
// (rbac.Authorize, extracted P2 RA.1). This file binds the pure decision point
// to the entrypoint: principalFrom resolves the caller through the canonical
// principalTenant rule, and the HTTP adapter encodes the 404-vs-403
// existence-hiding response. The leaf helpers (canSeeDevice, canSeeSaved,
// sameTenant, requireCrossTenant, requirePlatformAdmin) remain thin adapters
// over this layer.

import (
	"errors"
	"net/http"

	"netops/backend/internal/rbac"
)

type (
	Action       = rbac.Action
	ResourceType = rbac.ResourceType
	Principal    = rbac.Principal
	Resource     = rbac.Resource
	Decision     = rbac.Decision
)

const (
	ActionView   = rbac.ActionView
	ActionCreate = rbac.ActionCreate
	ActionUpdate = rbac.ActionUpdate
	ActionDelete = rbac.ActionDelete

	ResDevice     = rbac.ResDevice
	ResSaved      = rbac.ResSaved
	ResUser       = rbac.ResUser
	ResTenant     = rbac.ResTenant
	ResRole       = rbac.ResRole
	ResAPIKey     = rbac.ResAPIKey
	ResSNMPCred   = rbac.ResSNMPCred
	ResAlert      = rbac.ResAlert
	ResInfraStack = rbac.ResInfraStack
)

// Authorize delegates to the package policy (kept as a main-level name for the
// existing call sites).
func Authorize(p Principal, a Action, r Resource) Decision { return rbac.Authorize(p, a, r) }

// sameTenantStrict keeps main's historical name for the strict comparison.
func sameTenantStrict(resourceTenant, principalTenant string) bool {
	return rbac.SameTenantStrict(resourceTenant, principalTenant)
}

// principalFrom resolves the caller into a Principal using the canonical
// tenant/cross rule (principalTenant), so authz and the rest of the code agree
// on who is the platform owner.
func principalFrom(c jwtClaims) Principal {
	tenant, cross := principalTenant(c)
	return Principal{Subject: c.Sub, Role: c.Role, Tenant: tenant, Cross: cross}
}

// can is the boolean convenience for non-HTTP call sites (hub, jobs).
func (s *server) can(c jwtClaims, a Action, r Resource) bool {
	return rbac.Authorize(principalFrom(c), a, r).Allow
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
	d := rbac.Authorize(p, a, res)
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
