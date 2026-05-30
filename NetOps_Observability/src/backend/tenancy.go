package main

import (
	"strings"

	"netops/backend/models"
)

// tenancy.go — request-scoped tenant isolation.
//
// True multi-tenancy means a tenant-bound principal must never see another
// tenant's resources. We enforce that at the API boundary: every tenant-owned
// resource carries a TenantID, and read/write handlers filter against the
// caller's tenant resolved from their token claims.
//
// A principal is "cross-tenant" (sees everything) when it is a super-admin or
// is unbound / bound to the global tenant — that covers the seeded admin and
// platform operators. Everyone else is strictly scoped. Resources with an empty
// TenantID are treated as global/shared and are visible to all tenants but
// owned by none (so a scoped tenant can never mutate them away from others).
// See docs/IDENTITY_ACCESS.md (multi-tenancy).

// principalTenant resolves the caller's tenant id and whether they may read
// across all tenants.
func principalTenant(c jwtClaims) (tenant string, crossTenant bool) {
	t := strings.ToLower(strings.TrimSpace(c.Tenant))
	if isSuperAdminRole(c.Role) || t == "" || t == TenantGlobal {
		return t, true
	}
	return t, false
}

func deviceTenant(d models.Device) string {
	return strings.ToLower(strings.TrimSpace(d.TenantID))
}

// canSeeDevice reports whether a scoped principal may view a device.
func canSeeDevice(d models.Device, tenant string, cross bool) bool {
	if cross {
		return true
	}
	dt := deviceTenant(d)
	return dt == "" || dt == TenantGlobal || dt == tenant
}

// visibleDevices filters a device list to those the principal may view.
func visibleDevices(all []models.Device, c jwtClaims) []models.Device {
	tenant, cross := principalTenant(c)
	if cross {
		return all
	}
	out := make([]models.Device, 0, len(all))
	for _, d := range all {
		if canSeeDevice(d, tenant, cross) {
			out = append(out, d)
		}
	}
	return out
}

// visibleDeviceIDs returns the set of device ids the principal may view, plus a
// cross-tenant flag (when true the set is empty and means "all"). Used to scope
// resources that reference a device (alerts, flows, …).
func (s *server) visibleDeviceIDs(c jwtClaims) (ids map[string]bool, cross bool) {
	tenant, cross := principalTenant(c)
	if cross {
		return nil, true
	}
	ids = map[string]bool{}
	for _, d := range s.discovery.Devices() {
		if canSeeDevice(d, tenant, cross) {
			ids[d.ID] = true
		}
	}
	return ids, false
}
