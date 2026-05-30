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

// ---- saved objects ---------------------------------------------------------

func savedTenant(o SavedObject) string {
	return strings.ToLower(strings.TrimSpace(o.TenantID))
}

// canSeeSaved reports whether a scoped principal may view a saved object. Like
// devices, an empty/global tenant id is shared and visible to all.
func canSeeSaved(o SavedObject, tenant string, cross bool) bool {
	if cross {
		return true
	}
	st := savedTenant(o)
	return st == "" || st == TenantGlobal || st == tenant
}

// canMutateSaved reports whether a scoped principal may modify/delete a saved
// object. Scoped principals own only their own tenant's objects — never the
// shared/global ones (which belong to no single tenant), mirroring devices.
func canMutateSaved(o SavedObject, tenant string, cross bool) bool {
	if cross {
		return true
	}
	return savedTenant(o) == tenant
}

// visibleSaved filters a saved-object list to those the principal may view.
func visibleSaved(all []SavedObject, c jwtClaims) []SavedObject {
	tenant, cross := principalTenant(c)
	if cross {
		return all
	}
	out := make([]SavedObject, 0, len(all))
	for _, o := range all {
		if canSeeSaved(o, tenant, cross) {
			out = append(out, o)
		}
	}
	return out
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

// visibleDeviceAddrs returns the distinct non-empty management addresses of the
// devices a scoped principal may view, plus a cross-tenant flag (when true the
// slice is nil and means "all"). Used to scope ClickHouse flow rows, which key
// on src_addr/dst_addr rather than a device id.
func (s *server) visibleDeviceAddrs(c jwtClaims) (addrs []string, cross bool) {
	tenant, cross := principalTenant(c)
	if cross {
		return nil, true
	}
	seen := map[string]bool{}
	for _, d := range s.discovery.Devices() {
		if canSeeDevice(d, tenant, cross) && d.Address != "" && !seen[d.Address] {
			seen[d.Address] = true
			addrs = append(addrs, d.Address)
		}
	}
	return addrs, false
}

// visibleDeviceKeys returns the distinct identifiers (id and name) of the devices
// a scoped principal may view, plus a cross-tenant flag (when true the slice is
// nil and means "all"). Used to scope ClickHouse findings, whose `device` column
// may carry either a device id or hostname depending on the producer.
func (s *server) visibleDeviceKeys(c jwtClaims) (keys []string, cross bool) {
	tenant, cross := principalTenant(c)
	if cross {
		return nil, true
	}
	seen := map[string]bool{}
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			keys = append(keys, v)
		}
	}
	for _, d := range s.discovery.Devices() {
		if canSeeDevice(d, tenant, cross) {
			add(d.ID)
			add(d.Name)
		}
	}
	return keys, false
}
