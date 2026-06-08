package main

import (
	"net/http"
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
// Cross-tenant ("sees everything") is reserved for the PLATFORM OWNER only — a
// super-admin in the global/platform tenant. Every other principal, INCLUDING a
// tenant's own super-admin, is strictly confined to its tenant: a tenant is a
// namespace, not a window onto the platform. Resources owned by the global tenant
// (or with an empty TenantID) belong to the platform and are visible only to the
// platform owner — a new tenant therefore starts as an empty namespace and can
// never see another tenant's (or the platform's) data. See docs/IDENTITY_ACCESS.md.

// isPlatformOwner reports whether the principal is the cross-tenant SaaS operator
// — a super-admin whose own token tenant is the global/platform tenant. This is
// the ONLY identity that may read across tenants or scope into a specific one via
// the tenant switcher; it is derived from the token, never from a request header.
func isPlatformOwner(c jwtClaims) bool {
	t := strings.ToLower(strings.TrimSpace(c.Tenant))
	return isSuperAdminRole(c.Role) && (t == "" || t == TenantGlobal)
}

// principalTenant resolves the caller's tenant id and whether they may read
// across all tenants. crossTenant is true ONLY for the platform owner with no
// active "view as tenant" override.
//
// The platform owner may narrow their view with the tenant switcher (carried as a
// validated, server-set actingTenant — see withActingTenant): selecting a specific
// tenant drops them to that tenant's scope (cross=false), and selecting "Global"
// scopes them to the global/infra namespace only. The override can only NARROW —
// it is honored solely for the platform owner, so no other principal can use it to
// widen their reach. Every tenant-scoped read funnels through here, so one override
// scopes the whole app (logs, flows, metrics, findings, devices) at once.
func principalTenant(c jwtClaims) (tenant string, crossTenant bool) {
	if isPlatformOwner(c) {
		// Global view (no override) is CROSS-TENANT: the platform owner sees
		// everything — every tenant PLUS untagged/platform-owned resources (their
		// own devices). Selecting a specific tenant narrows to just that tenant.
		// There is deliberately no "global-tenant-only" scope: "Global" == platform
		// == cross-tenant, which is the user's mental model and shows their devices.
		if act := strings.ToLower(strings.TrimSpace(c.actingTenant)); act != "" {
			return act, false
		}
		return TenantGlobal, true
	}
	return strings.ToLower(strings.TrimSpace(c.Tenant)), false
}

// actingAll is the switcher sentinel for the default Global (cross-tenant) view.
const actingAll = "all"

// withActingTenant applies an optional platform-owner "view as tenant" override
// from the request (X-Acting-Tenant header, or ?as_tenant= query param) onto the
// claims. Zero trust: honored ONLY for the platform owner and ONLY when it names a
// real, NON-global tenant. Everything else — a non-owner caller, an unknown
// tenant, the "all"/"global" sentinels (which mean the default Global view), or no
// header — leaves the claims untouched, so the override can only ever NARROW from
// the cross-tenant Global view, never widen. The result feeds principalTenant.
func (s *server) withActingTenant(r *http.Request, c jwtClaims) jwtClaims {
	v := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Acting-Tenant")))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("as_tenant")))
	}
	// "", "all", "global" => Global (cross-tenant) view, i.e. no narrowing. The
	// global tenant is the platform/cross identity, never a narrowing target.
	if v == "" || v == actingAll || v == TenantGlobal || !isPlatformOwner(c) {
		return c
	}
	if _, ok := s.tenants.Get(v); ok {
		c.actingTenant = v
	}
	return c
}

func deviceTenant(d models.Device) string {
	return strings.ToLower(strings.TrimSpace(d.TenantID))
}

// sameTenant reports whether a resource owned by resourceTenant is visible to a
// principal scoped to `tenant` (cross-tenant principals see everything). Strict:
// only an exact tenant match — global/unassigned resources are platform-owned.
// Thin adapter over the central policy (authz.go).
func sameTenant(resourceTenant, tenant string, cross bool) bool {
	if cross {
		return true
	}
	return sameTenantStrict(resourceTenant, tenant)
}

// canSeeDevice reports whether a scoped principal may view a device. Strict
// isolation: a scoped principal sees ONLY its own tenant's devices; global/
// unassigned devices belong to the platform and are visible only cross-tenant.
// Decision flows through the central Authorize() policy.
func canSeeDevice(d models.Device, tenant string, cross bool) bool {
	return Authorize(
		Principal{Tenant: tenant, cross: cross},
		ActionView,
		Resource{Type: ResDevice, Tenant: deviceTenant(d)},
	).Allow
}

// ---- saved objects ---------------------------------------------------------

func savedTenant(o SavedObject) string {
	return strings.ToLower(strings.TrimSpace(o.TenantID))
}

// canSeeSaved reports whether a scoped principal may view a saved object.
// Strict isolation: only the principal's own tenant (global/unassigned objects
// are platform-owned, visible only cross-tenant). Routed through Authorize().
func canSeeSaved(o SavedObject, tenant string, cross bool) bool {
	return Authorize(
		Principal{Tenant: tenant, cross: cross},
		ActionView,
		Resource{Type: ResSaved, Tenant: savedTenant(o)},
	).Allow
}

// canMutateSaved reports whether a scoped principal may modify/delete a saved
// object. Scoped principals own only their own tenant's objects — never the
// shared/global ones (which belong to no single tenant), mirroring devices.
func canMutateSaved(o SavedObject, tenant string, cross bool) bool {
	return Authorize(
		Principal{Tenant: tenant, cross: cross},
		ActionUpdate,
		Resource{Type: ResSaved, Tenant: savedTenant(o)},
	).Allow
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

// alertVisibleTo reports whether a principal may see an alert: the platform
// owner sees all; a scoped principal sees alerts on its own devices, plus
// device-less (stack-level) alerts. Mirrors the GET /api/alerts filter so the
// WebSocket alert feed enforces the same boundary.
func (s *server) alertVisibleTo(a models.Alert, c jwtClaims) bool {
	ids, cross := s.visibleDeviceIDs(c)
	if cross {
		return true
	}
	return a.DeviceID == "" || ids[a.DeviceID]
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

// visibleDeviceMetricLabels returns the distinct device ids and device names a
// scoped principal may view, plus a cross-tenant flag (when true both slices are
// nil and mean "all"). Used to scope time-series metrics, where the device is
// identified by different labels depending on the producer: the Go collectors tag
// samples with `device`=<device id> (poller.go / snmpmetrics.go), the Telegraf
// SNMP edge poller tags `hostname`=<sysName>, and the gnmic sidecar tags
// `source`=<target name> — the latter two corresponding to the device name.
// Returning the two key classes separately lets the metrics scoper constrain each
// label with the right value set.
func (s *server) visibleDeviceMetricLabels(c jwtClaims) (ids, names []string, cross bool) {
	tenant, cross := principalTenant(c)
	if cross {
		return nil, nil, true
	}
	seenID, seenName := map[string]bool{}, map[string]bool{}
	for _, d := range s.discovery.Devices() {
		if !canSeeDevice(d, tenant, cross) {
			continue
		}
		if d.ID != "" && !seenID[d.ID] {
			seenID[d.ID] = true
			ids = append(ids, d.ID)
		}
		if d.Name != "" && !seenName[d.Name] {
			seenName[d.Name] = true
			names = append(names, d.Name)
		}
	}
	return ids, names, false
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
