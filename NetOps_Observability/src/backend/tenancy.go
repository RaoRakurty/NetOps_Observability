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

// tenantSuspended reports whether the principal's tenant is suspended (deny-by-
// default lifecycle). The platform owner / global realm is never suspended, so the
// operator can always reach a suspended tenant to reactivate it. A principal whose
// tenant no longer resolves is NOT treated as suspended here (other gates handle
// missing tenants); this answers only "is this caller's live tenant suspended?".
func (s *server) tenantSuspended(c jwtClaims) bool {
	if s.tenants == nil || isPlatformOwner(c) {
		return false
	}
	tenant := strings.ToLower(strings.TrimSpace(c.Tenant))
	if tenant == "" || tenant == TenantGlobal {
		return false
	}
	t, ok := s.tenants.Get(tenant)
	return ok && t.status() == TenantStatusSuspended
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
	// A non-owner is confined to its token tenant. Defense-in-depth: actingTenant is
	// NEVER trusted here for a non-owner — a multi-tenant switch is applied by
	// withActingTenant rewriting the effective Tenant (after a reachesTenant check),
	// so this function ignoring actingTenant for non-owners stays a hard invariant.
	return strings.ToLower(strings.TrimSpace(c.Tenant)), false
}

// principalOrg resolves the Organization a caller belongs to, by following its
// tenant → org. The platform owner (cross-tenant) maps to the Global org. Used to
// scope org-level views/governance to the caller's own organization.
func (s *server) principalOrg(c jwtClaims) string {
	if isPlatformOwner(c) {
		return OrgGlobal
	}
	tenant, _ := principalTenant(c)
	if s.tenants == nil {
		return OrgGlobal
	}
	if t, ok := s.tenants.Get(tenant); ok {
		return orgOf(t)
	}
	return OrgGlobal
}

// actingAll is the switcher sentinel for the default Global (cross-tenant) view.
const actingAll = "all"

// withActingTenant applies an optional "view as tenant" override from the request
// (X-Acting-Tenant header, or ?as_tenant= query param) onto the claims. Zero
// trust: the override can only ever NARROW, never widen —
//   - the platform owner may select any real, non-global tenant (its default view
//     is cross-tenant Global; selecting narrows to that tenant);
//   - PBAC Phase B: a NON-owner principal may select any tenant it REACHES via its
//     bindings (reachesTenant) — the multi-tenant/MSP/SRE switcher. A single-tenant
//     user only reaches its own tenant, so this is behaviour-preserving for them.
//
// "", "all", "global" mean the default view (no narrowing). An unknown/unreachable
// target is ignored. The result feeds principalTenant.
func (s *server) withActingTenant(r *http.Request, c jwtClaims) jwtClaims {
	v := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Acting-Tenant")))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("as_tenant")))
	}
	if v == "" || v == actingAll || v == TenantGlobal {
		return c
	}
	// `v` is UNTRUSTED (id or slug from a header/query). Resolve it to the
	// canonical opaque tenant id; the override is keyed on the id, never the slug.
	t, ok := s.tenants.Resolve(v)
	if !ok {
		return c // fail closed: an unresolvable reference is ignored
	}
	if isPlatformOwner(c) {
		c.actingTenant = t.ID
		return c
	}
	// Non-owner: honor the selection only if the principal is actually bound to a
	// scope that reaches this tenant. We rewrite the EFFECTIVE tenant (not
	// actingTenant) so principalTenant — which ignores actingTenant for non-owners
	// as a hard invariant — resolves to the target. The reach check is against the
	// opaque tenant id, never the slug. A single-tenant user only reaches its own
	// tenant, so this is a no-op for them.
	if s.reachesTenant(c.Sub, t.ID) {
		c.Tenant = t.ID
	}
	return c
}

func deviceTenant(d models.Device) string {
	return strings.ToLower(strings.TrimSpace(d.TenantID))
}

// telemetryRestriction is the device-keyed form of the operator-visibility
// compliance rule, for stores keyed by device (ClickHouse flows by src/dst addr,
// findings by device id/name, VictoriaMetrics by device label) rather than by a
// tenant_id column. deny means the operator scoped INTO a restricted tenant (serve
// nothing); the slices are the identifiers of restricted tenants' devices to
// EXCLUDE from the operator's cross-tenant (Global) view.
type telemetryRestriction struct {
	deny  bool
	keys  []string // device id + name  (findings `device`, log host/hostname)
	addrs []string // device address    (flow src_addr/dst_addr)
	ids   []string // device id         (metric `device` label)
	names []string // device name       (metric hostname/source labels)
}

// restrictedTelemetry resolves the device-keyed operator-visibility restriction
// for the caller. It is a no-op (zero value) for non-operators, when no tenant is
// restricted, or for an operator in a non-restricted scope — so normal use and
// tenants' own access are unaffected. Mirrors operatorTelemetryRestriction (which
// is the tenant_id form used for the OpenSearch logs path).
func (s *server) restrictedTelemetry(c jwtClaims) telemetryRestriction {
	tenant, cross := principalTenant(c)
	if !isPlatformOwner(c) || s.tenants == nil {
		return telemetryRestriction{}
	}
	// Break-glass (Phase C): a live session un-hides that tenant for its window.
	restricted := s.effectiveRestrictedIDs(c.Sub)
	if len(restricted) == 0 {
		return telemetryRestriction{}
	}
	if !cross { // operator scoped into a tenant → deny iff it's restricted
		for _, id := range restricted {
			if strings.EqualFold(id, tenant) {
				return telemetryRestriction{deny: true}
			}
		}
		return telemetryRestriction{}
	}
	rset := make(map[string]bool, len(restricted))
	for _, id := range restricted {
		rset[id] = true
	}
	var out telemetryRestriction
	seenKey, seenAddr := map[string]bool{}, map[string]bool{}
	for _, d := range s.discovery.Devices() {
		if !rset[deviceTenant(d)] {
			continue
		}
		for _, k := range []string{d.ID, d.Name} {
			if k != "" && !seenKey[k] {
				seenKey[k] = true
				out.keys = append(out.keys, k)
			}
		}
		if d.Address != "" && !seenAddr[d.Address] {
			seenAddr[d.Address] = true
			out.addrs = append(out.addrs, d.Address)
		}
		if d.ID != "" {
			out.ids = append(out.ids, d.ID)
		}
		if d.Name != "" {
			out.names = append(out.names, d.Name)
		}
	}
	return out
}

// operatorTelemetryRestriction enforces the per-tenant operator-visibility
// compliance switch (Tenant.OperatorRestricted) for telemetry reads. Given the
// principal's effective tenant/cross scope it returns:
//   - exclude: tenant ids whose telemetry must be filtered OUT of a cross-tenant
//     (Global) view, or
//   - deny: true when the operator has scoped INTO a restricted tenant (no access).
//
// Only the platform operator is ever restricted — a tenant's OWN users always see
// their own data, so this is a no-op for them. It is also a no-op when no tenant
// is marked restricted (the default), so normal deployments are unaffected.
func (s *server) operatorTelemetryRestriction(c jwtClaims, tenant string, cross bool) (exclude []string, deny bool) {
	if !isPlatformOwner(c) || s.tenants == nil {
		return nil, false
	}
	// Break-glass (Phase C): exclude restricted tenants the operator does NOT
	// currently hold a live session into; a session un-hides its tenant.
	restricted := s.effectiveRestrictedIDs(c.Sub)
	if len(restricted) == 0 {
		return nil, false
	}
	if cross {
		return restricted, false // Global view → hide restricted tenants' telemetry
	}
	for _, id := range restricted { // scoped into a tenant → deny if it's restricted
		if strings.EqualFold(id, tenant) {
			return nil, true
		}
	}
	return nil, false
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
