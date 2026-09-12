// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"net/http"
	"netops/backend/internal/saved"
	"sort"
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
	return ok && t.EffectiveStatus() == TenantStatusSuspended
}

// principalTenant resolves the caller's tenant id and whether they may read
// across all tenants. crossTenant is true ONLY for the platform owner with no
// active "view as tenant" override.
//
// The platform owner may narrow their view with the tenant switcher (carried as a
// validated, server-set ActingTenant — see withActingTenant): selecting a specific
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
		if act := strings.ToLower(strings.TrimSpace(c.ActingTenant)); act != "" {
			return act, false
		}
		return TenantGlobal, true
	}
	// A non-owner is confined to its token tenant. Defense-in-depth: ActingTenant is
	// NEVER trusted here for a non-owner — a multi-tenant switch is applied by
	// withActingTenant rewriting the effective Tenant (after a reachesTenant check),
	// so this function ignoring ActingTenant for non-owners stays a hard invariant.
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
		c.ActingTenant = t.ID
		return c
	}
	// Non-owner: honor the selection only if the principal is actually bound to a
	// scope that reaches this tenant. We rewrite the EFFECTIVE tenant (not
	// ActingTenant) so principalTenant — which ignores ActingTenant for non-owners
	// as a hard invariant — resolves to the target. The reach check is against the
	// opaque tenant id, never the slug. A single-tenant user only reaches its own
	// tenant, so this is a no-op for them.
	if s.reachesTenant(c.Sub, t.ID) {
		c.Tenant = t.ID
	}
	return c
}

// orgOf returns the org a tenant belongs to, treating blank as the Global org
// (tenants predating the org layer) — main's side of the tenant/org boundary.
func orgOf(t Tenant) string {
	if t.OrgID == "" {
		return OrgGlobal
	}
	return t.OrgID
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

// broadcastRestrictionSalt renders the operator-visibility restriction as it
// applies to THIS principal right now, for use as the extra component of the
// WebSocket broadcast cache key (Hub.scopeSalt).
//
// Why a key component at all: the restriction is resolved per SUBJECT, because
// break-glass is a per-operator, time-boxed session. Two platform owners collapse
// to the same tenant scope but are NOT entitled to the same frames — one may hold
// a live session into a restricted tenant and the other may not.
//
// It returns the resolved HIDDEN SET rather than the subject, on purpose. Keying
// on the subject would give every operator its own cache entry and throw away the
// build-once-per-scope property the hub depends on; keying on the set is exact —
// same hidden set means the builders produce the same frames. Sorted so the key
// is stable across calls. Empty for anyone the restriction cannot apply to, which
// is every tenant principal, so ordinary tenant scopes keep sharing one entry.
func (s *server) broadcastRestrictionSalt(c jwtClaims) string {
	if !isPlatformOwner(c) || s.tenants == nil {
		return ""
	}
	hidden := s.effectiveRestrictedIDs(c.Sub)
	if len(hidden) == 0 {
		return ""
	}
	sorted := make([]string, len(hidden))
	copy(sorted, hidden)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// tenantIDExcludeCondFor is the tenant_id-KEYED sibling of addrTenantClauseFor,
// for the ClickHouse tables that carry a tenant_id column — the correlation
// family (corr_current, corr_objects, corr_signals, corr_edges) above all.
//
// It answers the ONE half s.chTenantScopeFor cannot. The scope closes the
// as_tenant door: an operator who scoped INTO a restricted tenant gets the
// read-nothing scope, and the row policies enforce that server-side. But the
// Global door is '__all__', which means all, and the row-policy grammar has no
// "all except" — so the exclusion for an operator reading ACROSS tenants has to
// ride in the SQL. Unified search reached the same conclusion for the same
// reason (search_unified.go).
//
// Returns "" when there is nothing to exclude: a non-operator, no restricted
// tenant, or a caller the read-nothing scope already answered. Callers AND the
// fragment into their WHERE — it narrows, while the scope and the policies
// isolate.
func (s *server) tenantIDExcludeCondFor(claims jwtClaims, col string) string {
	tenant, cross := principalTenant(claims)
	exclude, deny := s.operatorTelemetryRestriction(claims, tenant, cross)
	if deny || len(exclude) == 0 {
		return ""
	}
	return col + " NOT IN (" + sqlInList(exclude) + ")"
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
		Principal{Tenant: tenant, Cross: cross},
		ActionView,
		Resource{Type: ResDevice, Tenant: deviceTenant(d)},
	).Allow
}

// ---- saved objects ---------------------------------------------------------

func savedTenant(o saved.Object) string {
	return strings.ToLower(strings.TrimSpace(o.TenantID))
}

// canSeeSaved reports whether a scoped principal may view a saved object.
// Strict isolation: only the principal's own tenant (global/unassigned objects
// are platform-owned, visible only cross-tenant). Routed through Authorize().
func canSeeSaved(o saved.Object, tenant string, cross bool) bool {
	return Authorize(
		Principal{Tenant: tenant, Cross: cross},
		ActionView,
		Resource{Type: ResSaved, Tenant: savedTenant(o)},
	).Allow
}

// canMutateSaved reports whether a scoped principal may modify/delete a saved
// object. Scoped principals own only their own tenant's objects — never the
// shared/global ones (which belong to no single tenant), mirroring devices.
func canMutateSaved(o saved.Object, tenant string, cross bool) bool {
	return Authorize(
		Principal{Tenant: tenant, Cross: cross},
		ActionUpdate,
		Resource{Type: ResSaved, Tenant: savedTenant(o)},
	).Allow
}

// visibleSaved filters a saved-object list to those the principal may view.
func visibleSaved(all []saved.Object, c jwtClaims) []saved.Object {
	tenant, cross := principalTenant(c)
	if cross {
		return all
	}
	out := make([]saved.Object, 0, len(all))
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

// deviceVisibility is the device-REGISTRY visibility decision RESOLVED for one
// principal: the ordinary tenant scope, plus the operator-visibility restriction
// (Tenant.OperatorRestricted) in its tenant_id form.
//
// It is the inventory sibling of alertVisibility, and it exists for the same
// reason. The restriction is resolved per SUBJECT (break-glass is a per-operator,
// time-boxed session), so resolving it once per device would rescan the tenant
// store for every row. Resolving it once per principal also means a surface that
// shows a LIST and a tile that shows its COUNT ask the same object, so they can
// never disagree about what the caller may see.
//
// WHAT THE RESTRICTION MEANS HERE IS AN OWNER DECISION. The restriction started
// as a telemetry rule and the device registry was deliberately left outside it.
// The owner has since ruled that devices and sites are counted per tenant, so a
// restricted tenant's inventory does not appear in the platform operator's view
// either.
type deviceVisibility struct {
	// tenantVisibility carries the scope and the restriction. deviceVisibility
	// adds only what it means for a models.Device row.
	tenantVisibility
}

// tenantVisibility is the (tenant, cross) scope PLUS the operator-visibility
// restriction in its tenant_id form, resolved ONCE for one principal. It is the
// single implementation of the restriction for every store whose rows name their
// owning tenant in a field: the device registry, the declared-sites store, and
// the counts derived from either.
//
// It exists because this rule has already been leaked once by hand-transcription.
// A reader that must not show a restricted tenant's rows asks for one of these
// and consults it; it does not re-type "resolve the restriction, lower-case the
// ids, compare" into its own body, because a rule at a call site is a snapshot
// and a rule at a chokepoint is an invariant.
type tenantVisibility struct {
	tenant string
	cross  bool

	// deny is the operator scoped INTO a restricted tenant: it sees no row owned
	// by that tenant at all.
	deny bool
	// hiddenTenants are the restricted tenants' ids, lower-cased, for the
	// operator's Global view. A device and a site both carry their owner in
	// TenantID, so the tenant_id form of the restriction is the exact one.
	hiddenTenants map[string]bool
}

// tenantVisibilityFor resolves the rule ONCE for a principal. The restriction
// comes from the shared resolver (operatorTelemetryRestriction) rather than a
// second copy of it, so it is a no-op for non-operators, for a tenant reading its
// own estate, and when no tenant is restricted.
func (s *server) tenantVisibilityFor(c jwtClaims) tenantVisibility {
	tenant, cross := principalTenant(c)
	v := tenantVisibility{tenant: tenant, cross: cross}
	exclude, deny := s.operatorTelemetryRestriction(c, tenant, cross)
	v.deny = deny
	if len(exclude) > 0 {
		v.hiddenTenants = make(map[string]bool, len(exclude))
		for _, id := range exclude {
			v.hiddenTenants[strings.ToLower(strings.TrimSpace(id))] = true
		}
	}
	return v
}

// hides reports whether a row owned by tenantID is hidden from this principal by
// the RESTRICTION alone (the ordinary tenant scope is a separate question, asked
// by the per-resource rule). Case- and blank-tolerant: the owner id on a row and
// the id in the tenant store are minted by different writers, and a blank owner
// is platform-owned, which the restriction never hides.
func (v tenantVisibility) hides(tenantID string) bool {
	if v.deny {
		return true
	}
	if len(v.hiddenTenants) == 0 {
		return false
	}
	return v.hiddenTenants[strings.ToLower(strings.TrimSpace(tenantID))]
}

// unrestricted reports whether this principal sees the whole store unchanged —
// a cross-tenant caller with nothing to hide. Lets a filter skip a copy.
func (v tenantVisibility) unrestricted() bool {
	return v.cross && !v.deny && len(v.hiddenTenants) == 0
}

// deviceVisibilityFor resolves the device rule ONCE for a principal.
func (s *server) deviceVisibilityFor(c jwtClaims) deviceVisibility {
	return deviceVisibility{tenantVisibility: s.tenantVisibilityFor(c)}
}

// visible reports whether this principal may see one device. The restriction is
// applied BEFORE the ordinary tenant rule, so a hidden device stays hidden on the
// cross-tenant path, where canSeeDevice allows everything.
func (v deviceVisibility) visible(d models.Device) bool {
	if v.hides(deviceTenant(d)) {
		return false
	}
	return canSeeDevice(d, v.tenant, v.cross)
}

// filter applies the resolved rule to a device list, preserving order.
func (v deviceVisibility) filter(all []models.Device) []models.Device {
	if v.unrestricted() {
		return all
	}
	out := make([]models.Device, 0, len(all))
	for _, d := range all {
		if v.visible(d) {
			out = append(out, d)
		}
	}
	return out
}

// platformInfraDeviceVisibility is the UNRESTRICTED platform scope, for the
// background workers that act on behalf of EVERY tenant rather than reading on
// behalf of a principal — today the wan-echo target publisher, which hands the
// prober the addresses it must measure so that each tenant (restricted or not)
// keeps receiving its own path measurements.
//
// It is deliberately NOT derivable from claims: a synthetic platform-owner token
// would pick up the operator-visibility restriction and silently stop measuring
// a restricted tenant, taking that tenant's own data away from itself. The
// restriction is a rule about what the OPERATOR may READ, never an accounting or
// collection rule — a restricted tenant is still discovered, still measured and
// still billed. Anything that answers a REQUEST must use deviceVisibilityFor.
func platformInfraDeviceVisibility() deviceVisibility {
	return deviceVisibility{tenantVisibility: tenantVisibility{tenant: TenantGlobal, cross: true}}
}

// visibleDevicesFor is visibleDevices plus the operator-visibility restriction,
// read straight from the registry. Callers that must not show a restricted
// tenant's inventory ask this instead of visibleDevices.
func (s *server) visibleDevicesFor(c jwtClaims) []models.Device {
	if s.discovery == nil {
		return nil
	}
	return s.deviceVisibilityFor(c).filter(s.discovery.Devices())
}

// visibleSitesFor reads the DECLARED-SITES store (the internal Source of Truth)
// through the same resolved rule the device registry is read through, so the list
// of sites and the count of sites can never disagree about what the caller may
// see.
//
// The store itself already applies the ordinary tenant scope (tenantKV.All), so
// what this adds is exactly the operator-visibility restriction: an operator
// scoped INTO a restricted tenant gets nothing, and the Global view drops the
// restricted tenants' sites. A site name is where a customer operates — the same
// class of disclosure as its fleet size, and the Sites tile already counts this
// way (dashboard.go).
func (s *server) visibleSitesFor(c jwtClaims) []Site {
	if s.sites == nil {
		return nil
	}
	v := s.tenantVisibilityFor(c)
	if v.deny {
		return nil
	}
	all := s.sites.All(v.tenant, v.cross)
	if len(v.hiddenTenants) == 0 {
		return all
	}
	out := make([]Site, 0, len(all))
	for _, st := range all {
		if v.hides(st.TenantID) {
			continue
		}
		out = append(out, st)
	}
	return out
}

// visibleSiteFor resolves ONE declared site by slug through the same rule
// visibleSitesFor applies to the list, so a slug the list omits cannot be read
// back by naming it. Not-visible is reported as not-found, and the HTTP callers
// map that to 404 — never 403, which would confirm the site exists.
//
// The fallback scan is not belt-and-braces: tenant.Collection.Get walks the map
// in arbitrary order for a cross-tenant caller, so when two tenants declare the
// same slug it can return the HIDDEN one and shadow a site the caller may see.
func (s *server) visibleSiteFor(c jwtClaims, slug string) (Site, bool) {
	if s.sites == nil {
		return Site{}, false
	}
	v := s.tenantVisibilityFor(c)
	if v.deny {
		return Site{}, false
	}
	st, ok := s.sites.Get(v.tenant, v.cross, slug)
	if ok && !v.hides(st.TenantID) {
		return st, true
	}
	if !ok || len(v.hiddenTenants) == 0 {
		return Site{}, false
	}
	for _, cand := range s.visibleSitesFor(c) {
		if cand.Slug == slug {
			return cand, true
		}
	}
	return Site{}, false
}

// alertVisible is THE alert visibility rule. Every surface that shows alerts
// asks this one function, so a fix here cannot be applied to some paths and
// missed on others.
//
// The platform owner sees all. A scoped principal sees alerts on its own
// devices. A DEVICE-LESS alert is platform-global ONLY when nothing owns it:
// the Digital Experience rules aggregate by target rather than device and carry
// no `device` label, but they DO have an owner, and their summary carries that
// tenant's target hostname, site and app. Treating "no device" as "everybody's"
// handed one tenant's target names to every other tenant.
func alertVisible(a models.Alert, tenant string, cross bool, ids map[string]bool) bool {
	if cross {
		return true
	}
	if a.DeviceID != "" {
		return ids[a.DeviceID]
	}
	owner := alertOwnerLabel(a)
	if owner == "" {
		return true // genuinely platform-owned: a stack-level alert
	}
	return sameTenantStrict(owner, tenant)
}

// alertVisibility is the alert-visibility decision RESOLVED for one principal:
// the tenant/cross pair, the device set, and the operator-visibility restriction
// (Tenant.OperatorRestricted). It exists because both halves of the alert lane —
// GET /api/alerts and the WebSocket feed — have to apply the same rule to a whole
// alert set, and resolving the restriction per alert would rescan the fleet for
// every row.
//
// An alert is the customer's live incident: the rule that fired, the device it
// fired on and a summary that names that device. A tenant that has switched the
// restriction on is hidden from the platform owner in flows, findings, logs,
// metrics, tunnels and the BMP feed, and must be hidden here too.
type alertVisibility struct {
	tenant string
	cross  bool
	ids    map[string]bool

	// deny is the operator scoped INTO a restricted tenant: it sees no alert of
	// that tenant at all.
	deny bool
	// hiddenDevices are the device identifiers of restricted tenants, for the
	// operator's Global view. Device-keyed, because that is how an alert names
	// what it fired on.
	hiddenDevices map[string]bool
	// hiddenTenants is the same restriction in its tenant_id form, for the
	// DEVICE-LESS alerts that carry an owner label instead (alertOwnerLabel).
	hiddenTenants []string
}

// alertVisibilityFor resolves the rule ONCE for a principal. Both restriction
// forms come from the shared resolvers (restrictedTelemetry /
// operatorTelemetryRestriction) rather than a second copy of the rule.
func (s *server) alertVisibilityFor(c jwtClaims) alertVisibility {
	ids, cross := s.visibleDeviceIDs(c)
	tenant, _ := principalTenant(c)
	v := alertVisibility{tenant: tenant, cross: cross, ids: ids}

	rt := s.restrictedTelemetry(c)
	v.deny = rt.deny
	if len(rt.keys) > 0 {
		v.hiddenDevices = make(map[string]bool, len(rt.keys))
		for _, k := range rt.keys {
			v.hiddenDevices[k] = true
		}
	}
	v.hiddenTenants, _ = s.operatorTelemetryRestriction(c, tenant, cross)
	return v
}

// visible reports whether this principal may see one alert. The restriction is
// applied BEFORE the ordinary tenant rule, so a hidden alert stays hidden even on
// the cross-tenant path where alertVisible answers true for everything.
func (v alertVisibility) visible(a models.Alert) bool {
	if v.deny {
		return false
	}
	if a.DeviceID != "" && v.hiddenDevices[a.DeviceID] {
		return false
	}
	if owner := alertOwnerLabel(a); owner != "" {
		for _, x := range v.hiddenTenants {
			if strings.EqualFold(strings.TrimSpace(x), owner) {
				return false
			}
		}
	}
	return alertVisible(a, v.tenant, v.cross, v.ids)
}

// alertVisibleTo applies the resolved rule to a principal's claims. Used by the
// WebSocket alert feed and the dashboard, which have claims rather than a
// pre-resolved device set.
func (s *server) alertVisibleTo(a models.Alert, c jwtClaims) bool {
	return s.alertVisibilityFor(c).visible(a)
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
