// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_sites.go — operator device→site BINDINGS: the first-class, editable
// "this device belongs to site X" intent the wire can't give (Phase 3 remainder
// of the SoT provider model; see docs/design/sot-provider-model.md).
//
// This is the INTENT counterpart to the free-form location annotation
// (device_locations.go): a binding references a DECLARED internal site by slug,
// so coordinates resolve LIVE from the site definition (move the site, every
// bound device follows) instead of snapshotting lat/lng per device. It feeds the
// internal SoTProvider's DeviceSites map and the geomap `assign` precedence, so a
// bound device folds into its site's bubble exactly like a NetBox-assigned one.
//
// Tenancy is default-closed by construction: the binding store is built on the
// tenantKV primitive (CLAUDE.md §3a), so there is no unscoped "list all" and a
// non-cross caller only ever sees its own tenant's bindings. The owning tenant is
// stamped from the DEVICE's tenant (server-side trusted state), never the request
// body. The HTTP handler additionally gates on device visibility (canSeeDevice →
// 404) and on the target site being visible to the caller.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/changeledger"
	"netops/backend/internal/discovery"
	"netops/backend/internal/siteres"
	"netops/backend/models"
	"strings"
	"time"
)

// DeviceSiteBinding is one operator-declared device→site assignment. It is OWNED
// by the device's tenant: TenantID scopes visibility/edit exactly like the device
// itself. DeviceID (the stable device id used everywhere) is the within-tenant id;
// Tokens are the device's identity tokens at save time, which the geomap join keys
// on (deviceIdentities) so the binding survives rediscovery.
type DeviceSiteBinding struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	DeviceID  string    `json:"device_id"`
	Tokens    []string  `json:"tokens,omitempty"`
	Device    string    `json:"device,omitempty"` // display name (convenience, not identity)
	Site      string    `json:"site"`             // declared internal site slug — the binding
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// deviceSiteStore persists operator device→site bindings, tenant-scoped by the
// shared tenantKV primitive (no isolation logic re-implemented here).
type deviceSiteStore struct {
	kv *tenantKV[DeviceSiteBinding]
}

func newDeviceSiteStore(path string) (*deviceSiteStore, error) {
	if path == "" {
		path = "/data/device_sites.json"
	}
	kv, err := newTenantKV[DeviceSiteBinding](path,
		func(b DeviceSiteBinding) string { return b.TenantID },
		func(b DeviceSiteBinding) string { return b.DeviceID })
	if err != nil {
		return nil, err
	}
	return &deviceSiteStore{kv: kv}, nil
}

// Assignments returns the identity-token → site-slug map VISIBLE to the
// (tenant, cross) principal — the shape the geomap join consumes. Each binding
// contributes one entry per identity token so any of a device's tokens resolves
// its site. A non-cross caller only ever sees its own tenant's bindings.
// A server built WITHOUT the store answers the same way a deployment that has
// placed no device does: nothing is bound. main.go builds it or aborts the boot,
// so a nil store is a partially-built server and nothing else — but a missing
// guard is not an error path (§10), and without it the nil dereference came out
// of /api/wan/interfaces as a recovered panic and a 500, which is a failure
// reported in the wrong way. Same reasoning, same route and the same fix as
// wanPolicyStore.Get one file over (tracker 285).
func (s *deviceSiteStore) Assignments(tenant string, cross bool) map[string]string {
	if s == nil || s.kv == nil {
		return nil
	}
	rows := s.kv.All(tenant, cross)
	if len(rows) == 0 {
		return nil
	}
	out := make(map[string]string, len(rows))
	for _, b := range rows {
		if b.Site == "" {
			continue
		}
		for _, tok := range b.Tokens {
			out[tok] = b.Site
		}
	}
	return out
}

// Get returns the binding for a device id if visible to the caller.
func (s *deviceSiteStore) Get(tenant string, cross bool, deviceID string) (DeviceSiteBinding, bool) {
	if s == nil || s.kv == nil {
		return DeviceSiteBinding{}, false // no store: no device is placed, which is the honest answer
	}
	return s.kv.Get(tenant, cross, deviceID)
}

// Set stores a binding. The caller MUST have stamped b.TenantID from the device's
// tenant (server-side), validated the site, and populated Tokens — see
// handleDeviceSite.
func (s *deviceSiteStore) Set(b DeviceSiteBinding) error {
	if s == nil || s.kv == nil {
		// The read side can fall back to "unplaced"; a write that cannot be
		// written down has no such fallback and must SAY so rather than panic.
		return errors.New("device site store is not configured")
	}
	b.UpdatedAt = time.Now().UTC()
	return s.kv.Upsert(b)
}

// Delete clears a device's binding within the caller's scope. Returns false when
// the device id isn't visible to the caller (or has no binding).
func (s *deviceSiteStore) Delete(tenant string, cross bool, deviceID string) bool {
	if s == nil || s.kv == nil {
		return false // nothing is bound, so nothing was deleted
	}
	return s.kv.Delete(tenant, cross, deviceID)
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

// handleDeviceSite serves /api/devices/{id}/site (GET/PUT/DELETE) — the operator
// device→site binding. Authz mirrors the device routes: the caller must be able to
// SEE the device (404 otherwise — never reveal another tenant's id), and writes
// require infrastructure:write. The binding is OWNED by the device's tenant
// (stamped server-side, never from the body); a PUT must name a site that is
// itself visible to the caller (cross-tenant placement is refused). The audit
// middleware records every mutation.
func (s *server) handleDeviceSite(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/site")
	level := LevelRead
	if r.Method != http.MethodGet {
		level = LevelWrite
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	d, found := s.discovery.Get(id)
	if !found || !canSeeDevice(d, tenant, cross) {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		resp := map[string]any{"site": ""}
		if b, ok := s.deviceSites.Get(tenant, cross, d.ID); ok {
			resp["site"] = b.Site
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		var req struct {
			Site string `json:"site"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
			return
		}
		slug := siteSlug(req.Site)
		if slug == "" {
			// Empty site clears the binding (idempotent — DELETE-equivalent).
			s.deviceSites.Delete(tenant, cross, d.ID)
			changeledger.SetTarget(r.Context(), "device", d.ID) // the change ledger's target (N-D2)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "site": ""})
			return
		}
		// The target site must be a declared site VISIBLE to the caller — refuse a
		// binding to a site the caller can't see (cross-tenant or non-existent).
		if _, vis := s.sites.Get(tenant, cross, slug); !vis {
			writeError(w, http.StatusBadRequest, errors.New("no such site in this tenant"))
			return
		}
		tokens := discovery.DeviceIdentities(d)
		if len(tokens) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("device has no stable identity token"))
			return
		}
		err := s.deviceSites.Set(DeviceSiteBinding{
			TenantID:  deviceTenant(d), // owning tenant from the device, NOT the body
			DeviceID:  d.ID,
			Tokens:    tokens,
			Device:    d.Name,
			Site:      slug,
			UpdatedBy: claims.Sub,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		changeledger.SetTarget(r.Context(), "device", d.ID) // the change ledger's target (N-D2)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "site": slug})
	case http.MethodDelete:
		if !s.deviceSites.Delete(tenant, cross, d.ID) {
			http.NotFound(w, r)
			return
		}
		changeledger.SetTarget(r.Context(), "device", d.ID) // the change ledger's target (N-D2)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// ── discovered sites: preview + adopt ───────────────────────────────────────
//
// A DISCOVERED site (internal/siteres) is a virtual grouping by the site id a
// device or its controller reports. Adopting one turns it into a real internal
// SoT site (stamped with the caller's tenant) and binds its devices to it — so
// the operator can then rename it, give it coordinates and a role. Rules:
//
//   - preview and apply build the SAME plan (siteres.PlanAdoption) from the same
//     inputs; apply then performs it, re-checking each write;
//   - a device that already has a site of record (an operator binding or a
//     discovery site label) is never touched;
//   - idempotent: once adopted the devices are bound, resolve as manual, and a
//     second run plans nothing;
//   - one tenant at a time: the cross-tenant "All tenants" view must pick a
//     tenant first, so a site is never created in one tenant for another
//     tenant's devices;
//   - audited by the audit middleware (POST) plus one structured log line.

// errAdoptNeedsTenant: the cross-tenant view cannot adopt (see above).
var errAdoptNeedsTenant = errors.New("choose a tenant before adopting discovered sites")

// maxAdoptKeys bounds the optional key filter of an adopt request (§9).
const maxAdoptKeys = 1000

// adoptionPlan builds the caller's adoption plan over its VISIBLE devices in
// its own tenant, using the same site rule as the Topology canvas.
func (s *server) adoptionPlan(claims jwtClaims) (siteres.Plan, string, error) {
	tenant, cross := principalTenant(claims)
	if cross {
		return siteres.Plan{}, tenant, errAdoptNeedsTenant
	}
	devs := s.visibleDevicesFor(claims)
	sc := s.siteContextFor(claims, s.sdwanOverlay.Load())
	resolved := sc.resolveAll(devs)
	in := make([]siteres.Device, 0, len(devs))
	for _, d := range devs {
		if !canSeeDevice(d, tenant, false) {
			continue // defence in depth: never plan another tenant's device
		}
		in = append(in, siteres.Device{ID: d.ID, Name: d.Name, Tenant: deviceTenant(d), Site: resolved[d.ID]})
	}
	vis := s.tenantVisibilityFor(claims)
	exists := func(slug string) bool {
		_, readable := s.resolveSiteForScope(vis, slug)
		return readable != siteAbsent
	}
	return siteres.PlanAdoption(in, siteSlug, exists), tenant, nil
}

// applyAdoption performs a plan for the caller. Every write is re-checked: a
// slug that turned out to be taken by a site the caller may not read is
// refused, and a device that gained a binding since the plan is skipped.
func (s *server) applyAdoption(claims jwtClaims, tenant string, plan siteres.Plan) siteres.Plan {
	byID := map[string]models.Device{}
	for _, d := range s.visibleDevicesFor(claims) {
		byID[d.ID] = d
	}
	vis := s.tenantVisibilityFor(claims)
	// abandon marks a site that could not be created and every device it would
	// have bound, so the summary never claims a bind that did not happen.
	abandon := func(st *siteres.AdoptSite, action, detail string) {
		plan.Summary[st.Action]--
		st.Action = action
		plan.Summary[action]++
		for j := range st.Devices {
			if st.Devices[j].Action == siteres.ActionBind {
				st.Devices[j].Action, st.Devices[j].Detail = siteres.ActionSkip, detail
				plan.Summary[siteres.ActionBind]--
				plan.Summary[siteres.ActionSkip]++
			}
		}
	}
	for i := range plan.Sites {
		st := &plan.Sites[i]
		_, readable := s.resolveSiteForScope(vis, st.Slug)
		switch readable {
		case siteHidden:
			abandon(st, siteres.ActionRefused, "not bound: "+refusedSiteDetail)
			continue
		case siteAbsent:
			if _, err := s.sites.Upsert(Site{TenantID: tenant, Slug: st.Slug, Name: st.Name, UpdatedBy: claims.Sub}); err != nil {
				abandon(st, siteres.ActionError, "not bound: the site could not be created ("+err.Error()+")")
				continue
			}
		case siteReadable:
			if st.Action == siteres.ActionCreate { // created since the plan: bind to it
				plan.Summary[siteres.ActionCreate]--
				st.Action = siteres.ActionReuse
				plan.Summary[siteres.ActionReuse]++
			}
		}
		for j := range st.Devices {
			row := &st.Devices[j]
			if row.Action != siteres.ActionBind {
				continue
			}
			d, ok := byID[row.DeviceID]
			if !ok || !canSeeDevice(d, tenant, false) {
				row.Action, row.Detail = siteres.ActionError, "device is no longer visible"
				plan.Summary[siteres.ActionBind]--
				plan.Summary[siteres.ActionError]++
				continue
			}
			if b, has := s.deviceSites.Get(tenant, false, d.ID); has {
				row.Action, row.Detail = siteres.ActionSkip, "already placed at "+b.Site+" by an operator"
				plan.Summary[siteres.ActionBind]--
				plan.Summary[siteres.ActionSkip]++
				continue
			}
			if err := s.bindDeviceSite(d, st.Slug, claims); err != nil {
				row.Action, row.Detail = siteres.ActionError, err.Error()
				plan.Summary[siteres.ActionBind]--
				plan.Summary[siteres.ActionError]++
			}
		}
	}
	return plan
}

// filterPlan keeps only the sites named in keys (all when keys is empty) and
// recomputes the summary.
func filterPlan(plan siteres.Plan, keys []string) siteres.Plan {
	if len(keys) == 0 {
		return plan
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	out := siteres.Plan{Sites: []siteres.AdoptSite{}, Summary: map[string]int{}}
	for k := range plan.Summary {
		out.Summary[k] = 0
	}
	for _, st := range plan.Sites {
		if !want[st.Key] {
			continue
		}
		out.Sites = append(out.Sites, st)
		out.Summary[st.Action]++
		for _, d := range st.Devices {
			out.Summary[d.Action]++
		}
	}
	return out
}

// handleDiscoveredSites serves GET /api/discovered-sites: the adoption PREVIEW
// for the caller's tenant (infrastructure:read). The cross-tenant view gets an
// empty plan and adoptable=false with the reason.
func (s *server) handleDiscoveredSites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	plan, _, err := s.adoptionPlan(claims)
	if errors.Is(err, errAdoptNeedsTenant) {
		writeJSON(w, http.StatusOK, map[string]any{"adoptable": false, "reason": err.Error(),
			"plan": siteres.Plan{Sites: []siteres.AdoptSite{}, Summary: map[string]int{}}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"adoptable": true, "plan": plan})
}

// handleAdoptDiscoveredSites serves POST /api/discovered-sites/adopt
// (infrastructure:write). Body {"dry_run": bool (default true), "keys": [...]}.
// A dry run returns exactly the plan an apply would perform.
func (s *server) handleAdoptDiscoveredSites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	var req struct {
		DryRun *bool    `json:"dry_run"`
		Keys   []string `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}
	if len(req.Keys) > maxAdoptKeys {
		writeError(w, http.StatusBadRequest, fmt.Errorf("at most %d sites per request", maxAdoptKeys))
		return
	}
	dryRun := req.DryRun == nil || *req.DryRun // default: preview (safe)
	plan, tenant, err := s.adoptionPlan(claims)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plan = filterPlan(plan, req.Keys)
	if dryRun {
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "plan": plan})
		return
	}
	if s.sites == nil || s.deviceSites == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the site store is not configured"))
		return
	}
	applied := s.applyAdoption(claims, tenant, plan)
	logInfo("sites", "discovered sites adopted", map[string]any{
		"tenant": tenant, "actor": claims.Sub, "sites_created": applied.Summary[siteres.ActionCreate],
		"sites_reused": applied.Summary[siteres.ActionReuse], "devices_bound": applied.Summary[siteres.ActionBind],
		"devices_skipped": applied.Summary[siteres.ActionSkip], "errors": applied.Summary[siteres.ActionError],
	})
	writeJSON(w, http.StatusOK, map[string]any{"dry_run": false, "plan": applied})
}
