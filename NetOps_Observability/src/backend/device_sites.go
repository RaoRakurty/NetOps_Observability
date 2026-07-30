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
	"netops/backend/internal/discovery"
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
func (s *deviceSiteStore) Assignments(tenant string, cross bool) map[string]string {
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
	return s.kv.Get(tenant, cross, deviceID)
}

// Set stores a binding. The caller MUST have stamped b.TenantID from the device's
// tenant (server-side), validated the site, and populated Tokens — see
// handleDeviceSite.
func (s *deviceSiteStore) Set(b DeviceSiteBinding) error {
	b.UpdatedAt = time.Now().UTC()
	return s.kv.Upsert(b)
}

// Delete clears a device's binding within the caller's scope. Returns false when
// the device id isn't visible to the caller (or has no binding).
func (s *deviceSiteStore) Delete(tenant string, cross bool, deviceID string) bool {
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
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "site": slug})
	case http.MethodDelete:
		if !s.deviceSites.Delete(tenant, cross, d.ID) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}
