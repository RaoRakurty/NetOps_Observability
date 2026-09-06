// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// sot_import.go — external Source-of-Truth IMPORT: a ONE-WAY, file-based seed of
// operator INTENT (sites + device→site placement) into the platform's internal
// SoT, landing as editable internal records. It NEVER swaps authority: the
// platform's own SNMP-discovered inventory stays the observed-state source of
// truth; this only enriches the intent plane the wire can't supply. See
// docs/design/research/external-sot-import-research.md.
//
// Model (IRE-inspired, ServiceNow's reference architecture, implemented stdlib):
//   1. IDENTIFY — match each incoming row to an existing internal record, else
//      create. Sites match by slug; devices match by serial → mgmt-IP → hostname
//      against the caller's VISIBLE inventory (so a device in another tenant
//      simply doesn't match — never a cross-tenant write).
//   2. RECONCILE — the in-app operator is the highest-priority source. By default
//      an import is non-clobbering: it CREATEs new records and reports existing
//      records that would change as CONFLICT (skipped) — the operator opts into
//      `overwrite` to apply them. Exact matches are UNCHANGED.
//
// Safety: dry-run is the default — the planner returns a per-row plan (create /
// update / skip / conflict / error) with counts and writes nothing; applying is a
// second, explicit call. Tenant-scoped (infrastructure:write); records are
// stamped from the caller's principal, never the payload. Bounded body.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/discovery"
	"sort"
	"strings"

	"netops/backend/internal/sotimport"
	"netops/backend/models"
)

// The parsers moved to internal/sotimport (Phase-2 W1.7). Aliases keep the
// planners and handler below source-compatible.
type (
	importedSite    = sotimport.Site
	importedBinding = sotimport.Binding
	importResult    = sotimport.Result
)

// ── plan + apply ────────────────────────────────────────────────────────────

func siteChangeDetail(existing Site, in importedSite) string {
	var ch []string
	if strings.TrimSpace(in.Name) != "" && in.Name != existing.Name {
		ch = append(ch, "name")
	}
	if in.Status != existing.Status {
		ch = append(ch, "status")
	}
	if in.Owner != existing.Owner {
		ch = append(ch, "owner")
	}
	if in.HasCoords && (!existing.HasCoords || in.Lat != existing.Lat || in.Lng != existing.Lng) {
		ch = append(ch, "coordinates")
	}
	return strings.Join(ch, ", ")
}

// runSitesImport plans (and, unless dryRun, applies) a sites import for the
// (tenant, cross) principal. Non-clobbering: existing records that would change
// are CONFLICT/skipped unless overwrite is set.
func (s *server) runSitesImport(tenant string, cross, overwrite, dryRun bool, rows []importedSite) *importResult {
	res := sotimport.NewResult("sites", dryRun)
	for i, in := range rows {
		line := i + 2 // +1 for 0-index, +1 for header row
		slug := siteSlug(in.Slug)
		if slug == "" {
			slug = siteSlug(in.Name)
		}
		key := slug
		if key == "" {
			key = in.Name
		}
		// Validate the candidate record up front.
		cand := Site{TenantID: tenant, Slug: slug, Name: strings.TrimSpace(in.Name),
			Status: in.Status, Owner: in.Owner, Lat: in.Lat, Lng: in.Lng, HasCoords: in.HasCoords}
		if err := cand.validate(); err != nil {
			res.Add(line, key, "error", err.Error())
			continue
		}
		existing, found := s.sites.Get(tenant, cross, slug)
		if !found {
			if !dryRun {
				if _, err := s.sites.Upsert(cand); err != nil {
					res.Add(line, key, "error", err.Error())
					continue
				}
			}
			res.Add(line, key, "create", "")
			continue
		}
		detail := siteChangeDetail(existing, in)
		if detail == "" {
			res.Add(line, key, "unchanged", "")
			continue
		}
		if !overwrite {
			res.Add(line, key, "conflict", "exists; would change "+detail+" (enable overwrite to apply)")
			continue
		}
		// Overwrite: preserve the existing owning tenant (never reassign ownership);
		// fill from the import, keeping existing values where the import is blank.
		upd := existing
		if strings.TrimSpace(in.Name) != "" {
			upd.Name = strings.TrimSpace(in.Name)
		}
		upd.Status, upd.Owner = in.Status, in.Owner
		if in.HasCoords {
			upd.Lat, upd.Lng, upd.HasCoords = in.Lat, in.Lng, true
		}
		if !dryRun {
			if _, err := s.sites.Upsert(upd); err != nil {
				res.Add(line, key, "error", err.Error())
				continue
			}
		}
		res.Add(line, key, "update", detail)
	}
	return res
}

// deviceResolver indexes the caller's VISIBLE devices for natural-key matching
// (id exact → serial → mgmt-IP → hostname, per the IRE precedence). Devices in
// another tenant are absent, so a foreign identifier simply fails to match —
// never a cross-tenant write.
type deviceResolver struct {
	byID, bySerial, byIP, byName map[string]models.Device
}

func (s *server) newDeviceResolver(claims jwtClaims) deviceResolver {
	dr := deviceResolver{byID: map[string]models.Device{}, bySerial: map[string]models.Device{},
		byIP: map[string]models.Device{}, byName: map[string]models.Device{}}
	for _, d := range visibleDevices(s.discovery.Devices(), claims) {
		dr.byID[d.ID] = d
		if sn := strings.ToLower(strings.TrimSpace(d.Labels["serial"])); sn != "" {
			dr.bySerial[sn] = d
		}
		if ip := strings.TrimSpace(d.Address); ip != "" {
			dr.byIP[ip] = d
		}
		if nm := strings.ToLower(strings.TrimSpace(d.Name)); nm != "" {
			dr.byName[nm] = d
		}
	}
	return dr
}

func (dr deviceResolver) resolve(identifier string) (models.Device, bool) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		var z models.Device
		return z, false
	}
	if d, ok := dr.byID[id]; ok {
		return d, true
	}
	low := strings.ToLower(id)
	if d, ok := dr.bySerial[low]; ok { // serial before IP (IPs aren't stable identity — IRE)
		return d, true
	}
	if d, ok := dr.byIP[id]; ok {
		return d, true
	}
	if d, ok := dr.byName[low]; ok {
		return d, true
	}
	var z models.Device
	return z, false
}

func (s *server) runBindingsImport(claims jwtClaims, tenant string, cross, overwrite, dryRun bool, rows []importedBinding) *importResult {
	res := sotimport.NewResult("device_sites", dryRun)
	dr := s.newDeviceResolver(claims)
	for i, in := range rows {
		line := i + 2
		key := in.Device
		slug := siteSlug(in.Site)
		if slug == "" {
			res.Add(line, key, "error", "missing site")
			continue
		}
		if _, ok := s.sites.Get(tenant, cross, slug); !ok {
			res.Add(line, key, "error", fmt.Sprintf("no site %q visible in this tenant", slug))
			continue
		}
		d, ok := dr.resolve(in.Device)
		if !ok {
			res.Add(line, key, "error", fmt.Sprintf("no visible device matches %q", in.Device))
			continue
		}
		existing, has := s.deviceSites.Get(tenant, cross, d.ID)
		if has && existing.Site == slug {
			res.Add(line, d.ID, "unchanged", "")
			continue
		}
		if has && existing.Site != slug {
			if !overwrite {
				res.Add(line, d.ID, "conflict", fmt.Sprintf("already bound to %q (enable overwrite to rebind)", existing.Site))
				continue
			}
			if !dryRun {
				if err := s.bindDeviceSite(d, slug, claims); err != nil {
					res.Add(line, d.ID, "error", err.Error())
					continue
				}
			}
			res.Add(line, d.ID, "update", "rebind "+existing.Site+" → "+slug)
			continue
		}
		if !dryRun {
			if err := s.bindDeviceSite(d, slug, claims); err != nil {
				res.Add(line, d.ID, "error", err.Error())
				continue
			}
		}
		res.Add(line, d.ID, "create", "→ "+slug)
	}
	return res
}

// bindDeviceSite writes one device→site binding, stamping the owning tenant from
// the DEVICE (server-side trusted state) and the identity tokens for geomap
// resolution — the same contract as handleDeviceSite.
func (s *server) bindDeviceSite(d models.Device, slug string, claims jwtClaims) error {
	tokens := discovery.DeviceIdentities(d)
	if len(tokens) == 0 {
		return errors.New("device has no stable identity token")
	}
	return s.deviceSites.Set(DeviceSiteBinding{
		TenantID: deviceTenant(d), DeviceID: d.ID, Tokens: tokens,
		Device: d.Name, Site: slug, UpdatedBy: claims.Sub,
	})
}

// ── HTTP ────────────────────────────────────────────────────────────────────

// handleSoTImport serves POST /api/sot/import — a one-way file import that seeds
// the internal SoT. Tenant-scoped, infrastructure:write. Dry-run by default.
func (s *server) handleSoTImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	var req struct {
		Kind      string `json:"kind"`   // sites | device_sites
		Format    string `json:"format"` // csv | json | geojson
		Data      string `json:"data"`   // raw file text
		DryRun    *bool  `json:"dry_run"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, sotimport.MaxBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}
	dryRun := req.DryRun == nil || *req.DryRun // default: dry-run (safe)
	format := strings.ToLower(strings.TrimSpace(req.Format))
	tenant, cross := principalTenant(claims)

	var res *importResult
	switch strings.ToLower(strings.TrimSpace(req.Kind)) {
	case "sites":
		rows, err := sotimport.ParseSites(format, []byte(req.Data))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		res = s.runSitesImport(tenant, cross, req.Overwrite, dryRun, rows)
	case "device_sites", "devices":
		rows, err := sotimport.ParseBindings(format, []byte(req.Data))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		res = s.runBindingsImport(claims, tenant, cross, req.Overwrite, dryRun, rows)
	default:
		writeError(w, http.StatusBadRequest, errors.New(`kind must be "sites" or "device_sites"`))
		return
	}
	// Ensure all action keys are present so the UI can render stable counters.
	for _, k := range []string{"create", "update", "skip", "conflict", "unchanged", "error"} {
		if _, ok := res.Summary[k]; !ok {
			res.Summary[k] = 0
		}
	}
	// Keep the rows deterministic for display.
	sort.SliceStable(res.Rows, func(i, j int) bool { return res.Rows[i].Line < res.Rows[j].Line })
	writeJSON(w, http.StatusOK, res)
}
