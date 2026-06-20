package main

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
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"netops/backend/models"
)

const importMaxBody = 1 << 20 // 1 MiB of file text — thousands of rows

// ── parsed rows ─────────────────────────────────────────────────────────────

type importedSite struct {
	Slug      string
	Name      string
	Status    string
	Owner     string
	Lat       float64
	Lng       float64
	HasCoords bool
}

type importedBinding struct {
	Device string // free identifier: device id | hostname | mgmt-IP | serial
	Site   string // site slug (or name → slugified)
}

// ── results ─────────────────────────────────────────────────────────────────

type importRowResult struct {
	Line   int    `json:"line"`             // 1-based source row (header = line 1)
	Key    string `json:"key"`              // site slug / device identifier
	Action string `json:"action"`           // create|update|skip|conflict|unchanged|error
	Detail string `json:"detail,omitempty"` // what would change, or why it failed
}

type importResult struct {
	Kind    string            `json:"kind"`
	DryRun  bool              `json:"dry_run"`
	Summary map[string]int    `json:"summary"`
	Rows    []importRowResult `json:"rows"`
}

func newImportResult(kind string, dryRun bool) *importResult {
	return &importResult{Kind: kind, DryRun: dryRun, Summary: map[string]int{}, Rows: []importRowResult{}}
}

func (r *importResult) add(line int, key, action, detail string) {
	r.Summary[action]++
	r.Rows = append(r.Rows, importRowResult{Line: line, Key: key, Action: action, Detail: detail})
}

// ── parsers (pure, unit-tested) ─────────────────────────────────────────────

// csvIndex maps lower-cased header names → column index, accepting common aliases.
func csvIndex(header []string) map[string]int {
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return idx
}

func cell(rec []string, idx map[string]int, names ...string) string {
	for _, n := range names {
		if i, ok := idx[n]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
	}
	return ""
}

// parseCoords resolves an optional lat/lng pair: both blank → no coords (valid);
// either present → both must parse as finite decimals.
func parseCoords(latS, lngS string) (lat, lng float64, has bool, err error) {
	latS, lngS = strings.TrimSpace(latS), strings.TrimSpace(lngS)
	if latS == "" && lngS == "" {
		return 0, 0, false, nil
	}
	if latS == "" || lngS == "" {
		return 0, 0, false, errors.New("both latitude and longitude are required (or leave both blank)")
	}
	if lat, err = strconv.ParseFloat(latS, 64); err != nil {
		return 0, 0, false, fmt.Errorf("bad latitude %q", latS)
	}
	if lng, err = strconv.ParseFloat(lngS, 64); err != nil {
		return 0, 0, false, fmt.Errorf("bad longitude %q", lngS)
	}
	return lat, lng, true, nil
}

func parseImportSites(format string, data []byte) ([]importedSite, error) {
	switch format {
	case "csv":
		return parseSitesCSV(data)
	case "json":
		return parseSitesJSON(data)
	case "geojson":
		return parseSitesGeoJSON(data)
	default:
		return nil, fmt.Errorf("unsupported format %q for sites (use csv, json or geojson)", format)
	}
}

func parseSitesCSV(data []byte) ([]importedSite, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV parse: %w", err)
	}
	if len(rows) < 1 {
		return nil, errors.New("empty CSV")
	}
	idx := csvIndex(rows[0])
	out := make([]importedSite, 0, len(rows)-1)
	for _, rec := range rows[1:] {
		lat, lng, has, cerr := parseCoords(
			cell(rec, idx, "lat", "latitude"), cell(rec, idx, "lng", "lon", "longitude"))
		if cerr != nil {
			return nil, cerr
		}
		out = append(out, importedSite{
			Slug:   cell(rec, idx, "slug"),
			Name:   cell(rec, idx, "name", "site", "site_name"),
			Status: cell(rec, idx, "status"),
			Owner:  cell(rec, idx, "owner", "team", "owner_team"),
			Lat:    lat, Lng: lng, HasCoords: has,
		})
	}
	return out, nil
}

func parseSitesJSON(data []byte) ([]importedSite, error) {
	var raw []struct {
		Slug   string   `json:"slug"`
		Name   string   `json:"name"`
		Status string   `json:"status"`
		Owner  string   `json:"owner"`
		Lat    *float64 `json:"lat"`
		Lng    *float64 `json:"lng"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("JSON parse (expected an array of site objects): %w", err)
	}
	out := make([]importedSite, 0, len(raw))
	for _, s := range raw {
		si := importedSite{Slug: strings.TrimSpace(s.Slug), Name: strings.TrimSpace(s.Name),
			Status: strings.TrimSpace(s.Status), Owner: strings.TrimSpace(s.Owner)}
		if s.Lat != nil && s.Lng != nil {
			si.Lat, si.Lng, si.HasCoords = *s.Lat, *s.Lng, true
		} else if (s.Lat == nil) != (s.Lng == nil) {
			return nil, errors.New("each site needs both lat and lng, or neither")
		}
		out = append(out, si)
	}
	return out, nil
}

// parseSitesGeoJSON reads an RFC 7946 FeatureCollection of Point features.
// IMPORTANT: GeoJSON coordinate order is [longitude, latitude] (lng first).
func parseSitesGeoJSON(data []byte) ([]importedSite, error) {
	var fc struct {
		Type     string `json:"type"`
		Features []struct {
			Geometry struct {
				Type        string    `json:"type"`
				Coordinates []float64 `json:"coordinates"`
			} `json:"geometry"`
			Properties map[string]any `json:"properties"`
		} `json:"features"`
	}
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("GeoJSON parse: %w", err)
	}
	if !strings.EqualFold(fc.Type, "FeatureCollection") {
		return nil, errors.New("GeoJSON must be a FeatureCollection")
	}
	prop := func(p map[string]any, keys ...string) string {
		for _, k := range keys {
			if v, ok := p[k]; ok {
				if s, ok := v.(string); ok {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}
	out := make([]importedSite, 0, len(fc.Features))
	for _, f := range fc.Features {
		si := importedSite{
			Slug:   prop(f.Properties, "slug"),
			Name:   prop(f.Properties, "name", "site", "site_name"),
			Status: prop(f.Properties, "status"),
			Owner:  prop(f.Properties, "owner", "team"),
		}
		if strings.EqualFold(f.Geometry.Type, "Point") && len(f.Geometry.Coordinates) >= 2 {
			si.Lng, si.Lat, si.HasCoords = f.Geometry.Coordinates[0], f.Geometry.Coordinates[1], true
		}
		out = append(out, si)
	}
	return out, nil
}

func parseImportBindings(format string, data []byte) ([]importedBinding, error) {
	switch format {
	case "csv":
		r := csv.NewReader(strings.NewReader(string(data)))
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("CSV parse: %w", err)
		}
		if len(rows) < 1 {
			return nil, errors.New("empty CSV")
		}
		idx := csvIndex(rows[0])
		out := make([]importedBinding, 0, len(rows)-1)
		for _, rec := range rows[1:] {
			out = append(out, importedBinding{
				Device: cell(rec, idx, "device", "device_id", "host", "hostname", "name", "ip", "address", "serial"),
				Site:   cell(rec, idx, "site", "site_slug", "slug"),
			})
		}
		return out, nil
	case "json":
		var raw []struct {
			Device string `json:"device"`
			Site   string `json:"site"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("JSON parse (expected an array of {device, site}): %w", err)
		}
		out := make([]importedBinding, 0, len(raw))
		for _, b := range raw {
			out = append(out, importedBinding{Device: strings.TrimSpace(b.Device), Site: strings.TrimSpace(b.Site)})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported format %q for device_sites (use csv or json)", format)
	}
}

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
	res := newImportResult("sites", dryRun)
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
			res.add(line, key, "error", err.Error())
			continue
		}
		existing, found := s.sites.Get(tenant, cross, slug)
		if !found {
			if !dryRun {
				if _, err := s.sites.Upsert(cand); err != nil {
					res.add(line, key, "error", err.Error())
					continue
				}
			}
			res.add(line, key, "create", "")
			continue
		}
		detail := siteChangeDetail(existing, in)
		if detail == "" {
			res.add(line, key, "unchanged", "")
			continue
		}
		if !overwrite {
			res.add(line, key, "conflict", "exists; would change "+detail+" (enable overwrite to apply)")
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
				res.add(line, key, "error", err.Error())
				continue
			}
		}
		res.add(line, key, "update", detail)
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
	res := newImportResult("device_sites", dryRun)
	dr := s.newDeviceResolver(claims)
	for i, in := range rows {
		line := i + 2
		key := in.Device
		slug := siteSlug(in.Site)
		if slug == "" {
			res.add(line, key, "error", "missing site")
			continue
		}
		if _, ok := s.sites.Get(tenant, cross, slug); !ok {
			res.add(line, key, "error", fmt.Sprintf("no site %q visible in this tenant", slug))
			continue
		}
		d, ok := dr.resolve(in.Device)
		if !ok {
			res.add(line, key, "error", fmt.Sprintf("no visible device matches %q", in.Device))
			continue
		}
		existing, has := s.deviceSites.Get(tenant, cross, d.ID)
		if has && existing.Site == slug {
			res.add(line, d.ID, "unchanged", "")
			continue
		}
		if has && existing.Site != slug {
			if !overwrite {
				res.add(line, d.ID, "conflict", fmt.Sprintf("already bound to %q (enable overwrite to rebind)", existing.Site))
				continue
			}
			if !dryRun {
				if err := s.bindDeviceSite(d, slug, claims); err != nil {
					res.add(line, d.ID, "error", err.Error())
					continue
				}
			}
			res.add(line, d.ID, "update", "rebind "+existing.Site+" → "+slug)
			continue
		}
		if !dryRun {
			if err := s.bindDeviceSite(d, slug, claims); err != nil {
				res.add(line, d.ID, "error", err.Error())
				continue
			}
		}
		res.add(line, d.ID, "create", "→ "+slug)
	}
	return res
}

// bindDeviceSite writes one device→site binding, stamping the owning tenant from
// the DEVICE (server-side trusted state) and the identity tokens for geomap
// resolution — the same contract as handleDeviceSite.
func (s *server) bindDeviceSite(d models.Device, slug string, claims jwtClaims) error {
	tokens := deviceIdentities(d)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, importMaxBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}
	dryRun := req.DryRun == nil || *req.DryRun // default: dry-run (safe)
	format := strings.ToLower(strings.TrimSpace(req.Format))
	tenant, cross := principalTenant(claims)

	var res *importResult
	switch strings.ToLower(strings.TrimSpace(req.Kind)) {
	case "sites":
		rows, err := parseImportSites(format, []byte(req.Data))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		res = s.runSitesImport(tenant, cross, req.Overwrite, dryRun, rows)
	case "device_sites", "devices":
		rows, err := parseImportBindings(format, []byte(req.Data))
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
