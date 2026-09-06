// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_locations.go — operator-supplied device placement: the location
// annotation LAYER under Infrastructure → Maps. Discovery data stays
// untouched; coordinates typed by the operator live in this small store and
// are composed with the NetBox Source-of-Truth at geomap read time with clear
// precedence: SoT site coords (organizational intent) win, then a device
// annotation (local intent), else the device counts as unplaced.
//
// Identity: annotations are keyed by the same stable identity tokens the
// inventory dedup uses (ip: / sn: / name: — see deviceIdentities), so a
// device keeps its placement across rediscovery and across sources. Tenancy
// is enforced on the read/write paths by device visibility (canSeeDevice),
// not duplicated in the store.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/discovery"
	"netops/backend/internal/platformdb"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
)

// DeviceLocation is one operator-placed device.
type DeviceLocation struct {
	Token     string    `json:"token"`             // primary identity token at save time
	Aliases   []string  `json:"aliases,omitempty"` // every identity token at save time — drift cleanup
	Device    string    `json:"device"`            // display name (editor convenience, not identity)
	Site      string    `json:"site,omitempty"`    // free-form label; devices sharing it form one map bubble
	Lat       float64   `json:"lat"`
	Lng       float64   `json:"lng"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (l DeviceLocation) validate() error {
	if l.Lat < -90 || l.Lat > 90 {
		return errors.New("lat must be within [-90, 90]")
	}
	if l.Lng < -180 || l.Lng > 180 {
		return errors.New("lng must be within [-180, 180]")
	}
	if len(l.Site) > 120 {
		return errors.New("site label too long (max 120)")
	}
	return nil
}

type deviceLocationStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]DeviceLocation // EVERY identity token (alias) → its record
}

func newDeviceLocationStore(path string) (*deviceLocationStore, error) {
	if path == "" {
		path = "/data/device_locations.json"
	}
	s := &deviceLocationStore{path: path, items: make(map[string]DeviceLocation)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *deviceLocationStore) load() error {
	b, err := platformdb.Load(s.path)
	if err != nil {
		return nil // absent store → empty
	}
	var list []DeviceLocation
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, l := range list {
		s.items[l.Token] = l
		for _, a := range l.Aliases {
			s.items[a] = l
		}
	}
	return nil
}

func (s *deviceLocationStore) flushLocked() error {
	// items is multi-keyed by alias — collapse to one row per record (Token).
	seen := map[string]bool{}
	list := make([]DeviceLocation, 0, len(s.items))
	for _, l := range s.items {
		if seen[l.Token] {
			continue
		}
		seen[l.Token] = true
		list = append(list, l)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Token < list[j].Token })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

// Lookup resolves a device's annotation by ANY of its identity tokens.
func (s *deviceLocationStore) Lookup(tokens []string) (DeviceLocation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range tokens {
		if l, ok := s.items[t]; ok {
			return l, true
		}
	}
	return DeviceLocation{}, false
}

// Upsert stores the annotation under EVERY identity token, replacing any
// record reachable through any of them — including all of that record's own
// aliases, so a device whose primary identity drifted between saves (new mgmt
// IP, same serial/name) can't leave a stale ghost behind.
func (s *deviceLocationStore) Upsert(tokens []string, l DeviceLocation) error {
	if err := l.validate(); err != nil {
		return err
	}
	if len(tokens) == 0 {
		return errors.New("device has no stable identity token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteReachableLocked(tokens)
	l.Token = tokens[0]
	l.Aliases = append([]string(nil), tokens...)
	l.UpdatedAt = time.Now().UTC()
	for _, t := range tokens {
		s.items[t] = l
	}
	return s.flushLocked()
}

// deleteReachableLocked removes every record reachable via any given token,
// under all of that record's aliases.
func (s *deviceLocationStore) deleteReachableLocked(tokens []string) bool {
	found := false
	for _, t := range tokens {
		old, ok := s.items[t]
		if !ok {
			continue
		}
		found = true
		delete(s.items, old.Token)
		for _, a := range old.Aliases {
			delete(s.items, a)
		}
		delete(s.items, t)
	}
	return found
}

func (s *deviceLocationStore) Delete(tokens []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.deleteReachableLocked(tokens) {
		return errors.New("no location set for this device")
	}
	return s.flushLocked()
}

// Empty reports whether any annotation exists (drives geomap onboarding).
func (s *deviceLocationStore) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items) == 0
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

// handleDeviceLocation serves /api/devices/{id}/location (GET/PUT/DELETE).
// Authz mirrors the device routes: the caller must be able to SEE the device
// (404 otherwise — never reveal other tenants' ids), and writes require
// infrastructure:write. The audit middleware records every mutation.
func (s *server) handleDeviceLocation(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/location")
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
	tokens := discovery.DeviceIdentities(d)

	switch r.Method {
	case http.MethodGet:
		resp := map[string]any{"set": false}
		if slug := sotSiteFor(d, s.geoAssignments(tenant, cross)); slug != "" && s.geoSiteSlugs(tenant, cross)[slug] {
			resp["sot_site"] = slug
		}
		if l, ok := s.deviceLocations.Lookup(tokens); ok {
			resp["set"], resp["location"] = true, l
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		var req struct {
			Site string  `json:"site"`
			Lat  float64 `json:"lat"`
			Lng  float64 `json:"lng"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
			return
		}
		l := DeviceLocation{
			Device:    d.Name,
			Site:      strings.TrimSpace(req.Site),
			Lat:       req.Lat,
			Lng:       req.Lng,
			UpdatedBy: claims.Sub,
		}
		if err := s.deviceLocations.Upsert(tokens, l); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if err := s.deviceLocations.Delete(tokens); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// handleDeviceLocations serves GET /api/devices/locations — the editor's
// joined view: every visible device with its placement and where it came from
// (sot | manual | none). Unplaced devices sort first so the operator sees what
// needs attention.
func (s *server) handleDeviceLocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	assign := s.geoAssignments(tenant, cross)
	resolvable := s.geoSiteSlugs(tenant, cross)
	type row struct {
		ID     string  `json:"id"`
		Name   string  `json:"name"`
		Vendor string  `json:"vendor,omitempty"`
		Site   string  `json:"site,omitempty"`
		Lat    float64 `json:"lat,omitempty"`
		Lng    float64 `json:"lng,omitempty"`
		Source string  `json:"source"` // sot | manual | none
	}
	devices := visibleDevices(s.discovery.Devices(), claims)
	rows := make([]row, 0, len(devices))
	for _, d := range devices {
		x := row{ID: d.ID, Name: d.Name, Vendor: d.Labels["vendor"], Source: "none"}
		toks := discovery.DeviceIdentities(d)
		if slug := sotSiteFor(d, assign); slug != "" && resolvable[slug] {
			x.Source, x.Site = "sot", slug
		} else if l, ok := s.deviceLocations.Lookup(toks); ok {
			x.Source, x.Site, x.Lat, x.Lng = "manual", l.Site, l.Lat, l.Lng
		}
		rows = append(rows, x)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if (rows[i].Source == "none") != (rows[j].Source == "none") {
			return rows[i].Source == "none"
		}
		return rows[i].Name < rows[j].Name
	})
	writeJSON(w, http.StatusOK, map[string]any{"devices": rows})
}

// sotSiteFor resolves a device's SoT site slug using the SAME precedence the
// geomap join uses: an explicit device→site assignment (operator binding, or the
// NetBox device→site map) wins, then a discovery-stamped inventory label. The
// explicit assignment is first-class intent and must override a stale label.
func sotSiteFor(d models.Device, assign map[string]string) string {
	for _, tok := range discovery.DeviceIdentities(d) {
		if s, ok := assign[tok]; ok && s != "" {
			return s
		}
	}
	return d.Labels["site"]
}

// geoAssignments returns the operator device→site bindings (the internal SoT
// authority), SCOPED to the (tenant, cross) principal. Callers treat nil as "no
// explicit assignment" and fall back to the device's inventory label.
func (s *server) geoAssignments(tenant string, cross bool) map[string]string {
	if s.deviceSites == nil {
		return nil
	}
	return s.deviceSites.Assignments(tenant, cross)
}

// geoSiteSlugs returns the slugs of internal SoT sites the geomap can actually
// render, SCOPED to the (tenant, cross) principal. A device whose `site` label
// names a site that isn't declared (e.g. a label stamped by a discovery source)
// is NOT SoT-placed — it must stay editable in the location layer or it could
// never appear on the map.
func (s *server) geoSiteSlugs(tenant string, cross bool) map[string]bool {
	out := map[string]bool{}
	if s.sites == nil {
		return out
	}
	for _, st := range s.sites.All(tenant, cross) {
		if st.Slug != "" {
			out[st.Slug] = true
		}
	}
	return out
}
