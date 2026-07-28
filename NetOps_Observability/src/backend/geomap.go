package main

import (
	"context"
	"errors"
	"net/http"
	"netops/backend/internal/discovery"
	"strings"
	"time"

	"netops/backend/models"
)

// geomap.go — Device Geomap data (Infrastructure → Maps). Joins the platform's
// own Source-of-Truth sites (the internal sites store holds latitude/longitude in
// decimal WGS 84 degrees) with the live device inventory: devices are placed by an
// operator device→site binding or a `site` label, and freshness of last_seen gives
// per-site health. GeoIP is deliberately NOT used here — RFC 1918 management
// addresses don't geolocate; placement is intent data owned by the operator in the
// SoT. (NetBox, when connected, is an automation connector — not the geo/placement
// authority; see docs/design/sot-provider-model.md.)
//
// Honest onboarding states instead of an empty map:
//   - geo_enabled:false + reason "sot"    → no sites declared and no annotations
//   - sites without coordinates are returned with has_coords:false so the UI
//     can say "set latitude/longitude on this site", not silently drop it
//   - devices with no site assignment are counted as unplaced

// geoFreshWindow mirrors the Devices UI heartbeat convention (FRESH_MS):
// a device seen within this window counts as up.
const geoFreshWindow = 5 * time.Minute

// geoSite is one site row in the /api/geomap response.
type geoSite struct {
	Name      string  `json:"name"`
	Slug      string  `json:"slug"`
	Status    string  `json:"status,omitempty"`
	Lat       float64 `json:"lat"`
	Lng       float64 `json:"lng"`
	HasCoords bool    `json:"has_coords"`
	Devices   int     `json:"devices"`
	Up        int     `json:"up"`
	Down      int     `json:"down"`
	// Source is the SoT provider that supplied this site ("internal"|"netbox"|
	// "manual"). In-memory only (drives the geo projection's evidence source); not
	// part of the /api/geomap wire response.
	Source string `json:"-"`
}

// buildGeomap joins the site list with the visible inventory. A device's site
// is resolved with clear intent precedence: an explicit operator device→site
// binding (the `assign` map) wins, then a discovery-stamped inventory `site`
// label; otherwise an operator location annotation (`lookup`, the
// device_locations layer) places it, with devices sharing a site label folding
// into one bubble. Pure — unit-tested.
func buildGeomap(sites []SoTSite, devices []models.Device, assign map[string]string,
	lookup func([]string) (DeviceLocation, bool), now time.Time) (rows []geoSite, unplaced int, deviceSite map[string]string) {
	bySlug := map[string]*geoSite{}
	order := []string{}
	deviceSite = map[string]string{}
	for _, s := range sites {
		if s.Slug == "" {
			continue
		}
		g := &geoSite{
			Name: s.Name, Slug: s.Slug, Status: s.Status,
			Lat: s.Lat, Lng: s.Lng, HasCoords: s.HasCoords, Source: s.Source,
		}
		bySlug[s.Slug] = g
		order = append(order, s.Slug)
	}
	count := func(g *geoSite, d models.Device) {
		g.Devices++
		if now.Sub(d.LastSeen) < geoFreshWindow {
			g.Up++
		} else {
			g.Down++
		}
		deviceSite[d.ID] = g.Slug // record which bubble each device folded into
	}
	for _, d := range devices {
		toks := discovery.DeviceIdentities(d)
		// Explicit device→site assignment (operator binding or NetBox map) is
		// first-class intent and wins over a discovery-stamped inventory label.
		var slug string
		if assign != nil {
			for _, tok := range toks {
				if s, ok := assign[tok]; ok && s != "" {
					slug = s
					break
				}
			}
		}
		if slug == "" {
			slug = d.Labels["site"]
		}
		if g := bySlug[slug]; slug != "" && g != nil {
			count(g, d)
			continue
		}
		// No SoT placement — fall back to the operator annotation layer.
		if lookup != nil {
			if l, ok := lookup(toks); ok {
				name := l.Site
				if name == "" {
					name = d.Name
				}
				key := "loc:" + strings.ToLower(name)
				g := bySlug[key]
				if g == nil {
					g = &geoSite{Name: name, Slug: key, Status: "manual", Lat: l.Lat, Lng: l.Lng, HasCoords: true, Source: "manual"}
					bySlug[key] = g
					order = append(order, key)
				}
				count(g, d)
				continue
			}
		}
		unplaced++
	}
	for _, slug := range order {
		rows = append(rows, *bySlug[slug])
	}
	return rows, unplaced, deviceSite
}

// geomapResolve gathers the geo surfaces' shared inputs: site rows joined with
// inventory health, the device→site slug map (SAME placement precedence as the
// rows, so circuits and bubbles can never disagree), and the unplaced device
// count. enabled is false (with a reason) when no intent source is configured.
// Both /api/geomap and the executive_geo topology projection call this so they
// share one source of truth.
func (s *server) geomapResolve(ctx context.Context, claims jwtClaims) (rows []geoSite, deviceSite map[string]string, unplaced int, enabled bool, reason, errMsg string) {
	tenant, cross := principalTenant(claims)
	p := s.activeSoT() // the internal provider — the platform's own inventory is the SoT
	sites, err := p.Sites(ctx, tenant, cross)
	if err != nil {
		// The internal provider never errors; kept for the SoTProvider contract.
		return nil, nil, 0, false, "fetch", err.Error()
	}
	assign, _ := p.DeviceSites(ctx, tenant, cross)

	// The map renders from EITHER intent source: declared sites and/or operator
	// location annotations. Onboarding empty-state only when neither exists.
	if len(sites) == 0 && s.deviceLocations.Empty() {
		return nil, nil, 0, false, "sot", ""
	}

	devices := visibleDevices(s.discovery.Devices(), claims)
	rows, unplaced, deviceSite = buildGeomap(sites, devices, assign, s.deviceLocations.Lookup, time.Now())
	return rows, deviceSite, unplaced, true, "", ""
}

// handleGeomap serves GET /api/geomap.
func (s *server) handleGeomap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	rows, _, unplaced, enabled, reason, errMsg := s.geomapResolve(r.Context(), claims)
	if !enabled {
		resp := map[string]any{"geo_enabled": false, "reason": reason}
		if errMsg != "" {
			resp["error"] = errMsg
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	placed := 0
	for _, g := range rows {
		placed += g.Devices
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"geo_enabled": true,
		"sites":       rows,
		"placed":      placed,
		"unplaced":    unplaced,
	})
}
