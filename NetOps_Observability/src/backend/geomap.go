package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
)

// geomap.go — Device Geomap data (Infrastructure → Maps). Joins NetBox DCIM
// sites (the Source of Truth holds latitude/longitude in decimal WGS 84
// degrees) with the live device inventory: devices carry a `site` label when
// their NetBox record assigns one, and freshness of last_seen gives per-site
// health. GeoIP is deliberately NOT used here — RFC 1918 management addresses
// don't geolocate; placement is intent data owned by the operator in the SoT.
//
// Honest onboarding states instead of an empty map:
//   - geo_enabled:false + reason "sot"    → NetBox not configured
//   - sites without coordinates are returned with has_coords:false so the UI
//     can say "set latitude/longitude on this site", not silently drop it
//   - devices with no site assignment are counted as unplaced

// geoFreshWindow mirrors the Devices UI heartbeat convention (FRESH_MS):
// a device seen within this window counts as up.
const geoFreshWindow = 5 * time.Minute

const geoSiteCacheTTL = 60 * time.Second

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
}

// netboxSite is the subset of /api/dcim/sites/ we read.
type netboxSite struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status *struct {
		Value string `json:"value"`
	} `json:"status"`
	Latitude  *float64 `json:"latitude"`
	Longitude *float64 `json:"longitude"`
}

type netboxSiteResp struct {
	Next    *string      `json:"next"`
	Results []netboxSite `json:"results"`
}

// geoSiteCache memoizes the NetBox site list briefly so a dashboard refresh
// doesn't turn into a NetBox request per panel.
type geoSiteCache struct {
	mu    sync.Mutex
	at    time.Time
	sites []netboxSite
}

// fetchNetboxSites pages through /api/dcim/sites/ with the same hardening as
// the device source (SR-023): token only to the configured host, pagination
// pinned to that host, bounded error bodies.
func fetchNetboxSites(ctx context.Context, client *http.Client, cfg netboxConfig) ([]netboxSite, error) {
	nbURL := strings.TrimRight(cfg.URL, "/")
	base, err := url.Parse(nbURL)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("geomap: invalid NetBox URL %q: %w", nbURL, err)
	}
	next := nbURL + "/api/dcim/sites/?limit=200"
	var out []netboxSite
	for next != "" && len(out) < 2000 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Authorization", "Token "+cfg.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return out, err
		}
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return out, fmt.Errorf("netbox sites %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var page netboxSiteResp
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return out, err
		}
		resp.Body.Close()
		out = append(out, page.Results...)
		next = ""
		if page.Next != nil && *page.Next != "" {
			if nu, perr := url.Parse(*page.Next); perr == nil &&
				(nu.Scheme == "http" || nu.Scheme == "https") && strings.EqualFold(nu.Host, base.Host) {
				next = *page.Next
			}
		}
	}
	return out, nil
}

// buildGeomap joins the site list with the visible inventory. Pure — unit-tested.
func buildGeomap(sites []netboxSite, devices []models.Device, now time.Time) (rows []geoSite, unplaced int) {
	bySlug := map[string]*geoSite{}
	order := []string{}
	for _, s := range sites {
		if s.Slug == "" {
			continue
		}
		g := &geoSite{Name: s.Name, Slug: s.Slug}
		if s.Status != nil {
			g.Status = s.Status.Value
		}
		if s.Latitude != nil && s.Longitude != nil {
			g.Lat, g.Lng, g.HasCoords = *s.Latitude, *s.Longitude, true
		}
		bySlug[s.Slug] = g
		order = append(order, s.Slug)
	}
	for _, d := range devices {
		slug := d.Labels["site"]
		g := bySlug[slug]
		if slug == "" || g == nil {
			unplaced++
			continue
		}
		g.Devices++
		if now.Sub(d.LastSeen) < geoFreshWindow {
			g.Up++
		} else {
			g.Down++
		}
	}
	for _, slug := range order {
		rows = append(rows, *bySlug[slug])
	}
	return rows, unplaced
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
	cfg := s.netboxCfg.effective()
	if !cfg.Enabled || cfg.URL == "" || cfg.Token == "" {
		writeJSON(w, http.StatusOK, map[string]any{"geo_enabled": false, "reason": "sot"})
		return
	}

	s.geoSites.mu.Lock()
	if time.Since(s.geoSites.at) > geoSiteCacheTTL {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		sites, err := fetchNetboxSites(ctx, &http.Client{Timeout: 10 * time.Second}, cfg)
		cancel()
		if err != nil && len(s.geoSites.sites) == 0 {
			s.geoSites.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"geo_enabled": false, "reason": "fetch", "error": err.Error()})
			return
		}
		if err == nil {
			s.geoSites.sites, s.geoSites.at = sites, time.Now()
		}
	}
	sites := s.geoSites.sites
	s.geoSites.mu.Unlock()

	devices := visibleDevices(s.discovery.Devices(), claims)
	rows, unplaced := buildGeomap(sites, devices, time.Now())
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
