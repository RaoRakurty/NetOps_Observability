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
	// Source is the SoT provider that supplied this site ("internal"|"netbox"|
	// "manual"). In-memory only (drives the geo projection's evidence source); not
	// part of the /api/geomap wire response.
	Source string `json:"-"`
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

// netboxDeviceSite is the slice of /api/dcim/devices/ used to resolve which
// site each device belongs to — independent of the discovery read-back, so the
// geomap places devices even in write-only sync mode (NetBox not polled as an
// inventory source). Name/serial/primary IP let us match the live inventory by
// the same identity tokens the dedup uses.
type netboxDeviceSite struct {
	Name      string `json:"name"`
	Serial    string `json:"serial"`
	PrimaryIP *struct {
		Address string `json:"address"`
	} `json:"primary_ip"`
	Site *struct {
		Slug string `json:"slug"`
	} `json:"site"`
}

type netboxDeviceSiteResp struct {
	Next    *string            `json:"next"`
	Results []netboxDeviceSite `json:"results"`
}

// geoSiteCache memoizes the NetBox site list + device→site assignments briefly
// so a dashboard refresh doesn't turn into a NetBox request per panel.
type geoSiteCache struct {
	mu     sync.Mutex
	at     time.Time
	sites  []netboxSite
	assign map[string]string // device identity token → site slug
}

// netboxPaged GETs a paginated NetBox list endpoint with the device-source
// hardening (SR-023): token only to the configured host, pagination pinned to
// that host, bounded error bodies, hard page cap. `decode` is called per page
// with the raw body and returns the upstream `next` URL.
func netboxPaged(ctx context.Context, client *http.Client, cfg netboxConfig, path string, decode func([]byte) (string, error)) error {
	nbURL := strings.TrimRight(cfg.URL, "/")
	base, err := url.Parse(nbURL)
	if err != nil || base.Host == "" {
		return fmt.Errorf("geomap: invalid NetBox URL %q: %w", nbURL, err)
	}
	next := nbURL + path
	for pages := 0; next != "" && pages < 20; pages++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Token "+cfg.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return fmt.Errorf("netbox %s %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		upstreamNext, err := decode(body)
		if err != nil {
			return err
		}
		next = ""
		if upstreamNext != "" {
			if nu, perr := url.Parse(upstreamNext); perr == nil &&
				(nu.Scheme == "http" || nu.Scheme == "https") && strings.EqualFold(nu.Host, base.Host) {
				next = upstreamNext
			}
		}
	}
	return nil
}

// fetchNetboxSites pages through /api/dcim/sites/.
func fetchNetboxSites(ctx context.Context, client *http.Client, cfg netboxConfig) ([]netboxSite, error) {
	var out []netboxSite
	err := netboxPaged(ctx, client, cfg, "/api/dcim/sites/?limit=200", func(body []byte) (string, error) {
		var page netboxSiteResp
		if err := json.Unmarshal(body, &page); err != nil {
			return "", err
		}
		out = append(out, page.Results...)
		if page.Next != nil {
			return *page.Next, nil
		}
		return "", nil
	})
	return out, err
}

// fetchNetboxDeviceSites returns device-identity-token → site-slug, so the
// geomap can place inventory devices by their NetBox site assignment without
// relying on the discovery read-back (works in write-only sync mode).
func fetchNetboxDeviceSites(ctx context.Context, client *http.Client, cfg netboxConfig) (map[string]string, error) {
	out := map[string]string{}
	err := netboxPaged(ctx, client, cfg, "/api/dcim/devices/?limit=200", func(body []byte) (string, error) {
		var page netboxDeviceSiteResp
		if err := json.Unmarshal(body, &page); err != nil {
			return "", err
		}
		for _, d := range page.Results {
			if d.Site == nil || d.Site.Slug == "" {
				continue
			}
			for _, tok := range netboxDeviceTokens(d) {
				out[tok] = d.Site.Slug
			}
		}
		if page.Next != nil {
			return *page.Next, nil
		}
		return "", nil
	})
	return out, err
}

// netboxDeviceTokens mirrors deviceIdentities for a NetBox device record so the
// assignment map keys match the live inventory's identity tokens.
func netboxDeviceTokens(d netboxDeviceSite) []string {
	var out []string
	if d.PrimaryIP != nil {
		addr := d.PrimaryIP.Address
		if i := strings.Index(addr, "/"); i > 0 {
			addr = addr[:i]
		}
		if addr = strings.TrimSpace(addr); addr != "" {
			out = append(out, "ip:"+addr)
		}
	}
	if sn := strings.TrimSpace(d.Serial); sn != "" {
		out = append(out, "sn:"+strings.ToLower(sn))
	}
	if nm := strings.ToLower(strings.TrimSpace(d.Name)); nm != "" {
		out = append(out, "name:"+nm)
	}
	return out
}

// buildGeomap joins the site list with the visible inventory. A device's site
// is resolved with clear intent precedence: the SoT placement — its inventory
// `site` label (read/both sync mode) OR the NetBox device→site assignment map
// (write-only mode) — wins; otherwise an operator location annotation
// (`lookup`, the device_locations layer) places it, with devices sharing a
// site label folding into one bubble. Pure — unit-tested.
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
		toks := deviceIdentities(d)
		slug := d.Labels["site"]
		if slug == "" && assign != nil {
			for _, tok := range toks {
				if s, ok := assign[tok]; ok {
					slug = s
					break
				}
			}
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
// count. enabled is false (with a reason) when no intent source is configured, or
// the SoT fetch fails with nothing cached. Both /api/geomap and the executive_geo
// topology projection call this so they share one source of truth.
func (s *server) geomapResolve(ctx context.Context, claims jwtClaims) (rows []geoSite, deviceSite map[string]string, unplaced int, enabled bool, reason, errMsg string) {
	p := s.activeSoT()
	sites, err := p.Sites(ctx)
	if err != nil {
		// Only an external provider errors (e.g. NetBox unreachable, nothing
		// cached). The internal provider never errors.
		return nil, nil, 0, false, "fetch", err.Error()
	}
	assign, _ := p.DeviceSites(ctx)

	// The map renders from EITHER intent source: declared sites and/or operator
	// location annotations. Onboarding empty-state only when neither exists.
	if len(sites) == 0 && s.deviceLocations.Empty() {
		return nil, nil, 0, false, "sot", ""
	}

	devices := visibleDevices(s.discovery.Devices(), claims)
	rows, unplaced, deviceSite = buildGeomap(sites, devices, assign, s.deviceLocations.Lookup, time.Now())
	return rows, deviceSite, unplaced, true, "", ""
}

// fetch returns the NetBox site list + device→site map, memoized in geoSites
// (60s TTL). On a fetch error with nothing cached it returns the error so the
// caller can surface an honest "couldn't reach the SoT" state; with stale cache
// it returns the cache and no error.
func (p *netboxProvider) fetch(ctx context.Context) (sites []netboxSite, assign map[string]string, err error) {
	cfg := p.s.netboxCfg.effective()
	p.s.geoSites.mu.Lock()
	defer p.s.geoSites.mu.Unlock()
	if time.Since(p.s.geoSites.at) > geoSiteCacheTTL {
		fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		client := &http.Client{Timeout: 10 * time.Second}
		fetched, ferr := fetchNetboxSites(fctx, client, cfg)
		// Device→site assignments resolve placement in write-only mode (where
		// NetBox isn't read back into the inventory). Best-effort.
		fassign, aerr := fetchNetboxDeviceSites(fctx, client, cfg)
		cancel()
		if ferr != nil && len(p.s.geoSites.sites) == 0 {
			return nil, nil, ferr
		}
		if ferr == nil {
			p.s.geoSites.sites, p.s.geoSites.at = fetched, time.Now()
			if aerr == nil {
				p.s.geoSites.assign = fassign
			}
		}
	}
	return p.s.geoSites.sites, p.s.geoSites.assign, nil
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
