// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// map_topology_restriction_test.go — the CLAUDE.md §3a rule-5 isolation tests for
// the operator-visibility restriction (Tenant.OperatorRestricted) on the MAP and
// TOPOLOGY surfaces: /api/geomap, /api/devices/locations, /api/devices/{id}/location,
// /api/topology/view, /api/topology/links and the device-role index the RCA spine
// stamps through.
//
// These six surfaces all read the device registry, and each of them used to answer
// the platform operator's Global view with "the operator sees everything". Two of
// them place a restricted tenant's devices on a map WITH COORDINATES, which says
// where that tenant operates; the rest draw or classify its fabric.
//
// The geo pair has a second half the device filter does not reach: a SITE row
// carries a name and decimal lat/lng of its own, so a bubble with every device
// filtered out of it still discloses the location.
//
// The topology pair has a third: an EDGE. The device slice handed to the link
// normalizer decides which neighbours RESOLVE, so filtering the slice alone
// demotes a link that joined two tenants into an unresolved one whose target is
// "ext:<hidden hostname>" — the node disappears and the edge keeps naming it.
// TestTopologyLinksHonour... asserts the edges, not only the nodes.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/pathgraph"
	"netops/backend/topology"
)

// ── fixture ──────────────────────────────────────────────────────────────────

// restrictedMapFixture is a real server over real stores (tenant store, sites
// store, location store, device registry), so the switch under test is the
// production one and the devices/sites are keyed on the OPAQUE tenant ids the
// store mints.
type restrictedMapFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
}

// owner / acmeUser are the two principals every assertion below is made for.
func (f *restrictedMapFixture) owner() jwtClaims {
	return jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
}

func (f *restrictedMapFixture) acmeUser() jwtClaims {
	return jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
}

func (f *restrictedMapFixture) restrictAcme() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		f.t.Fatalf("restrict acme: %v", err)
	}
}

// newRestrictedMapFixture seeds two tenants plus the platform:
//
//	acme   — acme-core (nyc), acme-edge (sfo)     ← the tenant that gets restricted
//	globex — globex-core (lon)                    ← must be unmoved throughout
//	platform — stack-jump (ams), no tenant        ← must survive every filter
//
// A fix that passes by showing nothing would fail on stack-jump and globex.
func newRestrictedMapFixture(t *testing.T) *restrictedMapFixture {
	t.Helper()
	dir := t.TempDir()
	// No VictoriaMetrics in a unit test: point the metric reads at a closed port
	// so they fail fast and honestly (topology degrades to unknown health) rather
	// than spending the handler's budget on a DNS timeout.
	t.Setenv("VICTORIA_URL", "http://127.0.0.1:1")

	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}
	sites, err := newSitesStore(filepath.Join(dir, "sites.json"))
	if err != nil {
		t.Fatalf("newSitesStore: %v", err)
	}
	locs, err := newDeviceLocationStore(filepath.Join(dir, "device_locations.json"))
	if err != nil {
		t.Fatalf("newDeviceLocationStore: %v", err)
	}

	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID,
			Labels: map[string]string{"site": "nyc", "role": topology.DevRoleCoreRouter}},
		{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.2", TenantID: acme.ID,
			Labels: map[string]string{"site": "sfo", "role": topology.DevRoleWANEdge}},
		{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID,
			Labels: map[string]string{"site": "lon", "role": topology.DevRoleCoreRouter}},
		{ID: "stack-jump", Name: "stack-jump", Address: "10.9.0.1",
			Labels: map[string]string{"site": "ams", "role": topology.DevRoleWANEdge}},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("upsert %s: %v", dev.ID, err)
		}
	}

	// Declared sites, each stamped with its owner exactly as the HTTP boundary
	// stamps it from the authenticated principal.
	for _, st := range []Site{
		{TenantID: acme.ID, Slug: "nyc", Name: "New York", Lat: 40.71, Lng: -74.01, HasCoords: true},
		{TenantID: acme.ID, Slug: "sfo", Name: "San Francisco", Lat: 37.77, Lng: -122.42, HasCoords: true},
		{TenantID: globex.ID, Slug: "lon", Name: "London", Lat: 51.51, Lng: -0.13, HasCoords: true},
		{Slug: "ams", Name: "Amsterdam", Lat: 52.37, Lng: 4.9, HasCoords: true}, // platform-owned
	} {
		if _, err := sites.Upsert(st); err != nil {
			t.Fatalf("upsert site %s: %v", st.Slug, err)
		}
	}

	s := &server{discovery: d, tenants: ts, roles: roles, sites: sites, deviceLocations: locs}
	s.alerts = alerts.NewEngine("", nil)

	// An operator-typed location on acme-core, so the by-id location route has
	// real coordinates to leak (the GET answers with them).
	dev, ok := d.Get("acme-core")
	if !ok {
		t.Fatal("fixture: acme-core is not in the registry")
	}
	if err := locs.Upsert(discovery.DeviceIdentities(dev), DeviceLocation{
		Device: "acme-core", Site: "nyc-dc1", Lat: 40.72, Lng: -74.0,
	}); err != nil {
		t.Fatalf("upsert acme-core location: %v", err)
	}

	return &restrictedMapFixture{t: t, s: s, acme: acme.ID, globex: globex.ID}
}

// get runs one real GET through a handler and returns the decoded body. A
// non-200 is fatal — every assertion here is about CONTENT, so a handler that
// refused would silently "pass" a leak test.
func (f *restrictedMapFixture) get(h http.HandlerFunc, path string, claims jwtClaims, out any) {
	f.t.Helper()
	w := httptest.NewRecorder()
	h(w, req(http.MethodGet, path, "", claims))
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET %s = %d (%s)", path, w.Code, w.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			f.t.Fatalf("decode %s: %v (%s)", path, err, w.Body.String())
		}
	}
}

// asTenant is the ?as_tenant= half. The switcher's override is applied by the
// auth middleware (withActingTenant) and arrives at a handler as ActingTenant on
// the claims, so a handler-level test carries it the same way the template does
// — the narrowing itself is covered by acting_tenant_test.go.
func (f *restrictedMapFixture) asTenant(h http.HandlerFunc, path, tenantID string, out any) {
	f.t.Helper()
	f.get(h, path, ownerActing(f.owner(), tenantID), out)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// tiny, deterministic: the sets here are single digits
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// ── /api/geomap ──────────────────────────────────────────────────────────────

type geomapResp struct {
	GeoEnabled bool `json:"geo_enabled"`
	Sites      []struct {
		Slug    string  `json:"slug"`
		Name    string  `json:"name"`
		Lat     float64 `json:"lat"`
		Lng     float64 `json:"lng"`
		Devices int     `json:"devices"`
	} `json:"sites"`
	Placed int `json:"placed"`
}

func (g geomapResp) slugs() map[string]bool {
	out := map[string]bool{}
	for _, s := range g.Sites {
		out[s.Slug] = true
	}
	return out
}

// TestGeomapHonoursTheOperatorVisibilityRestriction — the map bubble is the
// sharpest disclosure in the product: a site name and decimal coordinates.
func TestGeomapHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedMapFixture(t)

	// Baseline: four bubbles, four placed devices. Without this the assertions
	// below could pass on a map that always renders empty.
	var base geomapResp
	f.get(f.s.handleGeomap, "/api/geomap", f.owner(), &base)
	if got := base.slugs(); len(got) != 4 || !got["nyc"] || !got["sfo"] || !got["lon"] || !got["ams"] || base.Placed != 4 {
		t.Fatalf("baseline Global geomap = %v placed=%d, want the four sites and 4 placed — the fixture does not reach the handler",
			sortedKeys(got), base.Placed)
	}
	// acme's OWN map, captured BEFORE the switch so the guard below compares
	// against a number this test measured rather than one it assumed.
	var acmeBefore geomapResp
	f.get(f.s.handleGeomap, "/api/geomap", f.acmeUser(), &acmeBefore)
	if got := acmeBefore.slugs(); len(got) != 2 || !got["nyc"] || !got["sfo"] || acmeBefore.Placed != 2 {
		t.Fatalf("acme's own geomap = %v placed=%d, want nyc+sfo and 2 placed", sortedKeys(got), acmeBefore.Placed)
	}

	f.restrictAcme()

	// ── half 1: the Global view. acme's bubbles AND its devices leave the map.
	var global geomapResp
	f.get(f.s.handleGeomap, "/api/geomap", f.owner(), &global)
	got := global.slugs()
	if got["nyc"] || got["sfo"] {
		for _, s := range global.Sites {
			if s.Slug == "nyc" || s.Slug == "sfo" {
				t.Errorf("RESTRICTION LEAK: the Global geomap still plots the restricted tenant's site %q (%s) at %.2f,%.2f with %d device(s) — "+
					"a bubble with its devices filtered out still says WHERE acme operates.", s.Slug, s.Name, s.Lat, s.Lng, s.Devices)
			}
		}
	}
	if !got["lon"] || !got["ams"] {
		t.Errorf("the Global geomap lost globex's or the platform's site: %v — restricting acme must not empty the map", sortedKeys(got))
	}
	if global.Placed != 2 {
		t.Errorf("RESTRICTION LEAK: the Global geomap places %d devices, want 2 (globex-core + stack-jump) — "+
			"it is still counting acme-core and acme-edge into its bubbles.", global.Placed)
	}

	// ── half 2: the owner walks in with as_tenant=acme. Nothing is plotted.
	var scoped geomapResp
	f.asTenant(f.s.handleGeomap, "/api/geomap", f.acme, &scoped)
	if n := len(scoped.Sites); n != 0 || scoped.Placed != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme plotted %d site(s) (%v) and %d device(s) — "+
			"an operator scoped into a restricted tenant may read none of its placement.",
			n, sortedKeys(scoped.slugs()), scoped.Placed)
	}

	// ── the owner scoped into the UNRESTRICTED tenant still sees it whole.
	var gscoped geomapResp
	f.asTenant(f.s.handleGeomap, "/api/geomap", f.globex, &gscoped)
	if s := gscoped.slugs(); len(s) != 1 || !s["lon"] || gscoped.Placed != 1 {
		t.Errorf("as_tenant=globex geomap = %v placed=%d, want lon and 1 — restricting acme must not change globex",
			sortedKeys(s), gscoped.Placed)
	}

	// ── acme's OWN map is unchanged: the switch hides a tenant from the
	//    PLATFORM, never from itself.
	var acmeAfter geomapResp
	f.get(f.s.handleGeomap, "/api/geomap", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.slugs(), acmeAfter.slugs()) || acmeBefore.Placed != acmeAfter.Placed {
		t.Errorf("acme's own geomap changed when acme restricted itself: %v placed=%d → %v placed=%d",
			sortedKeys(acmeBefore.slugs()), acmeBefore.Placed, sortedKeys(acmeAfter.slugs()), acmeAfter.Placed)
	}
}

// ── /api/devices/locations + /api/devices/{id}/location ──────────────────────

type locationsResp struct {
	Devices []struct {
		ID   string  `json:"id"`
		Name string  `json:"name"`
		Site string  `json:"site"`
		Lat  float64 `json:"lat"`
		Lng  float64 `json:"lng"`
	} `json:"devices"`
}

func (l locationsResp) ids() map[string]bool {
	out := map[string]bool{}
	for _, d := range l.Devices {
		out[d.ID] = true
	}
	return out
}

// locationStatus runs the by-id route and returns its status code.
func (f *restrictedMapFixture) locationStatus(deviceID string, claims jwtClaims) int {
	f.t.Helper()
	path := "/api/devices/" + deviceID + "/location"
	w := httptest.NewRecorder()
	f.s.handleDeviceLocation(w, req(http.MethodGet, path, "", claims))
	return w.Code
}

// TestDeviceLocationsHonourTheOperatorVisibilityRestriction covers BOTH location
// routes: the editor list and the by-id read, which returns the coordinates an
// operator typed for one named device.
func TestDeviceLocationsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedMapFixture(t)

	var base locationsResp
	f.get(f.s.handleDeviceLocations, "/api/devices/locations", f.owner(), &base)
	if ids := base.ids(); len(ids) != 4 || !ids["acme-core"] || !ids["stack-jump"] {
		t.Fatalf("baseline Global locations = %v, want all four devices — the fixture does not reach the handler", sortedKeys(ids))
	}
	var acmeBefore locationsResp
	f.get(f.s.handleDeviceLocations, "/api/devices/locations", f.acmeUser(), &acmeBefore)
	if ids := acmeBefore.ids(); len(ids) != 2 || !ids["acme-core"] || !ids["acme-edge"] {
		t.Fatalf("acme's own locations = %v, want its own two devices", sortedKeys(ids))
	}
	if code := f.locationStatus("acme-core", f.owner()); code != http.StatusOK {
		t.Fatalf("baseline GET /api/devices/acme-core/location = %d, want 200", code)
	}

	f.restrictAcme()

	// ── half 1: the Global list.
	var global locationsResp
	f.get(f.s.handleDeviceLocations, "/api/devices/locations", f.owner(), &global)
	ids := global.ids()
	if ids["acme-core"] || ids["acme-edge"] {
		for _, d := range global.Devices {
			if d.ID == "acme-core" || d.ID == "acme-edge" {
				t.Errorf("RESTRICTION LEAK: the Global location editor still lists the restricted tenant's %q at site %q (%.2f,%.2f)",
					d.Name, d.Site, d.Lat, d.Lng)
			}
		}
	}
	if len(ids) != 2 || !ids["globex-core"] || !ids["stack-jump"] {
		t.Errorf("the Global location editor = %v, want globex-core + stack-jump", sortedKeys(ids))
	}

	// ── half 1 again, by id: reading ONE restricted device's coordinates is a
	//    404 — the same answer another tenant's id gets, never a 403 (§3a).
	if code := f.locationStatus("acme-core", f.owner()); code != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: GET /api/devices/acme-core/location in the Global view = %d, want 404 — "+
			"it is handing the operator the coordinates typed for a restricted tenant's device.", code)
	}
	if code := f.locationStatus("globex-core", f.owner()); code != http.StatusOK {
		t.Errorf("GET /api/devices/globex-core/location = %d, want 200 — restricting acme must not change globex", code)
	}

	// ── half 2: as_tenant=acme.
	var scoped locationsResp
	f.asTenant(f.s.handleDeviceLocations, "/api/devices/locations", f.acme, &scoped)
	if n := len(scoped.Devices); n != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme listed %d device location(s): %v", n, sortedKeys(scoped.ids()))
	}
	if code := f.locationStatus("acme-core", ownerActing(f.owner(), f.acme)); code != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme GET /api/devices/acme-core/location = %d, want 404", code)
	}

	// ── the unrestricted tenant is unmoved.
	var gscoped locationsResp
	f.asTenant(f.s.handleDeviceLocations, "/api/devices/locations", f.globex, &gscoped)
	if ids := gscoped.ids(); len(ids) != 1 || !ids["globex-core"] {
		t.Errorf("as_tenant=globex locations = %v, want globex-core only", sortedKeys(ids))
	}

	// ── acme's own access is undamaged.
	var acmeAfter locationsResp
	f.get(f.s.handleDeviceLocations, "/api/devices/locations", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.ids(), acmeAfter.ids()) {
		t.Errorf("acme's own location editor changed when acme restricted itself: %v → %v",
			sortedKeys(acmeBefore.ids()), sortedKeys(acmeAfter.ids()))
	}
	if code := f.locationStatus("acme-core", f.acmeUser()); code != http.StatusOK {
		t.Errorf("acme's own operator lost its own device location: %d", code)
	}
}

// ── /api/topology/view + /api/topology/links ─────────────────────────────────

// fakeTopologyCollector stands up a minimal RESP server on loopback and points
// the collector client at it, so the link surfaces run on REAL published LLDP
// records rather than the empty set an absent collector returns. Without it the
// edge half of the rule cannot be asserted at all.
func fakeTopologyCollector(t *testing.T, byKey map[string]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("close fake collector listener: %v", err)
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed by cleanup
			}
			go serveFakeRESP(c, byKey)
		}
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", ln.Addr(), err)
	}
	t.Setenv("REDIS_HOST", host)
	t.Setenv("REDIS_PORT", port)
}

// serveFakeRESP answers GET with the configured payload and a nil bulk for every
// other key. It speaks only the sliver of RESP the collector client uses.
func serveFakeRESP(c net.Conn, byKey map[string]string) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}
		if len(args) == 2 && strings.EqualFold(args[0], "GET") {
			if v, ok := byKey[args[1]]; ok {
				if _, err := fmt.Fprintf(c, "$%d\r\n%s\r\n", len(v), v); err != nil {
					return
				}
				continue
			}
		}
		if _, err := io.WriteString(c, "$-1\r\n"); err != nil {
			return
		}
	}
}

// readRESPCommand reads one "*N / $len payload" array — the only shape the
// collector client ever sends.
func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("fake redis: unexpected frame %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, fmt.Errorf("fake redis: bad array length %q: %w", line, err)
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, fmt.Errorf("fake redis: unexpected bulk header %q", hdr)
		}
		ln, err := strconv.Atoi(hdr[1:])
		if err != nil {
			return nil, fmt.Errorf("fake redis: bad bulk length %q: %w", hdr, err)
		}
		buf := make([]byte, ln+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:ln]))
	}
	return args, nil
}

// seedTopologyLinks publishes the LLDP adjacency set the two topology tests read:
//
//	globex-core ─ acme-core   a link that JOINS the two tenants (the edge case)
//	acme-core   ─ acme-edge   wholly inside the restricted tenant
//	globex-core ─ stack-jump  visible ↔ platform-owned: must survive
//	globex-core ─ isp-router  a genuine EXTERNAL neighbour: must survive
func seedTopologyLinks(t *testing.T) {
	t.Helper()
	now := time.Now().UnixMilli()
	type nb struct {
		LocalDevice string `json:"local_device"`
		LocalPort   string `json:"local_port"`
		RemSysName  string `json:"rem_sysname"`
		RemChassis  string `json:"rem_chassis"`
		RemPort     string `json:"rem_port"`
		Proto       string `json:"proto"`
		TS          int64  `json:"ts"`
	}
	payload, err := json.Marshal([]nb{
		{LocalDevice: "globex-core", LocalPort: "Et1", RemSysName: "acme-core", RemChassis: "10.1.0.1", RemPort: "Et9", Proto: "lldp", TS: now},
		{LocalDevice: "acme-core", LocalPort: "Et2", RemSysName: "acme-edge", RemChassis: "10.1.0.2", RemPort: "Et1", Proto: "lldp", TS: now},
		{LocalDevice: "globex-core", LocalPort: "Et3", RemSysName: "stack-jump", RemChassis: "10.9.0.1", RemPort: "Et1", Proto: "lldp", TS: now},
		{LocalDevice: "globex-core", LocalPort: "Et4", RemSysName: "isp-router", RemChassis: "203.0.113.9", RemPort: "ge-0/0/0", Proto: "lldp", TS: now},
	})
	if err != nil {
		t.Fatalf("marshal neighbours: %v", err)
	}
	fakeTopologyCollector(t, map[string]string{"netops:topology:lldp": string(payload)})
}

type linksResp struct {
	Links []struct {
		Source     string `json:"source"`
		Target     string `json:"target"`
		SourceName string `json:"source_name"`
		TargetName string `json:"target_name"`
		Resolved   bool   `json:"resolved"`
	} `json:"links"`
	Count int `json:"count"`
}

// endpoints renders the link set as "source→target" strings — the assertion
// names the leaked device instead of a count that moved.
func (l linksResp) endpoints() map[string]bool {
	out := map[string]bool{}
	for _, k := range l.Links {
		out[k.Source+"→"+k.Target] = true
	}
	return out
}

// namesAcme reports whether any endpoint of any link identifies an acme device.
func (l linksResp) namesAcme() []string {
	var hits []string
	for _, k := range l.Links {
		for _, v := range []string{k.Source, k.Target, k.SourceName, k.TargetName} {
			if strings.Contains(strings.ToLower(v), "acme") {
				hits = append(hits, k.Source+"→"+k.Target+" ("+v+")")
				break
			}
		}
	}
	return hits
}

// TestTopologyLinksHonourTheOperatorVisibilityRestriction is the EDGE half.
// Filtering the device slice is not enough here: a link that joined the two
// tenants survives as an unresolved edge whose target is "ext:acme-core".
func TestTopologyLinksHonourTheOperatorVisibilityRestriction(t *testing.T) {
	seedTopologyLinks(t)
	f := newRestrictedMapFixture(t)

	var base linksResp
	f.get(f.s.handleTopologyLinks, "/api/topology/links", f.owner(), &base)
	if base.Count != 4 {
		t.Fatalf("baseline Global links = %d (%v), want 4 — the fake collector is not reaching the handler",
			base.Count, sortedKeys(base.endpoints()))
	}
	var acmeBefore linksResp
	f.get(f.s.handleTopologyLinks, "/api/topology/links", f.acmeUser(), &acmeBefore)
	if acmeBefore.Count != 1 {
		t.Fatalf("acme's own links = %d (%v), want 1 (acme-core↔acme-edge)", acmeBefore.Count, sortedKeys(acmeBefore.endpoints()))
	}

	f.restrictAcme()

	// ── half 1: the Global view. NO link may name an acme device — neither as a
	//    resolved endpoint nor as an "ext:" neighbour.
	var global linksResp
	f.get(f.s.handleTopologyLinks, "/api/topology/links", f.owner(), &global)
	if hits := global.namesAcme(); len(hits) != 0 {
		t.Errorf("RESTRICTION LEAK: the Global topology link set still names the restricted tenant's devices: %v. "+
			"Dropping acme's devices from the inventory only demoted the cross-tenant link to an UNRESOLVED one — "+
			"the node is gone and the edge still carries the hostname.", hits)
	}
	eps := global.endpoints()
	if !eps["globex-core→stack-jump"] || !eps["globex-core→ext:isp-router"] {
		t.Errorf("the Global link set lost a link it must keep: %v — the platform link and the genuinely external "+
			"neighbour are not the restricted tenant's.", sortedKeys(eps))
	}
	if global.Count != 2 {
		t.Errorf("Global links = %d (%v), want 2", global.Count, sortedKeys(eps))
	}

	// ── half 2: as_tenant=acme sees no adjacency at all.
	var scoped linksResp
	f.asTenant(f.s.handleTopologyLinks, "/api/topology/links", f.acme, &scoped)
	if scoped.Count != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme returned %d link(s): %v", scoped.Count, sortedKeys(scoped.endpoints()))
	}

	// ── the unrestricted tenant is unmoved — and this is the one place the rule
	//    deliberately stops. Scoped into globex the operator sees EXACTLY what
	//    globex's own operator sees, which includes "ext:acme-core": an
	//    unresolved neighbour hostname is globex's OWN LLDP observation (acme's
	//    device advertised it to globex's port), not a row read out of acme's
	//    tenant. The shared resolver says the same thing everywhere else — scoped
	//    into a non-restricted tenant, the restriction is a no-op — and a view
	//    that differed from the tenant's own would be a different feature. The
	//    Global assertion above is where the operator is denied it.
	var gscoped linksResp
	f.asTenant(f.s.handleTopologyLinks, "/api/topology/links", f.globex, &gscoped)
	var globexOwn linksResp
	f.get(f.s.handleTopologyLinks, "/api/topology/links", jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: f.globex}, &globexOwn)
	if !sameSet(gscoped.endpoints(), globexOwn.endpoints()) {
		t.Errorf("as_tenant=globex links = %v, want exactly globex's own view %v",
			sortedKeys(gscoped.endpoints()), sortedKeys(globexOwn.endpoints()))
	}
	if eps := gscoped.endpoints(); !eps["globex-core→ext:isp-router"] {
		t.Errorf("as_tenant=globex lost globex's own external adjacency: %v", sortedKeys(eps))
	}

	// ── acme's own fabric is unchanged.
	var acmeAfter linksResp
	f.get(f.s.handleTopologyLinks, "/api/topology/links", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.endpoints(), acmeAfter.endpoints()) {
		t.Errorf("acme's own link set changed when acme restricted itself: %v → %v",
			sortedKeys(acmeBefore.endpoints()), sortedKeys(acmeAfter.endpoints()))
	}
}

type viewResp struct {
	Nodes []topology.Node `json:"nodes"`
	Edges []topology.Edge `json:"edges"`
}

func (v viewResp) nodeIDs() map[string]bool {
	out := map[string]bool{}
	for _, n := range v.Nodes {
		out[n.ID] = true
	}
	return out
}

func (v viewResp) edgeIDs() map[string]bool {
	out := map[string]bool{}
	for _, e := range v.Edges {
		out[e.Source+"→"+e.Target] = true
	}
	return out
}

// TestTopologyViewHonoursTheOperatorVisibilityRestriction — the canvas draws a
// node per device and an edge per adjacency; both must lose the restricted
// tenant, including the unresolved node an unfiltered edge would materialize.
func TestTopologyViewHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	seedTopologyLinks(t)
	f := newRestrictedMapFixture(t)

	var base viewResp
	f.get(f.s.handleTopologyView, "/api/topology/view?mode=explore", f.owner(), &base)
	ids := base.nodeIDs()
	if len(ids) != 5 || !ids["acme-core"] || !ids["acme-edge"] || !ids["ext:isp-router"] {
		t.Fatalf("baseline Global view nodes = %v, want the four devices plus ext:isp-router", sortedKeys(ids))
	}
	var acmeBefore viewResp
	f.get(f.s.handleTopologyView, "/api/topology/view?mode=explore", f.acmeUser(), &acmeBefore)
	if n := len(acmeBefore.nodeIDs()); n != 2 {
		t.Fatalf("acme's own view nodes = %v, want its own two devices", sortedKeys(acmeBefore.nodeIDs()))
	}

	f.restrictAcme()

	// ── half 1: the Global canvas.
	var global viewResp
	f.get(f.s.handleTopologyView, "/api/topology/view?mode=explore", f.owner(), &global)
	gids := global.nodeIDs()
	for id := range gids {
		if strings.Contains(strings.ToLower(id), "acme") {
			t.Errorf("RESTRICTION LEAK: the Global topology canvas still draws node %q — "+
				"an unfiltered edge to a hidden device materializes it as an unresolved node carrying its hostname.", id)
		}
	}
	for id := range global.edgeIDs() {
		if strings.Contains(strings.ToLower(id), "acme") {
			t.Errorf("RESTRICTION LEAK: the Global topology canvas still draws edge %q", id)
		}
	}
	if len(gids) != 3 || !gids["globex-core"] || !gids["stack-jump"] || !gids["ext:isp-router"] {
		t.Errorf("Global view nodes = %v, want globex-core + stack-jump + ext:isp-router", sortedKeys(gids))
	}

	// ── half 2: as_tenant=acme draws nothing.
	var scoped viewResp
	f.asTenant(f.s.handleTopologyView, "/api/topology/view?mode=explore", f.acme, &scoped)
	if n := len(scoped.Nodes); n != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme drew %d node(s): %v", n, sortedKeys(scoped.nodeIDs()))
	}
	if n := len(scoped.Edges); n != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme drew %d edge(s): %v", n, sortedKeys(scoped.edgeIDs()))
	}

	// ── the unrestricted tenant is unmoved.
	var gscoped viewResp
	f.asTenant(f.s.handleTopologyView, "/api/topology/view?mode=explore", f.globex, &gscoped)
	if ids := gscoped.nodeIDs(); !ids["globex-core"] {
		t.Errorf("as_tenant=globex lost its own node: %v", sortedKeys(ids))
	}

	// ── acme's own canvas is unchanged.
	var acmeAfter viewResp
	f.get(f.s.handleTopologyView, "/api/topology/view?mode=explore", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.nodeIDs(), acmeAfter.nodeIDs()) || !sameSet(acmeBefore.edgeIDs(), acmeAfter.edgeIDs()) {
		t.Errorf("acme's own canvas changed when acme restricted itself: nodes %v → %v, edges %v → %v",
			sortedKeys(acmeBefore.nodeIDs()), sortedKeys(acmeAfter.nodeIDs()),
			sortedKeys(acmeBefore.edgeIDs()), sortedKeys(acmeAfter.edgeIDs()))
	}
}

// ── the device-role index (RCA spine stamping) ───────────────────────────────

// TestDeviceRoleIndexHonoursTheOperatorVisibilityRestriction. The role index has
// no route of its own — it is stamped onto the RCA timeline's §7 spine — so the
// test drives the index and the stamping function that consumes it. A stamped
// role is an assertion that the hop IS one of our managed devices: stamping a
// restricted tenant's device confirms its fleet to an operator who may not read it.
func TestDeviceRoleIndexHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedMapFixture(t)
	ctx := t.Context()

	spine := func() []pathgraph.SpineNode {
		return []pathgraph.SpineNode{
			{EntityRef: "acme-core", Address: "10.1.0.1", Label: "acme-core"},
			{EntityRef: "globex-core", Address: "10.2.0.1", Label: "globex-core"},
		}
	}

	base := f.s.deviceRoleIndex(ctx, f.owner())
	if base["acme-core"].Role != topology.DevRoleCoreRouter || base["globex-core"].Role != topology.DevRoleCoreRouter {
		t.Fatalf("baseline Global role index = %v, want both cores classified — the fixture does not reach the classifier",
			sortedKeys(roleKeys(base)))
	}
	acmeBefore := roleKeys(f.s.deviceRoleIndex(ctx, f.acmeUser()))

	f.restrictAcme()

	// ── half 1: the Global index no longer knows acme's devices, by ANY of the
	//    three identities a spine hop resolves through (id, name, address).
	global := f.s.deviceRoleIndex(ctx, f.owner())
	for _, k := range []string{"acme-core", "acme-edge", "10.1.0.1", "10.1.0.2"} {
		if rr, ok := global[k]; ok {
			t.Errorf("RESTRICTION LEAK: the Global role index still classifies %q as %q (%s) — "+
				"stamping that on an RCA hop confirms the restricted tenant's device is one of ours.", k, rr.Role, rr.Confidence)
		}
	}
	if global["globex-core"].Role != topology.DevRoleCoreRouter || global["stack-jump"].Role != topology.DevRoleWANEdge {
		t.Errorf("the Global role index lost globex's or the platform's device: %v", sortedKeys(roleKeys(global)))
	}

	// ── and the spine that consumes it: acme's hop stays role-less, globex's is
	//    stamped as before.
	hops := spine()
	stampSpineRoles(hops, global)
	if hops[0].DeviceRole != "" {
		t.Errorf("RESTRICTION LEAK: the RCA spine stamped the restricted tenant's hop as %q (%s)",
			hops[0].DeviceRole, hops[0].RoleConfidence)
	}
	if hops[1].DeviceRole != topology.DevRoleCoreRouter {
		t.Errorf("the RCA spine lost globex's role stamp: %q", hops[1].DeviceRole)
	}

	// ── half 2: as_tenant=acme classifies nothing.
	if idx := f.s.deviceRoleIndex(ctx, ownerActing(f.owner(), f.acme)); len(idx) != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme role index = %v, want empty", sortedKeys(roleKeys(idx)))
	}

	// ── the unrestricted tenant is unmoved.
	if idx := f.s.deviceRoleIndex(ctx, ownerActing(f.owner(), f.globex)); idx["globex-core"].Role != topology.DevRoleCoreRouter {
		t.Errorf("as_tenant=globex role index = %v, want globex-core classified", sortedKeys(roleKeys(idx)))
	}

	// ── acme's own index is unchanged.
	if after := roleKeys(f.s.deviceRoleIndex(ctx, f.acmeUser())); !sameSet(acmeBefore, after) {
		t.Errorf("acme's own role index changed when acme restricted itself: %v → %v",
			sortedKeys(acmeBefore), sortedKeys(after))
	}
}

func roleKeys(idx map[string]topology.RoleResult) map[string]bool {
	out := map[string]bool{}
	for k := range idx {
		out[k] = true
	}
	return out
}

// ── /api/topology/graph (the PERSISTED spine) ────────────────────────────────

// seedPersistedGraph gives the fixture a reconciled graph: a node per device and
// the adjacencies the reconciler would have stored. The reconciler resolves links
// PER TENANT, so the cross-tenant one is stored under globex with the target
// "ext:acme-core" — which is the row that proves tenant_id filtering alone is not
// enough here either.
func (f *restrictedMapFixture) seedPersistedGraph() {
	f.t.Helper()
	store := topology.NewMemStore()
	f.s.topology = store
	if err := store.ReplaceAll(context.Background(), topology.GraphRecords{
		Nodes: []topology.NodeRecord{
			{TenantID: f.acme, ID: "acme-core", Label: "acme-core", MgmtIP: "10.1.0.1", Site: "nyc"},
			{TenantID: f.acme, ID: "acme-edge", Label: "acme-edge", MgmtIP: "10.1.0.2", Site: "sfo"},
			{TenantID: f.globex, ID: "globex-core", Label: "globex-core", MgmtIP: "10.2.0.1", Site: "lon"},
			{ID: "stack-jump", Label: "stack-jump", MgmtIP: "10.9.0.1", Site: "ams"},
		},
		Edges: []topology.EdgeRecord{
			{TenantID: f.acme, ID: "e-acme", Source: "acme-core", Target: "acme-edge", Resolved: true},
			{TenantID: f.globex, ID: "e-x", Source: "globex-core", Target: "ext:acme-core"},
			{TenantID: f.globex, ID: "e-jump", Source: "globex-core", Target: "ext:stack-jump"},
		},
	}); err != nil {
		f.t.Fatalf("seed persisted graph: %v", err)
	}
}

type graphResp struct {
	Nodes    []topology.Node   `json:"nodes"`
	Edges    []topology.Edge   `json:"edges"`
	Coverage topology.Coverage `json:"coverage"`
}

func (g graphResp) nodeIDs() map[string]bool {
	out := map[string]bool{}
	for _, n := range g.Nodes {
		out[n.ID] = true
	}
	return out
}

func (g graphResp) edgeIDs() map[string]bool {
	out := map[string]bool{}
	for _, e := range g.Edges {
		out[e.Source+"→"+e.Target] = true
	}
	return out
}

// TestTopologyGraphHonoursTheOperatorVisibilityRestriction — the persisted spine
// is the canvas's OTHER data source. Its store isolates tenant from tenant (the
// in-memory backend by tenant_id, the pg backend by FORCE-RLS), but the
// operator's cross-tenant door is "all", and neither a row policy nor
// FilterTenant has an "all except".
func TestTopologyGraphHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedMapFixture(t)
	f.seedPersistedGraph()

	var base graphResp
	f.get(f.s.handleTopologyGraph, "/api/topology/graph", f.owner(), &base)
	if ids := base.nodeIDs(); len(ids) != 4 || !ids["acme-core"] || base.Coverage.Nodes != 4 || base.Coverage.Edges != 3 {
		t.Fatalf("baseline Global graph = nodes %v coverage %+v, want all four nodes and 3 edges — the fixture does not reach the handler",
			sortedKeys(ids), base.Coverage)
	}
	var acmeBefore graphResp
	f.get(f.s.handleTopologyGraph, "/api/topology/graph", f.acmeUser(), &acmeBefore)
	if ids := acmeBefore.nodeIDs(); len(ids) != 2 {
		t.Fatalf("acme's own persisted graph = %v, want its own two nodes", sortedKeys(ids))
	}

	f.restrictAcme()

	// ── half 1: the Global view — nodes, EDGES and the coverage counts.
	var global graphResp
	f.get(f.s.handleTopologyGraph, "/api/topology/graph", f.owner(), &global)
	for id := range global.nodeIDs() {
		if strings.Contains(strings.ToLower(id), "acme") {
			t.Errorf("RESTRICTION LEAK: the persisted Global graph still carries node %q", id)
		}
	}
	for id := range global.edgeIDs() {
		if strings.Contains(strings.ToLower(id), "acme") {
			t.Errorf("RESTRICTION LEAK: the persisted Global graph still carries edge %q — the reconciler stores a "+
				"cross-tenant adjacency under the VISIBLE tenant with the hidden hostname as its target, so filtering "+
				"by tenant_id alone keeps it.", id)
		}
	}
	if ids := global.nodeIDs(); len(ids) != 2 || !ids["globex-core"] || !ids["stack-jump"] {
		t.Errorf("persisted Global graph nodes = %v, want globex-core + stack-jump", sortedKeys(ids))
	}
	if global.Coverage.Nodes != 2 || global.Coverage.Edges != 1 {
		t.Errorf("RESTRICTION LEAK: persisted Global coverage = %+v, want 2 nodes / 1 edge — a count is a disclosure.", global.Coverage)
	}

	// ── half 2: as_tenant=acme reads nothing.
	var scoped graphResp
	f.asTenant(f.s.handleTopologyGraph, "/api/topology/graph", f.acme, &scoped)
	if len(scoped.Nodes) != 0 || len(scoped.Edges) != 0 || scoped.Coverage.Nodes != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme persisted graph = nodes %v edges %v coverage %+v",
			sortedKeys(scoped.nodeIDs()), sortedKeys(scoped.edgeIDs()), scoped.Coverage)
	}

	// ── the unrestricted tenant is unmoved: scoped into globex the operator sees
	//    exactly globex's own rows, ext: neighbour included (same reasoning as the
	//    live link set — that target is globex's own stored observation).
	var gscoped graphResp
	f.asTenant(f.s.handleTopologyGraph, "/api/topology/graph", f.globex, &gscoped)
	var globexOwn graphResp
	f.get(f.s.handleTopologyGraph, "/api/topology/graph", jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: f.globex}, &globexOwn)
	if !sameSet(gscoped.nodeIDs(), globexOwn.nodeIDs()) || !sameSet(gscoped.edgeIDs(), globexOwn.edgeIDs()) {
		t.Errorf("as_tenant=globex persisted graph = %v/%v, want exactly globex's own %v/%v",
			sortedKeys(gscoped.nodeIDs()), sortedKeys(gscoped.edgeIDs()),
			sortedKeys(globexOwn.nodeIDs()), sortedKeys(globexOwn.edgeIDs()))
	}

	// ── acme's own persisted graph is unchanged.
	var acmeAfter graphResp
	f.get(f.s.handleTopologyGraph, "/api/topology/graph", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.nodeIDs(), acmeAfter.nodeIDs()) || !sameSet(acmeBefore.edgeIDs(), acmeAfter.edgeIDs()) {
		t.Errorf("acme's own persisted graph changed when acme restricted itself: %v/%v → %v/%v",
			sortedKeys(acmeBefore.nodeIDs()), sortedKeys(acmeBefore.edgeIDs()),
			sortedKeys(acmeAfter.nodeIDs()), sortedKeys(acmeAfter.edgeIDs()))
	}
}
