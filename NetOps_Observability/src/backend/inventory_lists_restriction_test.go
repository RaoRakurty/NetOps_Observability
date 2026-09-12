// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// inventory_lists_restriction_test.go — the CLAUDE.md §3a rule-5 isolation tests
// for the operator-visibility restriction (Tenant.OperatorRestricted) on the
// INVENTORY LISTS: the global omnibox, GET /api/devices (wired AND wireless),
// GET /api/sites (plus the by-slug read and the geomap's resolvable-slug set),
// GET /api/compliance, GET /api/vulns and the device_sites import's resolver.
//
// The dashboard's Devices and Sites tiles were closed in e214dfc7 by folding the
// rule into a registry chokepoint (deviceVisibility / visibleDevicesFor). The
// LISTS those tiles are the headline number for were not, so the platform
// operator could read "Devices: 3" on the dashboard and then page through six
// rows on the Devices tab — which is worse than never having filtered the tile,
// because the delta names exactly what is being hidden.
//
// Every test here asserts the same five things the tile test asserts:
//   - a baseline, so the test cannot pass by returning nothing;
//   - half 1, the Global (cross-tenant) view EXCLUDES the restricted tenant;
//   - half 2, an as_tenant walk into the restricted tenant is DENIED;
//   - an unrestricted tenant, and the platform-owned object, are unmoved;
//   - the restricted tenant's OWN view is unchanged — captured before the
//     switch and compared after. The switch hides a tenant from the PLATFORM,
//     never from itself.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/vuln"
	"netops/backend/models"
	"netops/backend/wireless"
)

// The identifiers that must never cross into the operator's view. Named so an
// assertion can say WHICH row leaked.
const (
	acmeEdgeID   = "acme-edge"   // acme's second device: vendor + OS, so it is assessable
	globexEdgeID = "globex-edge" // the unrestricted comparison
	stackJumpID  = "stack-jump"  // platform-owned: must survive every filter
	acmeSiteSlug = "acme-nyc"    // a site name is where a customer operates
	acmeWLCID    = "acme-wlc"    // wireless controller: the other half of /api/devices
)

// listFixture extends the alert lane's fixture (a REAL tenant store, a REAL
// binding store, so the switch under test is the production one) with the stores
// the inventory lists read: roles (requirePerm), saved objects (the omnibox),
// declared sites, device→site bindings, the wireless inventory and a vuln feed.
type listFixture struct {
	*restrictedAlertFixture
}

func newListFixture(t *testing.T) *listFixture {
	t.Helper()
	f := newRestrictedAlertFixture(t)
	dir := t.TempDir()

	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	sv, err := newSavedStore(filepath.Join(dir, "saved.json"))
	if err != nil {
		t.Fatalf("savedStore: %v", err)
	}
	sites, err := newSitesStore(filepath.Join(dir, "sites.json"))
	if err != nil {
		t.Fatalf("sitesStore: %v", err)
	}
	ds, err := newDeviceSiteStore(filepath.Join(dir, "device_sites.json"))
	if err != nil {
		t.Fatalf("deviceSiteStore: %v", err)
	}
	f.s.roles, f.s.saved, f.s.sites, f.s.deviceSites = roles, sv, sites, ds
	f.s.wireless = wireless.NewMemStore()

	// A vuln feed with one CVE that every seeded device's version matches, so
	// findings exist deterministically and each one names its device.
	feed := filepath.Join(dir, "advisories.csv")
	if err := os.WriteFile(feed, []byte(
		"vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary\n"+
			"arista,eos,CVE-2024-0002,high,8.1,4.30.0,,,4.33.2,,1,2024-02-20,Range DoS\n"), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}
	f.s.vulns = vuln.NewFeed(feed, nil, nil)

	// One assessable device per owner: acme (restricted later), globex (the
	// control) and the platform itself (must survive every filter — a fix that
	// passes by hiding everything is not a fix).
	const eos = "Arista Networks EOS version 4.33.1F running on an Arista DCS-7050"
	for _, d := range []models.Device{
		{ID: acmeEdgeID, Name: acmeEdgeID, Address: "10.1.0.2", TenantID: f.acme, Vendor: "arista", OS: eos, Source: "test"},
		{ID: globexEdgeID, Name: globexEdgeID, Address: "10.2.0.2", TenantID: f.globex, Vendor: "arista", OS: eos, Source: "test"},
		{ID: stackJumpID, Name: stackJumpID, Address: "10.9.0.2", Vendor: "arista", OS: eos, Source: "test"},
	} {
		if err := f.s.discovery.Upsert(d); err != nil {
			t.Fatalf("upsert %s: %v", d.ID, err)
		}
	}

	// Declared sites, one per owner.
	for _, st := range []Site{
		{TenantID: f.acme, Slug: acmeSiteSlug, Name: "Acme New York"},
		{TenantID: f.globex, Slug: "globex-lon", Name: "Globex London"},
		{Slug: "stack-ams", Name: "Platform Amsterdam"},
	} {
		if _, err := f.s.sites.Upsert(st); err != nil {
			t.Fatalf("upsert site %s: %v", st.Slug, err)
		}
	}

	// Wireless controllers nothing polls — the REMAINDER rows /api/devices
	// appends after the registry (wireless_devices.go).
	for _, c := range []wireless.Controller{
		{TenantID: f.acme, ControllerID: acmeWLCID, Name: acmeWLCID, Vendor: "cisco", ManagementAddress: "10.1.9.1"},
		{TenantID: f.globex, ControllerID: "globex-wlc", Name: "globex-wlc", Vendor: "cisco", ManagementAddress: "10.2.9.1"},
	} {
		if err := f.s.wireless.UpsertController(context.Background(), c); err != nil {
			t.Fatalf("upsert controller %s: %v", c.ControllerID, err)
		}
	}
	return &listFixture{restrictedAlertFixture: f}
}

func (f *listFixture) owner() jwtClaims {
	return jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
}

func (f *listFixture) acmeUser() jwtClaims {
	return jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
}

func (f *listFixture) restrictAcme(t *testing.T) {
	t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
}

// call drives one real handler and returns the body, failing on a non-200.
func (f *listFixture) call(t *testing.T, h http.HandlerFunc, method, path, body string, claims jwtClaims) string {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, req(method, path, body, claims))
	if w.Code != http.StatusOK {
		t.Fatalf("%s %s = %d (%s)", method, path, w.Code, w.Body.String())
	}
	return w.Body.String()
}

// keys renders a set as a sorted, comparable string, so a failure prints what
// was actually returned rather than "not equal".
func keys(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// ── 1. the global omnibox (search_global.go) ────────────────────────────────

// omniboxKinds runs the real GET /api/search/global and returns the ids it
// offered for one kind, plus the raw body (a leak test must be able to grep
// bytes, not only typed ids).
func (f *listFixture) omnibox(t *testing.T, claims jwtClaims, q, kind string) (map[string]bool, string) {
	t.Helper()
	body := f.call(t, f.s.handleGlobalSearch, http.MethodGet, "/api/search/global?q="+q, "", claims)
	var out struct {
		Results []globalResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode omnibox: %v (%s)", err, body)
	}
	ids := map[string]bool{}
	for _, r := range out.Results {
		if r.Kind == kind {
			ids[r.ID] = true
		}
	}
	return ids, body
}

// TestGlobalOmniboxHonoursTheOperatorVisibilityRestriction is the sharpest
// inconsistency in the set: unified search hid a restricted tenant's devices
// (searchVisibility.hides) while THIS box, answering the same free-text query
// from the same registry, named them.
func TestGlobalOmniboxHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newListFixture(t)
	owner, acmeUser := f.owner(), f.acmeUser()

	// Baseline: "10." matches every device's management address, so the box
	// offers all five registry rows to the platform owner.
	ids, _ := f.omnibox(t, owner, "10.", "device")
	for _, want := range []string{"acme-core", acmeEdgeID, "globex-core", globexEdgeID, stackJumpID} {
		if !ids[want] {
			t.Fatalf("baseline omnibox is missing %q (got %s) — the fixture does not reach the handler", want, keys(ids))
		}
	}
	// And acme's own answer BEFORE the switch, so the guard below compares
	// against a number this test measured rather than one it assumed.
	beforeOwn, _ := f.omnibox(t, acmeUser, "10.", "device")
	if len(beforeOwn) != 2 {
		t.Fatalf("acme's own omnibox = %s, want its two devices", keys(beforeOwn))
	}
	// The alert half of the same handler, also read through the raw
	// restriction-blind rule until now.
	alertsBefore, _ := f.omnibox(t, owner, "bgp", "alert")
	if !alertsBefore[acmeAlertID] {
		t.Fatalf("baseline omnibox alerts = %s, want %q among them", keys(alertsBefore), acmeAlertID)
	}

	f.restrictAcme(t)

	// ── half 1: the Global view.
	got, body := f.omnibox(t, owner, "10.", "device")
	for _, hidden := range []string{"acme-core", acmeEdgeID} {
		if got[hidden] {
			t.Errorf("RESTRICTION LEAK: the Global omnibox still offers %q as a jump target (results: %s) — "+
				"unified search hides the same device for the same query.", hidden, keys(got))
		}
		if strings.Contains(body, hidden) {
			t.Errorf("RESTRICTION LEAK: the Global omnibox body names %q", hidden)
		}
	}
	for _, want := range []string{"globex-core", globexEdgeID, stackJumpID} {
		if !got[want] {
			t.Errorf("restricting acme removed %q from the omnibox (results: %s) — it must move nothing else", want, keys(got))
		}
	}
	if alerts, _ := f.omnibox(t, owner, "bgp", "alert"); alerts[acmeAlertID] {
		t.Errorf("RESTRICTION LEAK: the Global omnibox still offers the restricted tenant's alert %q (results: %s) — "+
			"GET /api/alerts and the WebSocket feed both hide it.", acmeAlertID, keys(alerts))
	}

	// ── half 2: the owner walks in with as_tenant=acme. It finds nothing.
	if got, _ := f.omnibox(t, ownerActing(owner, f.acme), "10.", "device"); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme omnibox returned %s, want nothing", keys(got))
	}

	// ── the owner scoped into the UNRESTRICTED tenant is unmoved.
	if got, _ := f.omnibox(t, ownerActing(owner, f.globex), "10.", "device"); !got["globex-core"] || !got[globexEdgeID] {
		t.Errorf("as_tenant=globex omnibox = %s, want both globex devices — restricting acme must not change globex", keys(got))
	}

	// ── acme's OWN view is unchanged.
	if afterOwn, _ := f.omnibox(t, acmeUser, "10.", "device"); keys(afterOwn) != keys(beforeOwn) {
		t.Errorf("acme's own omnibox changed when acme restricted itself: %s → %s — "+
			"the switch hides a tenant from the platform, never from itself.", keys(beforeOwn), keys(afterOwn))
	}
}

// ── 2. GET /api/devices, wired + wireless (main.go) ─────────────────────────

func (f *listFixture) devices(t *testing.T, claims jwtClaims) (map[string]bool, string) {
	t.Helper()
	body := f.call(t, f.s.handleDevices, http.MethodGet, "/api/devices", "", claims)
	var rows []models.Device
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatalf("decode devices: %v (%s)", err, body)
	}
	ids := map[string]bool{}
	for _, d := range rows {
		ids[d.ID] = true
	}
	return ids, body
}

// TestDevicesListHonoursTheOperatorVisibilityRestriction covers the list the
// Devices tile is the headline number for — and BOTH halves of that list: the
// registry rows and the wireless inventory appended after them.
func TestDevicesListHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newListFixture(t)
	owner, acmeUser := f.owner(), f.acmeUser()
	acmeWLCRow := wireless.ControllerDeviceIDPrefix + acmeWLCID
	globexWLCRow := wireless.ControllerDeviceIDPrefix + "globex-wlc"

	// Baseline: five registry devices plus two unpolled controllers.
	ids, _ := f.devices(t, owner)
	for _, want := range []string{"acme-core", acmeEdgeID, "globex-core", globexEdgeID, stackJumpID, acmeWLCRow, globexWLCRow} {
		if !ids[want] {
			t.Fatalf("baseline GET /api/devices is missing %q (got %s)", want, keys(ids))
		}
	}
	beforeOwn, _ := f.devices(t, acmeUser)
	if len(beforeOwn) != 3 {
		t.Fatalf("acme's own fleet = %s, want its two devices + its controller", keys(beforeOwn))
	}

	f.restrictAcme(t)

	// ── half 1: the Global list.
	got, body := f.devices(t, owner)
	for _, hidden := range []string{"acme-core", acmeEdgeID, acmeWLCRow} {
		if got[hidden] {
			t.Errorf("RESTRICTION LEAK: GET /api/devices still returns %q to the platform operator (rows: %s). "+
				"The Devices tile counts three; this list hands over six, and the delta names what the tile hid.", hidden, keys(got))
		}
	}
	if strings.Contains(body, acmeWLCID) {
		t.Errorf("RESTRICTION LEAK: the wireless projection leaked %q into GET /api/devices — "+
			"filtering the wired half and leaving the wireless half in the table hides nothing.", acmeWLCID)
	}
	for _, want := range []string{"globex-core", globexEdgeID, stackJumpID, globexWLCRow} {
		if !got[want] {
			t.Errorf("restricting acme removed %q from GET /api/devices (rows: %s)", want, keys(got))
		}
	}

	// ── half 2: as_tenant=acme returns nothing at all.
	if got, _ := f.devices(t, ownerActing(owner, f.acme)); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme GET /api/devices returned %s, want no rows", keys(got))
	}

	// ── the unrestricted tenant is unmoved.
	if got, _ := f.devices(t, ownerActing(owner, f.globex)); !got["globex-core"] || !got[globexEdgeID] || !got[globexWLCRow] {
		t.Errorf("as_tenant=globex GET /api/devices = %s, want globex's two devices + its controller", keys(got))
	}

	// ── acme's OWN fleet is unchanged.
	if afterOwn, _ := f.devices(t, acmeUser); keys(afterOwn) != keys(beforeOwn) {
		t.Errorf("acme's own fleet changed when acme restricted itself: %s → %s", keys(beforeOwn), keys(afterOwn))
	}
}

// ── 3. GET /api/sites, the by-slug read, and the geomap's slug set ──────────

func (f *listFixture) sites(t *testing.T, claims jwtClaims) (map[string]bool, string) {
	t.Helper()
	body := f.call(t, f.s.handleSites, http.MethodGet, "/api/sites", "", claims)
	var out struct {
		Sites []Site `json:"sites"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode sites: %v (%s)", err, body)
	}
	slugs := map[string]bool{}
	for _, st := range out.Sites {
		slugs[st.Slug] = true
	}
	return slugs, body
}

// siteStatus returns the status code of GET /api/sites/{slug}.
func (f *listFixture) siteStatus(t *testing.T, claims jwtClaims, slug string) int {
	t.Helper()
	w := httptest.NewRecorder()
	f.s.handleSiteByID(w, req(http.MethodGet, "/api/sites/"+slug, "", claims))
	return w.Code
}

// TestSitesListHonoursTheOperatorVisibilityRestriction covers the declared-sites
// store: the list, the by-slug read that could otherwise read back exactly what
// the list withheld, and the geomap's resolvable-slug set built from the same
// store.
func TestSitesListHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newListFixture(t)
	owner, acmeUser := f.owner(), f.acmeUser()

	// Baseline: three declared sites, one per owner.
	slugs, _ := f.sites(t, owner)
	for _, want := range []string{acmeSiteSlug, "globex-lon", "stack-ams"} {
		if !slugs[want] {
			t.Fatalf("baseline GET /api/sites is missing %q (got %s)", want, keys(slugs))
		}
	}
	if st := f.siteStatus(t, owner, acmeSiteSlug); st != http.StatusOK {
		t.Fatalf("baseline GET /api/sites/%s = %d, want 200", acmeSiteSlug, st)
	}
	if !f.s.geoSiteSlugs(owner)[acmeSiteSlug] {
		t.Fatalf("baseline geoSiteSlugs does not resolve %q", acmeSiteSlug)
	}
	beforeOwn, _ := f.sites(t, acmeUser)
	if keys(beforeOwn) != acmeSiteSlug {
		t.Fatalf("acme's own sites = %s, want %q", keys(beforeOwn), acmeSiteSlug)
	}

	f.restrictAcme(t)

	// ── half 1: the Global list drops acme's site; the others stay.
	got, body := f.sites(t, owner)
	if got[acmeSiteSlug] {
		t.Errorf("RESTRICTION LEAK: GET /api/sites still returns %q to the platform operator (sites: %s) — "+
			"a site name is where the restricted tenant operates, and the Sites tile already hides it.", acmeSiteSlug, keys(got))
	}
	if strings.Contains(body, "Acme New York") {
		t.Errorf("RESTRICTION LEAK: GET /api/sites body names the restricted tenant's site: %s", body)
	}
	for _, want := range []string{"globex-lon", "stack-ams"} {
		if !got[want] {
			t.Errorf("restricting acme removed %q from GET /api/sites (sites: %s)", want, keys(got))
		}
	}
	// The by-slug read must agree: 404, never 403 — a 403 confirms it exists.
	if st := f.siteStatus(t, owner, acmeSiteSlug); st != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: GET /api/sites/%s = %d for the platform operator, want 404 — "+
			"naming the slug read back exactly what the list withheld.", acmeSiteSlug, st)
	}
	if f.s.geoSiteSlugs(owner)[acmeSiteSlug] {
		t.Errorf("RESTRICTION LEAK: geoSiteSlugs still resolves %q for the platform operator", acmeSiteSlug)
	}

	// ── half 2: as_tenant=acme sees no sites at all.
	if got, _ := f.sites(t, ownerActing(owner, f.acme)); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme GET /api/sites returned %s, want none", keys(got))
	}
	if st := f.siteStatus(t, ownerActing(owner, f.acme), acmeSiteSlug); st != http.StatusNotFound {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme GET /api/sites/%s = %d, want 404", acmeSiteSlug, st)
	}

	// ── the unrestricted tenant is unmoved.
	if got, _ := f.sites(t, ownerActing(owner, f.globex)); keys(got) != "globex-lon" {
		t.Errorf("as_tenant=globex GET /api/sites = %s, want globex-lon", keys(got))
	}

	// ── acme's OWN sites are unchanged, list and by-slug.
	afterOwn, _ := f.sites(t, acmeUser)
	if keys(afterOwn) != keys(beforeOwn) {
		t.Errorf("acme's own sites changed when acme restricted itself: %s → %s", keys(beforeOwn), keys(afterOwn))
	}
	if st := f.siteStatus(t, acmeUser, acmeSiteSlug); st != http.StatusOK {
		t.Errorf("acme's own GET /api/sites/%s = %d after restricting itself, want 200", acmeSiteSlug, st)
	}
	if !f.s.geoSiteSlugs(acmeUser)[acmeSiteSlug] {
		t.Errorf("acme's own geoSiteSlugs stopped resolving %q after restricting itself", acmeSiteSlug)
	}
}

// ── 4. GET /api/compliance and GET /api/vulns ──────────────────────────────

// compliance runs the real handler and returns summary.devices plus the device
// ids the findings AND gaps name.
func (f *listFixture) compliance(t *testing.T, claims jwtClaims) (int, map[string]bool, string) {
	t.Helper()
	body := f.call(t, f.s.handleCompliance, http.MethodGet, "/api/compliance", "", claims)
	var out struct {
		Summary struct {
			Devices int `json:"devices"`
		} `json:"summary"`
		Findings []struct {
			DeviceID string `json:"device_id"`
		} `json:"findings"`
		// Gaps name a device too ("vendor unknown … OS checks skipped"), so they
		// are the same disclosure as a finding and are asserted alongside them.
		Gaps []struct {
			DeviceID string `json:"device_id"`
		} `json:"gaps"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode compliance: %v (%s)", err, body)
	}
	ids := map[string]bool{}
	for _, fd := range out.Findings {
		ids[fd.DeviceID] = true
	}
	for _, g := range out.Gaps {
		ids[g.DeviceID] = true
	}
	return out.Summary.Devices, ids, body
}

// TestComplianceHonoursTheOperatorVisibilityRestriction — a compliance finding
// names the device AND what is wrong with it.
func TestComplianceHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newListFixture(t)
	owner, acmeUser := f.owner(), f.acmeUser()

	total, ids, _ := f.compliance(t, owner)
	if total != 5 {
		t.Fatalf("baseline compliance summary.devices = %d, want 5", total)
	}
	for _, want := range []string{acmeEdgeID, globexEdgeID, stackJumpID} {
		if !ids[want] {
			t.Fatalf("baseline compliance rows miss %q (got %s) — the fixture produces nothing to hide", want, keys(ids))
		}
	}
	beforeOwn, beforeIDs, _ := f.compliance(t, acmeUser)

	f.restrictAcme(t)

	// ── half 1.
	got, gotIDs, body := f.compliance(t, owner)
	if got != 3 {
		t.Errorf("RESTRICTION LEAK: Global compliance summary.devices = %d, want 3 — it still counts acme's fleet", got)
	}
	for _, hidden := range []string{"acme-core", acmeEdgeID} {
		if gotIDs[hidden] {
			t.Errorf("RESTRICTION LEAK: Global compliance names %q in its findings/gaps (rows: %s) — "+
				"the row says which device is non-compliant and why.", hidden, keys(gotIDs))
		}
		if strings.Contains(body, hidden) {
			t.Errorf("RESTRICTION LEAK: the compliance body names %q", hidden)
		}
	}
	if !gotIDs[globexEdgeID] || !gotIDs[stackJumpID] {
		t.Errorf("restricting acme changed the unrestricted/platform findings: %s", keys(gotIDs))
	}

	// ── half 2: an as_tenant walk gets the not-configured answer, not acme's.
	body = f.call(t, f.s.handleCompliance, http.MethodGet, "/api/compliance", "", ownerActing(owner, f.acme))
	for _, hidden := range []string{"acme-core", acmeEdgeID} {
		if strings.Contains(body, hidden) {
			t.Errorf("RESTRICTION LEAK: as_tenant=acme compliance names %q: %s", hidden, body)
		}
	}

	// ── the unrestricted tenant is unmoved.
	if n, _, _ := f.compliance(t, ownerActing(owner, f.globex)); n != 2 {
		t.Errorf("as_tenant=globex compliance summary.devices = %d, want 2", n)
	}

	// ── acme's OWN posture is unchanged.
	afterOwn, afterIDs, _ := f.compliance(t, acmeUser)
	if afterOwn != beforeOwn || keys(afterIDs) != keys(beforeIDs) {
		t.Errorf("acme's own compliance changed when acme restricted itself: devices %d→%d, findings %s→%s",
			beforeOwn, afterOwn, keys(beforeIDs), keys(afterIDs))
	}
}

// vulns runs the real handler and returns summary.devices plus the device ids
// the findings name.
func (f *listFixture) vulns(t *testing.T, claims jwtClaims) (int, map[string]bool, string) {
	t.Helper()
	body := f.call(t, f.s.handleVulns, http.MethodGet, "/api/vulns", "", claims)
	var out struct {
		Summary struct {
			Devices int `json:"devices"`
		} `json:"summary"`
		Findings []struct {
			DeviceID string `json:"device_id"`
			CVE      string `json:"cve"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode vulns: %v (%s)", err, body)
	}
	ids := map[string]bool{}
	for _, fd := range out.Findings {
		ids[fd.DeviceID] = true
	}
	return out.Summary.Devices, ids, body
}

// TestVulnsHonoursTheOperatorVisibilityRestriction — a CVE row names a device,
// its OS version and the weakness it is exposed to.
func TestVulnsHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newListFixture(t)
	owner, acmeUser := f.owner(), f.acmeUser()

	total, ids, _ := f.vulns(t, owner)
	if total != 5 {
		t.Fatalf("baseline vulns summary.devices = %d, want 5", total)
	}
	for _, want := range []string{acmeEdgeID, globexEdgeID, stackJumpID} {
		if !ids[want] {
			t.Fatalf("baseline vuln findings miss %q (got %s)", want, keys(ids))
		}
	}
	beforeOwn, beforeIDs, _ := f.vulns(t, acmeUser)

	f.restrictAcme(t)

	// ── half 1.
	got, gotIDs, body := f.vulns(t, owner)
	if got != 3 {
		t.Errorf("RESTRICTION LEAK: Global vulns summary.devices = %d, want 3", got)
	}
	if gotIDs[acmeEdgeID] {
		t.Errorf("RESTRICTION LEAK: Global vuln findings name %q with its CVEs (findings: %s)", acmeEdgeID, keys(gotIDs))
	}
	if strings.Contains(body, acmeEdgeID) {
		t.Errorf("RESTRICTION LEAK: the vulns body names %q — including its unassessed row", acmeEdgeID)
	}
	if !gotIDs[globexEdgeID] || !gotIDs[stackJumpID] {
		t.Errorf("restricting acme changed the unrestricted/platform findings: %s", keys(gotIDs))
	}

	// ── half 2.
	if n, gotIDs, _ := f.vulns(t, ownerActing(owner, f.acme)); n != 0 || len(gotIDs) != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme vulns reported %d devices / findings %s, want 0 / none", n, keys(gotIDs))
	}

	// ── the unrestricted tenant is unmoved.
	if n, _, _ := f.vulns(t, ownerActing(owner, f.globex)); n != 2 {
		t.Errorf("as_tenant=globex vulns summary.devices = %d, want 2", n)
	}

	// ── acme's OWN exposure is unchanged.
	afterOwn, afterIDs, _ := f.vulns(t, acmeUser)
	if afterOwn != beforeOwn || keys(afterIDs) != keys(beforeIDs) {
		t.Errorf("acme's own vulns changed when acme restricted itself: devices %d→%d, findings %s→%s",
			beforeOwn, afterOwn, keys(beforeIDs), keys(afterIDs))
	}
}

// ── 5. the device_sites import resolver (sot_import.go) ────────────────────

// importPlan runs a DRY-RUN device_sites import and returns action-by-key. The
// import is the one WRITE path in this set, so the assertion is about what the
// plan says, not only about what it writes: the plan itself is the oracle.
func (f *listFixture) importPlan(t *testing.T, claims jwtClaims, csv string) map[string]string {
	t.Helper()
	body := f.call(t, f.s.handleSoTImport, http.MethodPost, "/api/sot/import",
		mustJSON(t, map[string]any{"kind": "device_sites", "format": "csv", "data": csv, "dry_run": true}), claims)
	var res importResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode import: %v (%s)", err, body)
	}
	out := map[string]string{}
	for i, row := range res.Rows {
		out[fmt.Sprintf("line%d", i+2)] = row.Action + ":" + row.Key
	}
	return out
}

// TestSoTImportResolverHonoursTheOperatorVisibilityRestriction. resolve()
// answers by serial, address and hostname and the plan ECHOES the resolved
// device id, so an import of guessed identifiers is an existence-and-identity
// oracle over a fleet the operator may not read. A row that does not resolve is
// a per-row "error" — the import continues and writes nothing for it — so this
// costs an explicit refusal, never a silent change.
func TestSoTImportResolverHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newListFixture(t)
	owner, acmeUser := f.owner(), f.acmeUser()
	// Both rows name a device by HOSTNAME and a site by slug, so a resolution is
	// a disclosure of both.
	csvOwner := "device,site\n" + acmeEdgeID + "," + acmeSiteSlug + "\n" + globexEdgeID + ",globex-lon\n"
	csvAcme := "device,site\n" + acmeEdgeID + "," + acmeSiteSlug + "\n"

	plan := f.importPlan(t, owner, csvOwner)
	if plan["line2"] != "create:"+acmeEdgeID || plan["line3"] != "create:"+globexEdgeID {
		t.Fatalf("baseline import plan = %v, want both rows resolved to a create", plan)
	}
	beforeOwn := f.importPlan(t, acmeUser, csvAcme)
	if beforeOwn["line2"] != "create:"+acmeEdgeID {
		t.Fatalf("acme's own import plan = %v, want create:%s", beforeOwn, acmeEdgeID)
	}

	f.restrictAcme(t)

	// ── half 1: the operator's row for acme no longer resolves, and the plan no
	//    longer echoes acme's device id. globex still resolves.
	got := f.importPlan(t, owner, csvOwner)
	if got["line2"] != "error:"+acmeEdgeID {
		t.Errorf("RESTRICTION LEAK: the import plan answered %q for a restricted tenant's device — "+
			"resolving it confirms the device exists and hands back its id.", got["line2"])
	}
	if got["line3"] != "create:"+globexEdgeID {
		t.Errorf("restricting acme broke the unrestricted tenant's import row: %q", got["line3"])
	}

	// ── half 2: scoped in, nothing resolves.
	if got := f.importPlan(t, ownerActing(owner, f.acme), csvAcme); got["line2"] != "error:"+acmeEdgeID {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme import plan = %q, want an error row", got["line2"])
	}

	// ── acme's OWN import is unchanged: the tenant can still place its devices.
	if afterOwn := f.importPlan(t, acmeUser, csvAcme); afterOwn["line2"] != beforeOwn["line2"] {
		t.Errorf("acme's own import plan changed when acme restricted itself: %q → %q",
			beforeOwn["line2"], afterOwn["line2"])
	}
}

// ── 6. securityRegistryDevices, folded onto the chokepoint ─────────────────

// TestSecurityRegistryDevicesMatchesTheChokepoint pins the fold in main.go:
// securityRegistryDevices used to re-derive the restriction by hand. It now
// calls s.visibleDevicesFor, and this asserts the two agree on every scope —
// the property the hand-rolled copy had, kept by construction rather than by
// coincidence. (The end-to-end assertions on the number it feeds —
// coverage.total_assets — live in security_findings_restriction_test.go.)
func TestSecurityRegistryDevicesMatchesTheChokepoint(t *testing.T) {
	f := newListFixture(t)
	owner := f.owner()
	f.restrictAcme(t)

	for _, tc := range []struct {
		name   string
		claims jwtClaims
		want   int
	}{
		{"global excludes the restricted tenant", owner, 3},
		{"as_tenant into the restricted tenant is denied", ownerActing(owner, f.acme), 0},
		{"as_tenant into an unrestricted tenant", ownerActing(owner, f.globex), 2},
		{"the restricted tenant's own users", f.acmeUser(), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req(http.MethodGet, "/api/security/posture", "", tc.claims)
			if got := f.s.securityRegistryDevices(r); got != tc.want {
				t.Errorf("securityRegistryDevices = %d, want %d", got, tc.want)
			}
			if got, want := f.s.securityRegistryDevices(r), len(f.s.visibleDevicesFor(tc.claims)); got != want {
				t.Errorf("securityRegistryDevices = %d but the chokepoint says %d — they must be one implementation", got, want)
			}
		})
	}
}
