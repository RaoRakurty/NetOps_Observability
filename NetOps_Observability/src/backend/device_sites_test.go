package backend

// device_sites_test.go — unit + cross-org isolation for the operator device→site
// binding (Phase 3 SoT remainder). The isolation test (CLAUDE.md §3a) runs through
// the REAL router + auth middleware: a tenant user may bind only its OWN devices to
// its OWN sites, can never reach another org's device or site, and the placement it
// declares flows into the geomap scoped to that org alone.

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/models"
)

// ── store unit: token expansion + default-closed tenant scoping ──────────────────

func TestDeviceSiteStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_sites.json")
	st, err := newDeviceSiteStore(path)
	if err != nil {
		t.Fatal(err)
	}

	// Tenant "a" binds a device (two identity tokens) to site "nyc".
	if err := st.Set(DeviceSiteBinding{
		TenantID: "a", DeviceID: "dev1", Tokens: []string{"ip:10.0.0.1", "name:dev1"}, Site: "nyc",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Assignments are token-keyed and own-tenant only.
	aMap := st.Assignments("a", false)
	if aMap["ip:10.0.0.1"] != "nyc" || aMap["name:dev1"] != "nyc" {
		t.Fatalf("assignments missing token expansion: %v", aMap)
	}
	if got := st.Assignments("b", false); len(got) != 0 {
		t.Fatalf("tenant b sees tenant a's binding: %v", got) // CROSS-TENANT LEAK
	}
	if got := st.Assignments("", true); got["ip:10.0.0.1"] != "nyc" {
		t.Fatalf("cross principal should see all bindings: %v", got)
	}

	// Get is scoped: b can't read a's binding; a can; cross can.
	if _, ok := st.Get("b", false, "dev1"); ok {
		t.Fatal("tenant b read tenant a's binding")
	}
	if b, ok := st.Get("a", false, "dev1"); !ok || b.Site != "nyc" {
		t.Fatalf("tenant a get = %+v ok=%v", b, ok)
	}

	// Delete is scoped: b can't delete a's; a can; persists across reopen.
	if st.Delete("b", false, "dev1") {
		t.Fatal("tenant b deleted tenant a's binding")
	}
	if !st.Delete("a", false, "dev1") {
		t.Fatal("tenant a could not delete own binding")
	}
	reopened, err := newDeviceSiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Assignments("a", false); len(got) != 0 {
		t.Fatalf("binding survived delete after reopen: %v", got)
	}
}

// ── buildGeomap: an explicit operator binding wins over a stale inventory label ──

func TestBuildGeomapBindingOverridesLabel(t *testing.T) {
	now := time.Now()
	sites := []SoTSite{{Name: "NYC", Slug: "nyc", Lat: 40.7, Lng: -74.0, HasCoords: true, Source: "internal"}}
	// The device carries a stale discovery label "ghost" (no such declared site);
	// the operator binding to "nyc" must take precedence and place it.
	devices := []models.Device{
		{ID: "d1", Name: "leaf1", Address: "10.0.0.1", Labels: map[string]string{"site": "ghost"}, LastSeen: now},
	}
	assign := map[string]string{"ip:10.0.0.1": "nyc"}
	rows, unplaced, _ := buildGeomap(sites, devices, assign, nil, now)
	if unplaced != 0 {
		t.Fatalf("device should be placed via binding, unplaced=%d", unplaced)
	}
	if len(rows) != 1 || rows[0].Slug != "nyc" || rows[0].Devices != 1 {
		t.Fatalf("binding placement failed: %+v", rows)
	}
}

// ── end-to-end cross-org isolation through the real router ───────────────────────

func TestDeviceSiteIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	dir := t.TempDir()
	var err error
	if s.sites, err = newSitesStore(filepath.Join(dir, "sites.json")); err != nil {
		t.Fatal(err)
	}
	if s.deviceSites, err = newDeviceSiteStore(filepath.Join(dir, "device_sites.json")); err != nil {
		t.Fatal(err)
	}

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, each: org → tenant → operator → one site → one device.
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		f := &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
		// One declared site in the tenant.
		st, b = do(t, srv, "POST", "/api/sites", f.token, map[string]any{"name": "Site " + name})
		if st != 200 {
			t.Fatalf("user %s create site: %d %s", name, st, b)
		}
		var saved struct {
			Slug string `json:"slug"`
		}
		if err := json.Unmarshal(b, &saved); err != nil || saved.Slug == "" {
			t.Fatalf("user %s site has no slug: %s", name, b)
		}
		f.siteSlug = saved.Slug
		// One device OWNED by the tenant, in discovery.
		s.discovery.Upsert(models.Device{
			ID: "dev-" + name, Name: "dev-" + name, Address: "10.0.0." + name, TenantID: tenantID, Source: "manual",
		})
		fix[name] = f
	}
	a, b := fix["A"], fix["B"]

	siteOf := func(token, devID string) (int, string) {
		st, body := do(t, srv, "GET", "/api/devices/"+devID+"/site", token, nil)
		var r struct {
			Site string `json:"site"`
		}
		_ = json.Unmarshal(body, &r)
		return st, r.Site
	}

	// 1) user-A binds its own device to its own site → 200, and reads it back.
	if st, body := do(t, srv, "PUT", "/api/devices/dev-A/site", a.token, map[string]any{"site": a.siteSlug}); st != 200 {
		t.Fatalf("user-A bind own device: %d %s", st, body)
	}
	if st, got := siteOf(a.token, "dev-A"); st != 200 || got != a.siteSlug {
		t.Fatalf("user-A read own binding: %d site=%q want %q", st, got, a.siteSlug)
	}

	// 2) user-A cannot bind its device to org-B's site (not visible → 400, no leak).
	if st, _ := do(t, srv, "PUT", "/api/devices/dev-A/site", a.token, map[string]any{"site": b.siteSlug}); st != 400 {
		t.Fatalf("user-A bind to org-B site: %d, want 400", st)
	}

	// 3) user-A cannot read/set/delete org-B's DEVICE (404 — never reveal the id).
	if st, _ := siteOf(a.token, "dev-B"); st != 404 {
		t.Fatalf("user-A GET org-B device site: %d, want 404", st)
	}
	if st, _ := do(t, srv, "PUT", "/api/devices/dev-B/site", a.token, map[string]any{"site": a.siteSlug}); st != 404 {
		t.Fatalf("user-A PUT org-B device site: %d, want 404", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/devices/dev-B/site", a.token, nil); st != 404 {
		t.Fatalf("user-A DELETE org-B device site: %d, want 404", st)
	}

	// 4) org-B's binding is untouched and B can still place its own device.
	if st, body := do(t, srv, "PUT", "/api/devices/dev-B/site", b.token, map[string]any{"site": b.siteSlug}); st != 200 {
		t.Fatalf("user-B bind own device: %d %s", st, body)
	}

	// 5) Platform owner can read any device's binding.
	if st, got := siteOf(admin, "dev-A"); st != 200 || got != a.siteSlug {
		t.Fatalf("admin read dev-A binding: %d site=%q", st, got)
	}

	// 6) Geomap is scoped: user-A's geomap places dev-A at its own site and never
	//    carries org-B's site or device.
	st, body := do(t, srv, "GET", "/api/geomap", a.token, nil)
	if st != 200 {
		t.Fatalf("geomap: %d %s", st, body)
	}
	var geo struct {
		Sites []geoSite `json:"sites"`
	}
	if err := json.Unmarshal(body, &geo); err != nil {
		t.Fatalf("decode geomap: %v", err)
	}
	placed := 0
	for _, gs := range geo.Sites {
		if gs.Slug == b.siteSlug {
			t.Fatalf("geomap cross-org leak: org-A saw org-B site %q", gs.Slug)
		}
		if gs.Slug == a.siteSlug {
			placed = gs.Devices
		}
	}
	if placed != 1 {
		t.Fatalf("org-A geomap should place dev-A at its site, got %d devices", placed)
	}
}
