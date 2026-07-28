package main

import (
	"encoding/json"
	"netops/backend/internal/discovery"
	"path/filepath"
	"testing"

	"netops/backend/models"
)

// ── parsers (pure) ──────────────────────────────────────────────────────────

func TestParseImportSites(t *testing.T) {
	// CSV with aliased headers + a coordinate-less row.
	csv := "name,slug,status,owner,latitude,longitude\n" +
		"New York,nyc,active,NetEng,40.71,-74.01\n" +
		"Backup,,planned,,,\n"
	rows, err := parseImportSites("csv", []byte(csv))
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if len(rows) != 2 || rows[0].Slug != "nyc" || !rows[0].HasCoords || rows[0].Lat != 40.71 || rows[0].Lng != -74.01 {
		t.Fatalf("csv row0 = %+v", rows[0])
	}
	if rows[1].HasCoords {
		t.Fatalf("csv row1 should have no coords: %+v", rows[1])
	}

	// JSON array.
	jrows, err := parseImportSites("json", []byte(`[{"name":"LA","slug":"lax","lat":34.05,"lng":-118.24}]`))
	if err != nil || len(jrows) != 1 || !jrows[0].HasCoords || jrows[0].Lat != 34.05 {
		t.Fatalf("json: %v %+v", err, jrows)
	}

	// GeoJSON — coordinates are [lng, lat] (lng FIRST); we must not swap them.
	geo := `{"type":"FeatureCollection","features":[
	  {"type":"Feature","geometry":{"type":"Point","coordinates":[-74.01,40.71]},
	   "properties":{"name":"New York","slug":"nyc","owner":"NetEng"}}]}`
	grows, err := parseImportSites("geojson", []byte(geo))
	if err != nil || len(grows) != 1 {
		t.Fatalf("geojson: %v %+v", err, grows)
	}
	if grows[0].Lat != 40.71 || grows[0].Lng != -74.01 {
		t.Fatalf("geojson lng/lat order wrong: lat=%v lng=%v (want 40.71/-74.01)", grows[0].Lat, grows[0].Lng)
	}
	if grows[0].Owner != "NetEng" {
		t.Fatalf("geojson properties not read: %+v", grows[0])
	}
}

func TestParseImportBindings(t *testing.T) {
	csv := "device,site\nleaf1,nyc\n10.0.0.2,lax\n"
	rows, err := parseImportBindings("csv", []byte(csv))
	if err != nil || len(rows) != 2 || rows[0].Device != "leaf1" || rows[0].Site != "nyc" || rows[1].Device != "10.0.0.2" {
		t.Fatalf("csv: %v %+v", err, rows)
	}
	jrows, err := parseImportBindings("json", []byte(`[{"device":"SN1","site":"nyc"}]`))
	if err != nil || len(jrows) != 1 || jrows[0].Device != "SN1" {
		t.Fatalf("json: %v %+v", err, jrows)
	}
}

// ── plan + apply: sites ─────────────────────────────────────────────────────

func newImportTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	s := &server{discovery: discovery.NewDiscoveryAggregator()}
	var err error
	if s.sites, err = newSitesStore(filepath.Join(dir, "sites.json")); err != nil {
		t.Fatal(err)
	}
	if s.deviceSites, err = newDeviceSiteStore(filepath.Join(dir, "device_sites.json")); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunSitesImport(t *testing.T) {
	s := newImportTestServer(t)
	rows := []importedSite{
		{Slug: "nyc", Name: "New York", Status: "active", Owner: "NetEng", Lat: 40.71, Lng: -74.01, HasCoords: true},
		{Name: "No Name OK"}, // slug derived
		{Name: ""},           // invalid → error (no name, no slug)
	}

	// Dry-run: plans creates but writes NOTHING.
	plan := s.runSitesImport("t1", false, false, true, rows)
	if plan.Summary["create"] != 2 || plan.Summary["error"] != 1 {
		t.Fatalf("dry-run summary = %v, want 2 create / 1 error", plan.Summary)
	}
	if got := s.sites.All("t1", false); len(got) != 0 {
		t.Fatalf("dry-run wrote %d sites, want 0", len(got))
	}

	// Apply: now it writes.
	app := s.runSitesImport("t1", false, false, false, rows)
	if app.Summary["create"] != 2 {
		t.Fatalf("apply create = %d, want 2", app.Summary["create"])
	}
	if got := s.sites.All("t1", false); len(got) != 2 {
		t.Fatalf("apply wrote %d sites, want 2", len(got))
	}

	// Re-import identical → unchanged, no clobber.
	again := s.runSitesImport("t1", false, false, false, rows[:1])
	if again.Summary["unchanged"] != 1 {
		t.Fatalf("re-import = %v, want 1 unchanged", again.Summary)
	}

	// Changed row without overwrite → conflict (skipped, not written).
	changed := []importedSite{{Slug: "nyc", Name: "NYC Renamed", Owner: "SecOps"}}
	conf := s.runSitesImport("t1", false, false, false, changed)
	if conf.Summary["conflict"] != 1 {
		t.Fatalf("conflict summary = %v, want 1 conflict", conf.Summary)
	}
	if cur, _ := s.sites.Get("t1", false, "nyc"); cur.Name != "New York" {
		t.Fatalf("conflict must not clobber: name = %q, want New York", cur.Name)
	}

	// Same change WITH overwrite → update applied; owner reassigned tenant preserved.
	upd := s.runSitesImport("t1", false, true, false, changed)
	if upd.Summary["update"] != 1 {
		t.Fatalf("overwrite summary = %v, want 1 update", upd.Summary)
	}
	cur, _ := s.sites.Get("t1", false, "nyc")
	if cur.Name != "NYC Renamed" || cur.Owner != "SecOps" || cur.TenantID != "t1" {
		t.Fatalf("overwrite result = %+v", cur)
	}
}

// ── plan + apply: device→site bindings ──────────────────────────────────────

func TestRunBindingsImport(t *testing.T) {
	s := newImportTestServer(t)
	claims := jwtClaims{Sub: "u", Role: RoleOperator, Tenant: "t1"}
	s.discovery.Upsert(models.Device{ID: "dev1", Name: "leaf1", Address: "10.0.0.1",
		TenantID: "t1", Labels: map[string]string{"serial": "SN1"}})
	if _, err := s.sites.Upsert(Site{TenantID: "t1", Slug: "nyc", Name: "NYC"}); err != nil {
		t.Fatal(err)
	}

	// Resolve by hostname → create binding.
	r := s.runBindingsImport(claims, "t1", false, false, false, []importedBinding{{Device: "leaf1", Site: "nyc"}})
	if r.Summary["create"] != 1 {
		t.Fatalf("by-name create = %v", r.Summary)
	}
	if b, ok := s.deviceSites.Get("t1", false, "dev1"); !ok || b.Site != "nyc" {
		t.Fatalf("binding not written: %+v ok=%v", b, ok)
	}

	// Re-import by serial → same site → unchanged (resolves the SAME device).
	r = s.runBindingsImport(claims, "t1", false, false, false, []importedBinding{{Device: "SN1", Site: "nyc"}})
	if r.Summary["unchanged"] != 1 {
		t.Fatalf("by-serial unchanged = %v", r.Summary)
	}

	// Unknown device → error. Unknown site → error.
	r = s.runBindingsImport(claims, "t1", false, false, false, []importedBinding{
		{Device: "ghost", Site: "nyc"},
		{Device: "10.0.0.1", Site: "atlantis"},
	})
	if r.Summary["error"] != 2 {
		t.Fatalf("error rows = %v, want 2", r.Summary)
	}

	// Rebind needs overwrite.
	if _, err := s.sites.Upsert(Site{TenantID: "t1", Slug: "lax", Name: "LA"}); err != nil {
		t.Fatal(err)
	}
	r = s.runBindingsImport(claims, "t1", false, false, false, []importedBinding{{Device: "dev1", Site: "lax"}})
	if r.Summary["conflict"] != 1 {
		t.Fatalf("rebind without overwrite = %v, want conflict", r.Summary)
	}
	r = s.runBindingsImport(claims, "t1", false, true, false, []importedBinding{{Device: "dev1", Site: "lax"}})
	if r.Summary["update"] != 1 {
		t.Fatalf("rebind with overwrite = %v, want update", r.Summary)
	}
	if b, _ := s.deviceSites.Get("t1", false, "dev1"); b.Site != "lax" {
		t.Fatalf("rebind result = %+v", b)
	}
}

// ── end-to-end cross-org isolation through the real router ───────────────────

func TestSoTImportIsolation(t *testing.T) {
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

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("user %s: %d %s", name, st, b)
		}
		f := &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
		s.discovery.Upsert(models.Device{ID: "dev-" + name, Name: "dev-" + name, Address: "10.0.0." + name, TenantID: tenantID})
		fix[name] = f
	}
	a, b := fix["A"], fix["B"]

	imp := func(token string, body map[string]any) (int, *importResult) {
		st, raw := do(t, srv, "POST", "/api/sot/import", token, body)
		var r importResult
		_ = json.Unmarshal(raw, &r)
		return st, &r
	}

	// 1) A imports a site (dry-run default) then applies → A owns it, B can't see it.
	siteCSV := "name,slug,lat,lng\nNYC,nyc,40.7,-74.0\n"
	if st, r := imp(a.token, map[string]any{"kind": "sites", "format": "csv", "data": siteCSV}); st != 200 || r.Summary["create"] != 1 || !r.DryRun {
		t.Fatalf("A dry-run sites: %d %+v", st, r.Summary)
	}
	if st, r := imp(a.token, map[string]any{"kind": "sites", "format": "csv", "data": siteCSV, "dry_run": false}); st != 200 || r.Summary["create"] != 1 {
		t.Fatalf("A apply sites: %d %+v", st, r.Summary)
	}
	if got, _ := s.sites.Get(b.tenantID, false, "nyc"); got.Slug != "" {
		t.Fatalf("CROSS-TENANT LEAK: B can see A's imported site")
	}

	// 2) A binds its own device by name → create.
	if st, r := imp(a.token, map[string]any{"kind": "device_sites", "format": "csv",
		"data": "device,site\ndev-A,nyc\n", "dry_run": false}); st != 200 || r.Summary["create"] != 1 {
		t.Fatalf("A bind own device: %d %+v", st, r.Summary)
	}

	// 3) A tries to bind org-B's device (by id) → error row, NO cross-tenant write.
	if _, r := imp(a.token, map[string]any{"kind": "device_sites", "format": "csv",
		"data": "device,site\ndev-B,nyc\n", "dry_run": false}); r.Summary["error"] != 1 {
		t.Fatalf("A bind B's device should error: %+v", r.Summary)
	}
	if _, ok := s.deviceSites.Get(b.tenantID, false, "dev-B"); ok {
		t.Fatalf("CROSS-TENANT LEAK: A created a binding on B's device")
	}

	// 4) A imports a binding to a site slug it can't see → error.
	if _, r := imp(a.token, map[string]any{"kind": "device_sites", "format": "csv",
		"data": "device,site\ndev-A,bsite\n", "dry_run": false}); r.Summary["error"] != 1 {
		t.Fatalf("A bind to invisible site should error: %+v", r.Summary)
	}
}
