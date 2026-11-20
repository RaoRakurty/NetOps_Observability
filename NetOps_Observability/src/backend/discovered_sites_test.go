// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// discovered_sites_test.go — the ONE site rule as the Topology canvas applies
// it (operator binding → discovery label → reported site id, with provenance),
// and the discovered-site adoption: preview == apply, idempotent, never touches
// a device with a site of record, tenant stamped from the principal, and the
// §3a two-org isolation of /api/discovered-sites{,/adopt}.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/internal/siteres"
	"netops/backend/models"
	"netops/backend/topology"
)

func vmanageDev(id, name, tenant, site string) models.Device {
	return models.Device{ID: id, Name: name, Address: "10.0.0." + strings.TrimPrefix(id, "d"), TenantID: tenant,
		Labels: map[string]string{"controller_site_id": site, "source_system": "vmanage"}}
}

func newSiteTestServer(t *testing.T) *server {
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

// The canvas grouping: manual binding beats the label beats the reported id;
// the reported id groups by (tenant, namespace, id) with a provenance label;
// the controller's site 250 groups like any branch; nothing is written.
func TestTopologySiteRule(t *testing.T) {
	s := newSiteTestServer(t)
	claims := jwtClaims{Sub: "u", Role: RoleOperator, Tenant: "t1"}
	devs := []models.Device{
		vmanageDev("d1", "vEdge-51", "t1", "50"),
		vmanageDev("d2", "vEdge-52", "t1", "50"),
		vmanageDev("d3", "vSmart", "t1", "250"),
		vmanageDev("d4", "vBond", "t1", "250"),
		vmanageDev("d5", "cEdge-80", "t1", "80"), // manually placed
		vmanageDev("d6", "cEdge-60", "t1", "60"), // labelled
		{ID: "d7", Name: "edge-mib", Address: "10.0.0.7", TenantID: "t1"},  // reports via its own MIB
		{ID: "d8", Name: "edge-peer", Address: "10.0.0.8", TenantID: "t1"}, // known only to its peers
		{ID: "d9", Name: "lonely", Address: "10.0.0.9", TenantID: "t1"},
	}
	devs[5].Labels["site"] = "dc-west"
	for _, d := range devs {
		s.discovery.Upsert(d)
	}
	if _, err := s.sites.Upsert(Site{TenantID: "t1", Slug: "nyc", Name: "New York"}); err != nil {
		t.Fatal(err)
	}
	if err := s.bindDeviceSite(devs[4], "nyc", claims); err != nil {
		t.Fatal(err)
	}
	snap := &sdwanOverlaySnapshot{at: time.Now(),
		devFacts: map[string]collectors.OverlayDeviceFacts{"d7": {SiteID: "50"}},
		res:      topology.OverlayResult{DeviceSites: map[string]string{"d8": "90"}}}

	resolved := s.siteContextFor(claims, snap).resolveAll(devs)
	want := map[string]struct {
		key, label string
		src        siteres.Source
	}{
		"d1": {"discovered:t1:sdwan:50", "Site 50 · from vManage", siteres.SourceDiscovered},
		"d2": {"discovered:t1:sdwan:50", "Site 50 · from vManage", siteres.SourceDiscovered},
		"d3": {"discovered:t1:sdwan:250", "Site 250 · from vManage", siteres.SourceDiscovered},
		"d5": {"nyc", "New York", siteres.SourceManual},
		"d6": {"dc-west", "dc-west", siteres.SourceLabel},
		// The MIB answer joins the vManage-reported branch (one SD-WAN namespace).
		"d7": {"discovered:t1:sdwan:50", "Site 50 · from vManage", siteres.SourceDiscovered},
		"d8": {"discovered:t1:sdwan:90", "Site 90 · from SD-WAN peers", siteres.SourceDiscovered},
		"d9": {"", "", ""},
	}
	for id, w := range want {
		got := resolved[id]
		if got.Key != w.key || got.Label != w.label || got.Source != w.src {
			t.Errorf("%s: got (%q,%q,%q) want (%q,%q,%q)", id, got.Key, got.Label, got.Source, w.key, w.label, w.src)
		}
	}
	if !strings.Contains(resolved["d5"].Note, "reports site 80") {
		t.Errorf("disagreement note missing: %q", resolved["d5"].Note)
	}

	facts := toDeviceFacts(devs, nil, nil, nil, nil)
	applySites(facts, resolved)
	view := topology.Project(topology.Input{Mode: topology.ModeExplore, TenantID: "t1", Devices: facts})
	labels := map[string]string{}
	for _, g := range view.Groups {
		labels[g.Label] = g.Source
	}
	for _, l := range []string{"Site 50 · from vManage", "Site 250 · from vManage", "Site 90 · from SD-WAN peers"} {
		if labels[l] != "discovered" {
			t.Errorf("group %q = %q (groups %v)", l, labels[l], labels)
		}
	}
	if labels["New York"] != "manual" || labels["dc-west"] != "label" {
		t.Errorf("groups %v", labels)
	}
	// Virtual only: resolving wrote no binding and no site.
	if got := len(s.sites.All("t1", false)); got != 1 {
		t.Fatalf("sites written by a read: %d", got)
	}
	if _, ok := s.deviceSites.Get("t1", false, "d1"); ok {
		t.Fatal("a discovered site was written as a binding")
	}
}

// §3a at the rule: the same site id in two tenants is two groups, even on a
// cross-tenant view.
func TestDiscoveredSitesNeverMergeAcrossTenants(t *testing.T) {
	s := newSiteTestServer(t)
	devs := []models.Device{vmanageDev("d1", "a", "acme", "50"), vmanageDev("d2", "b", "globex", "50")}
	resolved := s.siteContextFor(jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}, nil).resolveAll(devs)
	if resolved["d1"].Key == resolved["d2"].Key {
		t.Fatalf("two tenants' site 50 share key %q", resolved["d1"].Key)
	}
}

func TestAdoptDiscoveredSites(t *testing.T) {
	s := newSiteTestServer(t)
	claims := jwtClaims{Sub: "ops", Role: RoleOperator, Tenant: "t1"}
	devs := []models.Device{
		vmanageDev("d1", "vEdge-51", "t1", "50"),
		vmanageDev("d2", "vEdge-52", "t1", "50"),
		vmanageDev("d3", "vEdge-53", "t1", "50"), // manually placed → never touched
		vmanageDev("d4", "vSmart", "t1", "250"),
	}
	for _, d := range devs {
		s.discovery.Upsert(d)
	}
	if _, err := s.sites.Upsert(Site{TenantID: "t1", Slug: "boston", Name: "Boston"}); err != nil {
		t.Fatal(err)
	}
	if err := s.bindDeviceSite(devs[2], "boston", claims); err != nil {
		t.Fatal(err)
	}

	preview, tenant, err := s.adoptionPlan(claims)
	if err != nil || tenant != "t1" {
		t.Fatalf("plan: %v %q", err, tenant)
	}
	if len(preview.Sites) != 2 || preview.Summary["create"] != 2 || preview.Summary["bind"] != 3 || preview.Summary["skip"] != 1 {
		t.Fatalf("preview = %+v", preview)
	}
	// Preview writes nothing.
	if n := len(s.sites.All("t1", false)); n != 1 {
		t.Fatalf("preview wrote sites: %d", n)
	}

	applied := s.applyAdoption(claims, tenant, preview)
	// preview == apply: the same sites, slugs and rows, now performed.
	if len(applied.Sites) != len(preview.Sites) || applied.Summary["create"] != 2 || applied.Summary["bind"] != 3 || applied.Summary["error"] != 0 {
		t.Fatalf("applied = %+v", applied)
	}
	for _, slug := range []string{"site-50", "site-250"} {
		st, ok := s.sites.Get("t1", false, slug)
		if !ok || st.TenantID != "t1" || st.UpdatedBy != "ops" {
			t.Fatalf("site %s = %+v ok=%v", slug, st, ok)
		}
	}
	if st, _ := s.sites.Get("t1", false, "site-50"); st.Name != "Site 50" {
		t.Fatalf("adopted name = %q", st.Name)
	}
	for _, id := range []string{"d1", "d2"} {
		if b, ok := s.deviceSites.Get("t1", false, id); !ok || b.Site != "site-50" || b.TenantID != "t1" {
			t.Fatalf("%s binding = %+v ok=%v", id, b, ok)
		}
	}
	if b, _ := s.deviceSites.Get("t1", false, "d3"); b.Site != "boston" {
		t.Fatalf("a manual binding was touched: %+v", b)
	}

	// Idempotent: a second plan is empty and a second apply changes nothing.
	again, _, _ := s.adoptionPlan(claims)
	if len(again.Sites) != 0 {
		t.Fatalf("second plan = %+v", again.Sites)
	}
	if n := len(s.sites.All("t1", false)); n != 3 {
		t.Fatalf("sites after adoption = %d", n)
	}

	// Renamed afterwards: the binding holds (by slug) and the device resolves
	// as a MANUAL site under the new name.
	if _, err := s.sites.Upsert(Site{TenantID: "t1", Slug: "site-50", Name: "Branch Boston North"}); err != nil {
		t.Fatal(err)
	}
	r := s.siteContextFor(claims, nil).resolveAll(s.visibleDevicesFor(claims))
	if r["d1"].Source != siteres.SourceManual || r["d1"].Label != "Branch Boston North" || r["d1"].Note != "" {
		t.Fatalf("after rename: %+v", r["d1"])
	}
}

// A binding that appears between preview and apply wins; the apply skips it.
func TestAdoptApplyRechecksBindings(t *testing.T) {
	s := newSiteTestServer(t)
	claims := jwtClaims{Sub: "ops", Role: RoleOperator, Tenant: "t1"}
	d := vmanageDev("d1", "vEdge-51", "t1", "50")
	s.discovery.Upsert(d)
	plan, tenant, err := s.adoptionPlan(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.sites.Upsert(Site{TenantID: "t1", Slug: "elsewhere", Name: "Elsewhere"}); err != nil {
		t.Fatal(err)
	}
	if err := s.bindDeviceSite(d, "elsewhere", claims); err != nil {
		t.Fatal(err)
	}
	applied := s.applyAdoption(claims, tenant, plan)
	if applied.Summary["bind"] != 0 || applied.Summary["skip"] != 1 {
		t.Fatalf("summary = %v", applied.Summary)
	}
	if b, _ := s.deviceSites.Get("t1", false, "d1"); b.Site != "elsewhere" {
		t.Fatalf("binding overwritten: %+v", b)
	}
}

// §3a two-org isolation over HTTP: own-only preview, a foreign key adopts
// nothing, as_tenant into another org is ignored, the cross-tenant view must
// pick a tenant, and an adoption never writes into another tenant.
func TestDiscoveredSitesOrgIsolation(t *testing.T) {
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
	for i, name := range []string{"A", "B"} {
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
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
		// Both orgs report the SAME controller site id 50.
		s.discovery.Upsert(vmanageDev("d"+string(rune('1'+i)), "edge-"+name, tenantID, "50"))
	}
	a, b := fix["A"], fix["B"]

	type previewResp struct {
		Adoptable bool         `json:"adoptable"`
		Reason    string       `json:"reason"`
		Plan      siteres.Plan `json:"plan"`
	}
	preview := func(token, asTenant string) previewResp {
		t.Helper()
		path := "/api/discovered-sites"
		if asTenant != "" {
			path += "?as_tenant=" + asTenant
		}
		st, body := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		var r previewResp
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatalf("decode: %v (%s)", err, body)
		}
		return r
	}
	deviceIDs := func(p siteres.Plan) []string {
		var out []string
		for _, st := range p.Sites {
			for _, d := range st.Devices {
				out = append(out, d.DeviceID)
			}
		}
		return out
	}

	// 1) Own-only: each org's preview holds exactly its own device and key.
	pa, pb := preview(a.token, ""), preview(b.token, "")
	if !pa.Adoptable || len(pa.Plan.Sites) != 1 || strings.Join(deviceIDs(pa.Plan), ",") != "d1" {
		t.Fatalf("org A preview = %+v", pa)
	}
	if len(pb.Plan.Sites) != 1 || strings.Join(deviceIDs(pb.Plan), ",") != "d2" {
		t.Fatalf("org B preview = %+v", pb)
	}
	keyA, keyB := pa.Plan.Sites[0].Key, pb.Plan.Sites[0].Key
	if keyA == keyB || !strings.Contains(keyA, strings.ToLower(a.tenantID)) {
		t.Fatalf("keys not tenant-qualified: %q %q", keyA, keyB)
	}

	// 2) as_tenant into the other org is ignored (no binding → override dropped).
	if p := preview(a.token, b.tenantID); strings.Join(deviceIDs(p.Plan), ",") != "d1" {
		t.Fatalf("as_tenant leaked: %+v", p)
	}

	// 3) Naming the other org's key adopts nothing (the key is simply absent
	//    from A's plan — never "forbidden", which would confirm it exists).
	st, body := do(t, srv, "POST", "/api/discovered-sites/adopt", a.token, map[string]any{"dry_run": false, "keys": []string{keyB}})
	if st != 200 || !strings.Contains(string(body), `"sites":[]`) {
		t.Fatalf("foreign-key adopt: %d %s", st, body)
	}
	if got := s.sites.All(b.tenantID, false); len(got) != 0 {
		t.Fatalf("org B got sites from A's request: %+v", got)
	}

	// 4) Dry run (the default) previews exactly what apply performs.
	st, dry := do(t, srv, "POST", "/api/discovered-sites/adopt", a.token, map[string]any{})
	if st != 200 || !strings.Contains(string(dry), `"dry_run":true`) {
		t.Fatalf("dry run: %d %s", st, dry)
	}
	if len(s.sites.All(a.tenantID, false)) != 0 {
		t.Fatal("a dry run wrote a site")
	}
	st, body = do(t, srv, "POST", "/api/discovered-sites/adopt", a.token, map[string]any{"dry_run": false, "as_tenant": b.tenantID})
	if st != 200 {
		t.Fatalf("apply: %d %s", st, body)
	}
	var dryR, appR struct {
		Plan siteres.Plan `json:"plan"`
	}
	if json.Unmarshal(dry, &dryR) != nil || json.Unmarshal(body, &appR) != nil {
		t.Fatal("decode adopt responses")
	}
	if len(dryR.Plan.Sites) != 1 || len(appR.Plan.Sites) != 1 || dryR.Plan.Sites[0].Slug != appR.Plan.Sites[0].Slug ||
		dryR.Plan.Summary["bind"] != appR.Plan.Summary["bind"] {
		t.Fatalf("preview != apply: %+v vs %+v", dryR.Plan, appR.Plan)
	}

	// 5) The site is A's (stamped from the principal); B is untouched and
	//    still offered its own site 50.
	sa := s.sites.All(a.tenantID, false)
	if len(sa) != 1 || sa[0].TenantID != strings.ToLower(a.tenantID) || sa[0].Slug != "site-50" {
		t.Fatalf("org A sites = %+v", sa)
	}
	if len(s.sites.All(b.tenantID, false)) != 0 {
		t.Fatal("org B received a site")
	}
	if _, ok := s.deviceSites.Get(b.tenantID, false, "d2"); ok {
		t.Fatal("org B's device was bound by org A")
	}
	if p := preview(b.token, ""); len(p.Plan.Sites) != 1 || p.Plan.Sites[0].Action != siteres.ActionCreate {
		t.Fatalf("org B preview after A's adoption = %+v", p)
	}
	// B cannot read A's adopted site.
	if st, _ := do(t, srv, "GET", "/api/sites/site-50", b.token, nil); st != 404 {
		t.Fatalf("org B GET org A's adopted site: %d, want 404", st)
	}

	// 6) The cross-tenant platform view must pick a tenant first.
	if p := preview(admin, ""); p.Adoptable || p.Reason == "" || len(p.Plan.Sites) != 0 {
		t.Fatalf("cross-tenant preview = %+v", p)
	}
	if st, _ := do(t, srv, "POST", "/api/discovered-sites/adopt", admin, map[string]any{"dry_run": false}); st != 400 {
		t.Fatalf("cross-tenant adopt: %d, want 400", st)
	}
}
