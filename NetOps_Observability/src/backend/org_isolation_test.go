// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// org_isolation_test.go — end-to-end CROSS-ORG isolation, exercised through the
// REAL router + auth middleware (httptest), the way the running system behaves
// (not the docs). Three orgs (A, B, C) each with one tenant and one tenant-scoped
// user; we assert a user in org A sees ONLY org-A data across the SoT/geo feature
// surface, can never read/delete/switch into org B's, and that the platform owner
// sees all. This is the regression guard for the P1 "every org gets a unique view"
// invariant on the features touched in the SoT/geo work.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
)

type orgFixture struct {
	orgID, tenantID, user, token, siteSlug string
}

// idOf pulls {"id":...} from a create response.
func idOf(t *testing.T, body []byte) string {
	t.Helper()
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.ID == "" {
		t.Fatalf("no id in response: %s", body)
	}
	return r.ID
}

func TestCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	// The shared harness doesn't wire these two stores; the handlers read them at
	// request time, so setting them on the live *server is enough.
	dir := t.TempDir()
	var err error
	if s.sites, err = newSitesStore(filepath.Join(dir, "sites.json")); err != nil {
		t.Fatal(err)
	}
	if s.deviceLocations, err = newDeviceLocationStore(filepath.Join(dir, "loc.json")); err != nil {
		t.Fatal(err)
	}

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// ── build org A, B, C, each: org → tenant → tenant-scoped operator ───────────
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B", "C"} {
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
	}

	// ── each user creates a site in its own tenant (distinct slug per org) ───────
	for _, name := range []string{"A", "B", "C"} {
		f := fix[name]
		st, b := do(t, srv, "POST", "/api/sites", f.token, map[string]any{
			"name": "Site " + name, "lat": 10 + float64(name[0]), "lng": 20 + float64(name[0]),
		})
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
	}

	// helper: list site slugs visible to a token
	listSites := func(token string, asTenant string) []string {
		path := "/api/sites"
		if asTenant != "" {
			path += "?as_tenant=" + asTenant
		}
		st, b := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, b)
		}
		var r struct {
			Sites []Site `json:"sites"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("decode sites: %v (%s)", err, b)
		}
		out := make([]string, 0, len(r.Sites))
		for _, s := range r.Sites {
			out = append(out, s.Slug)
		}
		return out
	}

	a, b, c := fix["A"], fix["B"], fix["C"]

	// 1) Each org user sees ONLY its own site — never another org's.
	for _, name := range []string{"A", "B", "C"} {
		f := fix[name]
		got := listSites(f.token, "")
		if len(got) != 1 || got[0] != f.siteSlug {
			t.Fatalf("org %s leak: GET /api/sites = %v, want exactly [%s]", name, got, f.siteSlug)
		}
	}

	// 2) The platform owner sees all three.
	if all := listSites(admin, ""); len(all) != 3 {
		t.Fatalf("platform owner sees %v, want 3 sites", all)
	}

	// 3) user-A cannot READ org-B's site (404, never reveal it exists).
	if st, _ := do(t, srv, "GET", "/api/sites/"+b.siteSlug, a.token, nil); st != 404 {
		t.Fatalf("user-A GET org-B site: %d, want 404", st)
	}

	// 4) user-A cannot DELETE org-B's site, and it survives.
	if st, _ := do(t, srv, "DELETE", "/api/sites/"+b.siteSlug, a.token, nil); st != 404 {
		t.Fatalf("user-A DELETE org-B site: %d, want 404", st)
	}
	if got := listSites(b.token, ""); len(got) != 1 || got[0] != b.siteSlug {
		t.Fatalf("org-B site wrongly affected by A's delete: %v", got)
	}

	// 5) user-A cannot PUT-overwrite org-B's site (404 — no cross-tenant hijack).
	if st, _ := do(t, srv, "PUT", "/api/sites/"+b.siteSlug, a.token,
		map[string]any{"name": "PWNED", "lat": 0, "lng": 0}); st != 404 {
		t.Fatalf("user-A PUT org-B site: %d, want 404", st)
	}

	// 6) user-A cannot SWITCH into org-B's tenant (no binding → override ignored).
	if got := listSites(a.token, b.tenantID); len(got) != 1 || got[0] != a.siteSlug {
		t.Fatalf("user-A ?as_tenant=%s leaked: %v, want only [%s]", b.tenantID, got, a.siteSlug)
	}

	// 7) Geomap is scoped the same way: user-A's geomap carries only org-A's site.
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
	for _, gs := range geo.Sites {
		if gs.Slug == b.siteSlug || gs.Slug == c.siteSlug {
			t.Fatalf("geomap cross-org leak: org-A saw %q", gs.Slug)
		}
	}

	// 8) Sanity: the reach primitive itself denies cross-org for a tenant user.
	if s.reachesTenant(a.user, b.tenantID) {
		t.Fatalf("reachesTenant(%s, %s) = true — cross-org reach leak", a.user, b.tenantID)
	}
	_ = fmt.Sprint(c.orgID) // c used above; keep referenced
}
