// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// appid_status_isolation_test.go — CLAUDE.md §3a for the App-ID coverage read,
// GET "/api/appid/status" (tracker 244), through the REAL router + auth
// middleware (httptest), two orgs each with its own tenant, operator user,
// firewall attributions, cloud identity mappings and operator overrides.
//
// The bug this pins: the route is requirePerm(infrastructure, read) — a
// TENANT-scoped surface — yet it summed `ngfw_attributions` and
// `cloud_attributions` across EVERY tenant's bucket, so org A's coverage card
// carried org B's numbers. Counts are data: "how many destinations another
// customer's firewall has classified" is that customer's, not ours.
//
// What is asserted here:
//   1. each tenant's counts equal ONLY its own bucket (and are NOT the
//      platform-wide total, so the guard cannot pass vacuously);
//   2. the response labels the reading — scope:"tenant" plus the tenant id;
//   3. as_tenant into ANOTHER org is ignored (the switcher can only narrow):
//      the caller still gets its own tenant's numbers under its own tenant id;
//   4. the platform owner's default (cross) view is the only reading that spans
//      tenants, and it says so: scope:"platform";
//   5. the platform owner narrowed with as_tenant sees exactly that tenant —
//      scope:"tenant", that tenant's counts, nothing summed;
//   6. one layer down, on the rows those counts summarize
//      ("/api/appid/catalog" + "/api/appid/catalog/{id}"): rows are stamped from
//      the token, the list is own-only, as_tenant across an org is ignored, and
//      deleting another org's row returns the SAME 404 an unknown id does.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/appid"
	"netops/backend/cloud"
)

// appIDStatusView is the coverage response as a consumer reads it.
type appIDStatusView struct {
	Scope             string `json:"scope"`
	Tenant            string `json:"tenant"`
	CatalogPrefixes   int    `json:"catalog_prefixes"`
	CatalogDomains    int    `json:"catalog_domains"`
	NgfwAttributions  int    `json:"ngfw_attributions"`
	CloudAttributions int    `json:"cloud_attributions"`
	TenantOverrides   int    `json:"tenant_overrides"`
	TenantOverridePfx int    `json:"tenant_override_pfx"`
	TenantOverrideDom int    `json:"tenant_override_dom"`
}

func appIDStatus(t *testing.T, srv *httptest.Server, token, query string) appIDStatusView {
	t.Helper()
	path := "/api/appid/status"
	if query != "" {
		path += "?" + query
	}
	st, body := do(t, srv, "GET", path, token, nil)
	if st != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, st, body)
	}
	var out appIDStatusView
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode status: %v (%s)", err, body)
	}
	return out
}

func TestAppIDStatusTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// ── two orgs, each: org → tenant → tenant-scoped operator ───────────────
	type party struct{ orgID, tenantID, token string }
	parties := map[string]*party{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "AppID Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "AppID Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "appid-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		parties[name] = &party{orgID: orgID, tenantID: strings.ToLower(tenantID),
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := parties["A"], parties["B"]

	// ── the engine's stores, seeded with DISTINCT per-tenant volumes ────────
	// The vendor feed stays empty (public data, owned by no tenant); what is
	// seeded here is exactly the tenant-partitioned material.
	s.appCatalog = appid.NewCatalogHolder("")

	// Firewall app-id overlay: A has 2 destinations, B has 3, and one untagged
	// (platform-owned telemetry) row lives in the "" bucket → platform total 6.
	s.ngfw = newNgfwAppResolver()
	ngfwMap := buildNgfwAppMap([]ngfwDoc{
		{TenantID: a.tenantID, AppID: "salesforce", AppDst: "10.1.0.1"},
		{TenantID: a.tenantID, AppID: "office365", AppDst: "10.1.0.2"},
		{TenantID: b.tenantID, AppID: "workday", AppDst: "10.2.0.1"},
		{TenantID: b.tenantID, AppID: "zoom", AppDst: "10.2.0.2"},
		{TenantID: b.tenantID, AppID: "slack", AppDst: "10.2.0.3"},
		{TenantID: "", AppID: "netops", AppDst: "10.9.0.1"},
	})
	s.ngfw.cur.Store(&ngfwMap)

	// Cloud identity-map: A has 1 key, B has 4 → platform total 5.
	s.cloudApp = appid.NewCloudResolver(nil)
	s.cloudApp.SeedForTest([]cloud.CloudIdentityMapping{
		{TenantID: a.tenantID, MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.1.1.1", AppName: "billing", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: b.tenantID, MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.2.1.1", AppName: "payroll", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: b.tenantID, MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.2.1.2", AppName: "payroll", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: b.tenantID, MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.2.1.3", AppName: "payroll", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: b.tenantID, MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.2.1.4", AppName: "payroll", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
	})

	// Operator overrides, created BY each tenant's own user through the real
	// route (the tenant is stamped from the token, §3a.2): A one prefix, B one
	// prefix + one domain. The harness does not wire the override store, so
	// build the production in-memory one (newServer's newAppCatalogStore).
	s.appOverrides = newAppCatalogStore()
	newOverride := func(token, kind, value, label string) AppCatalogEntry {
		t.Helper()
		st, body := do(t, srv, "POST", "/api/appid/catalog", token, map[string]any{
			"match_kind": kind, "match_value": value, "app_label": label,
		})
		if st != 201 {
			t.Fatalf("create override %s=%s: %d %s", kind, value, st, body)
		}
		var out AppCatalogEntry
		if err := json.Unmarshal(body, &out); err != nil || out.CatalogID == "" {
			t.Fatalf("create override %s=%s: no row in %s (%v)", kind, value, body, err)
		}
		return out
	}
	rowA := newOverride(a.token, "prefix", "192.0.2.0/24", "orgA-app")
	rowB := newOverride(b.token, "prefix", "198.51.100.0/24", "orgB-app")
	newOverride(b.token, "domain", "orgb.example.com", "orgB-web")
	// §3a.2: the row is stamped from the TOKEN, never the body.
	if rowA.TenantID != a.tenantID || rowB.TenantID != b.tenantID {
		t.Fatalf("override rows not stamped with the caller's tenant: %q / %q", rowA.TenantID, rowB.TenantID)
	}

	// 1) each tenant sees ONLY its own attributions, labelled with its own id.
	sa := appIDStatus(t, srv, a.token, "")
	if sa.Scope != "tenant" || sa.Tenant != a.tenantID {
		t.Fatalf("org A scope label = %q/%q, want tenant/%s", sa.Scope, sa.Tenant, a.tenantID)
	}
	if sa.NgfwAttributions != 2 {
		t.Fatalf("TENANT LEAK: org A ngfw_attributions = %d, want 2 (its own bucket; platform total is 6)", sa.NgfwAttributions)
	}
	if sa.CloudAttributions != 1 {
		t.Fatalf("TENANT LEAK: org A cloud_attributions = %d, want 1 (its own bucket; platform total is 5)", sa.CloudAttributions)
	}
	if sa.TenantOverrides != 1 || sa.TenantOverridePfx != 1 || sa.TenantOverrideDom != 0 {
		t.Fatalf("org A overrides = %d (pfx %d, dom %d), want 1/1/0", sa.TenantOverrides, sa.TenantOverridePfx, sa.TenantOverrideDom)
	}

	// 2) the mirror view: org B's own numbers, never org A's, never the sum.
	sb := appIDStatus(t, srv, b.token, "")
	if sb.Scope != "tenant" || sb.Tenant != b.tenantID {
		t.Fatalf("org B scope label = %q/%q, want tenant/%s", sb.Scope, sb.Tenant, b.tenantID)
	}
	if sb.NgfwAttributions != 3 || sb.CloudAttributions != 4 {
		t.Fatalf("TENANT LEAK: org B counts = ngfw %d / cloud %d, want 3 / 4", sb.NgfwAttributions, sb.CloudAttributions)
	}
	if sb.TenantOverrides != 2 || sb.TenantOverridePfx != 1 || sb.TenantOverrideDom != 1 {
		t.Fatalf("org B overrides = %d (pfx %d, dom %d), want 2/1/1", sb.TenantOverrides, sb.TenantOverridePfx, sb.TenantOverrideDom)
	}
	// Anti-vacuity: neither tenant may be reading the platform-wide total (6
	// firewall / 5 cloud), and the two tenants must not read the same numbers.
	if sa.NgfwAttributions == 6 || sb.NgfwAttributions == 6 || sa.CloudAttributions == 5 || sb.CloudAttributions == 5 {
		t.Fatalf("a tenant read the platform-wide total: A=%+v B=%+v", sa, sb)
	}
	if sa.NgfwAttributions == sb.NgfwAttributions && sa.CloudAttributions == sb.CloudAttributions {
		t.Fatalf("both tenants read identical counts (%+v / %+v) — the scoping is not doing anything", sa, sb)
	}

	// 3) as_tenant into ANOTHER org is IGNORED — org A stays org A. The
	// switcher narrows within reach; it never crosses an org boundary.
	crossA := appIDStatus(t, srv, a.token, "as_tenant="+b.tenantID)
	if crossA.Tenant != a.tenantID || crossA.Scope != "tenant" {
		t.Fatalf("as_tenant into org B changed the scope label: %q/%q", crossA.Scope, crossA.Tenant)
	}
	if crossA.NgfwAttributions != 2 || crossA.CloudAttributions != 1 || crossA.TenantOverrides != 1 {
		t.Fatalf("TENANT LEAK: org A with as_tenant=orgB read %+v, want its own 2/1/1", crossA)
	}

	// 4) the platform owner's default view is cross-tenant and SAYS SO.
	plat := appIDStatus(t, srv, admin, "")
	if plat.Scope != "platform" {
		t.Fatalf("platform owner scope = %q, want platform", plat.Scope)
	}
	if plat.NgfwAttributions != 6 || plat.CloudAttributions != 5 {
		t.Fatalf("platform totals = ngfw %d / cloud %d, want 6 / 5", plat.NgfwAttributions, plat.CloudAttributions)
	}

	// 5) the platform owner narrowed to org B reads org B's numbers only.
	platB := appIDStatus(t, srv, admin, "as_tenant="+b.tenantID)
	if platB.Scope != "tenant" || platB.Tenant != b.tenantID {
		t.Fatalf("narrowed platform view label = %q/%q, want tenant/%s", platB.Scope, platB.Tenant, b.tenantID)
	}
	if platB.NgfwAttributions != 3 || platB.CloudAttributions != 4 || platB.TenantOverrides != 2 {
		t.Fatalf("narrowed platform view = %+v, want org B's 3/4/2", platB)
	}

	// 6) the vendor feed is public reference data owned by no tenant: identical
	// for every reading, and not a place a tenant's rows can hide.
	if sa.CatalogPrefixes != sb.CatalogPrefixes || sa.CatalogDomains != sb.CatalogDomains {
		t.Fatalf("vendor feed counts differ per tenant (%d/%d vs %d/%d) — the feed is global public data",
			sa.CatalogPrefixes, sa.CatalogDomains, sb.CatalogPrefixes, sb.CatalogDomains)
	}
	// ── the rows behind those counts: /api/appid/catalog[/{id}] ─────────────
	// The same §3a proof one layer down, on the surface the coverage numbers
	// summarize: own-only list, another org's id is not even acknowledged, and
	// as_tenant across an org boundary is ignored.
	listOverrides := func(token, query string) []AppCatalogEntry {
		t.Helper()
		path := "/api/appid/catalog"
		if query != "" {
			path += "?" + query
		}
		st, body := do(t, srv, "GET", path, token, nil)
		if st != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		var out struct {
			Entries []AppCatalogEntry `json:"entries"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode overrides: %v (%s)", err, body)
		}
		return out.Entries
	}

	ownA := listOverrides(a.token, "")
	if len(ownA) != 1 || ownA[0].CatalogID != rowA.CatalogID {
		t.Fatalf("TENANT LEAK: org A override list = %+v, want only its own row", ownA)
	}
	if got := listOverrides(b.token, ""); len(got) != 2 {
		t.Fatalf("org B override list = %d rows, want its own 2: %+v", len(got), got)
	}
	// as_tenant into org B is ignored — org A still lists org A.
	if got := listOverrides(a.token, "as_tenant="+b.tenantID); len(got) != 1 || got[0].CatalogID != rowA.CatalogID {
		t.Fatalf("TENANT LEAK: org A with as_tenant=orgB listed %+v", got)
	}
	// A cross-tenant DELETE is refused with the SAME 404 an unknown id gets —
	// another org's id is never acknowledged.
	if st, body := do(t, srv, "DELETE", "/api/appid/catalog/"+rowB.CatalogID, a.token, nil); st != http.StatusNotFound {
		t.Fatalf("TENANT LEAK: org A deleting org B's override: %d %s, want 404", st, body)
	}
	unknown := "11111111-1111-4111-8111-111111111111"
	if st, _ := do(t, srv, "DELETE", "/api/appid/catalog/"+unknown, a.token, nil); st != http.StatusNotFound {
		t.Fatalf("unknown override id must 404 like a cross-tenant one")
	}
	// org B's row survived that attempt, and its owner can delete it.
	if got := listOverrides(b.token, ""); len(got) != 2 {
		t.Fatalf("org B lost a row to org A's delete attempt: %+v", got)
	}
	if st, body := do(t, srv, "DELETE", "/api/appid/catalog/"+rowB.CatalogID, b.token, nil); st != http.StatusOK {
		t.Fatalf("org B could not delete its own override: %d %s", st, body)
	}
}
