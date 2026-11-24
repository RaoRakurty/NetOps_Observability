// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// site_collection_isolation_test.go — §3a cross-org isolation for the
// device-less SiteCollectionLost alert (tracker 368).
//
// THE RULE THIS PINS. A SiteCollection* alert is owned by its (tenant_id, site)
// label PAIR only when the api itself published that pair in its last
// device-site snapshot (internal/sitecollect). A forged tenant, another
// tenant's site, or a site no device has any more resolves to "" (platform
// only). The membership the api publishes is resolved PER TENANT, so the same
// controller site id in two tenants is two different sites.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/sitecollect"
	"netops/backend/models"
)

func siteLostAlert(id, tenant, site, mark string) models.Alert {
	return models.Alert{
		ID: id, Rule: "SiteCollectionLost", Severity: "critical",
		Summary: "Collection lost for site " + mark,
		Labels:  map[string]string{"tenant_id": tenant, "site": site, "site_label": mark},
		FiredAt: time.Now().UTC(),
	}
}

func TestSiteCollectionAlertCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)
	s.alertEpisodes = newAlertEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"))
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, body := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Site Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, body)
		}
		orgID := idOf(t, body)
		st, body = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Site Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, body)
		}
		tenantID := idOf(t, body)
		user := "site-user-" + name
		st, body = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, body)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// Both tenants have a vManage site "50": the controller's id is the same,
	// the sites are not.
	for _, d := range []models.Device{
		{ID: "a-edge-1", Name: "a-edge-1", TenantID: a.tenantID, Labels: map[string]string{"controller_site_id": "50", "source_system": "vmanage"}},
		{ID: "a-edge-2", Name: "a-edge-2", TenantID: a.tenantID, Labels: map[string]string{"controller_site_id": "50", "source_system": "vmanage"}},
		{ID: "b-edge-1", Name: "b-edge-1", TenantID: b.tenantID, Labels: map[string]string{"controller_site_id": "50", "source_system": "vmanage"}},
		{ID: "a-nosite", Name: "a-nosite", TenantID: a.tenantID},
	} {
		s.discovery.Upsert(d)
	}
	s.siteCollect = sitecollect.New(s.siteMemberships, nil)
	if err := s.siteCollect.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// ── the published membership, read back through the real resolver ───────
	var buf strings.Builder
	s.siteCollect.WriteMetrics(&buf)
	siteOf := map[string]string{}
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.HasPrefix(line, sitecollect.MetricInfo+"{") {
			continue
		}
		dev := between(line, `device="`, `"`)
		siteOf[dev] = between(line, `site="`, `"`)
		if dev == "b-edge-1" && !strings.Contains(line, `tenant_id="`+b.tenantID+`"`) {
			t.Errorf("b-edge-1 published under the wrong tenant: %s", line)
		}
	}
	siteA, siteB := siteOf["a-edge-1"], siteOf["b-edge-1"]
	if siteA == "" || siteB == "" {
		t.Fatalf("controller site ids did not resolve to sites:\n%s", buf.String())
	}
	if siteOf["a-edge-2"] != siteA {
		t.Errorf("one tenant's two edges at site 50 must share a site key: %q vs %q", siteOf["a-edge-2"], siteA)
	}
	if siteA == siteB {
		t.Fatalf("§3a: two tenants' site 50 collapsed into one key %q", siteA)
	}
	if _, ok := siteOf["a-nosite"]; ok {
		t.Error("a device with no site must not be published")
	}

	// ── the owner derivation ──────────────────────────────────────────────
	set := map[string]models.Alert{
		"lostA":   siteLostAlert("site-a", a.tenantID, siteA, "site-mark-A"),
		"lostB":   siteLostAlert("site-b", b.tenantID, siteB, "site-mark-B"),
		"crossed": siteLostAlert("site-x", a.tenantID, siteB, "site-mark-crossed"), // A's tenant, B's site
		"forged":  siteLostAlert("site-f", a.tenantID, "no-such-site", "site-mark-forged"),
	}
	for k, want := range map[string]string{"lostA": a.tenantID, "lostB": b.tenantID, "crossed": "", "forged": ""} {
		if got := s.alertTenant(set[k]); got != want {
			t.Errorf("alertTenant(%s) = %q, want %q", k, got, want)
		}
	}
	// A label alone never makes an owner for any other rule.
	other := set["lostA"]
	other.Rule = "SomethingElse"
	if got := s.alertTenant(other); got != "" {
		t.Errorf("a (tenant_id, site) label on a non-SiteCollection rule must own nothing, got %q", got)
	}

	// ── GET /api/alerts: own only; as_tenant into the other org ignored ───────
	all := []models.Alert{set["lostA"], set["lostB"], set["crossed"], set["forged"]}
	for _, al := range all {
		s.observeAlertTransition(al, true)
	}
	s.alerts.SeedActiveForTest(all...)
	get := func(path, token string) string {
		t.Helper()
		st, body := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		return string(body)
	}
	bodyA := get("/api/alerts", a.token)
	if !strings.Contains(bodyA, "site-mark-A") {
		t.Errorf("tenant A cannot see its own site alert\n%s", bodyA)
	}
	for _, m := range []string{"site-mark-B", "site-mark-crossed", "site-mark-forged"} {
		if strings.Contains(bodyA, m) {
			t.Errorf("LEAK on GET /api/alerts: tenant A was served %q", m)
		}
	}
	bodyB := get("/api/alerts", b.token)
	if !strings.Contains(bodyB, "site-mark-B") || strings.Contains(bodyB, "site-mark-A") {
		t.Errorf("tenant B's view is wrong\n%s", bodyB)
	}
	if body := get("/api/alerts?as_tenant="+b.tenantID, a.token); strings.Contains(body, "site-mark-B") || !strings.Contains(body, "site-mark-A") {
		t.Errorf("?as_tenant=%s widened or blanked tenant A's view\n%s", b.tenantID, body)
	}
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	s = s[i+len(open):]
	j := strings.Index(s, close)
	if j < 0 {
		return ""
	}
	return s[:j]
}
