// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// dem_alert_isolation_test.go — §3a cross-org isolation guard for DEVICE-LESS
// alerts that nonetheless have an owning tenant.
//
// THE DEFECT. The Digital Experience rules (noc-experience in rules.yaml)
// aggregate by (tenant, target, kind, site, app) and carry no `device` label, so
// the in-API engine publishes them with DeviceID "". Every consumer treated an
// empty device as "platform-global, visible to everyone", so a read-only user of
// tenant B was served tenant A's target hostname, site, app and latency numbers.
//
// THE RULE THIS PINS. Device-less means platform-global ONLY when nothing owns
// the alert. An alert whose owning tenant resolves (server.alertTenant) belongs
// to that tenant alone — on EVERY surface, not just the one that was reported.
// The positive half matters just as much: the owning tenant must still see its
// own targets, so the leak cannot be "fixed" by blanking the field for all.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
)

// demTarget is the string that must never cross the tenant wall.
const demTarget = "shop.acme.example"

func TestDigitalExperienceAlertCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)
	store := newAlertEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"))
	store.SetNowForTest(func() time.Time { return time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC) })
	s.alertEpisodes = store

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

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
		user := "dem-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	s.discovery.Upsert(models.Device{ID: "dev-a", Name: "dev-a", TenantID: a.tenantID})
	s.discovery.Upsert(models.Device{ID: "dev-b", Name: "dev-b", TenantID: b.tenantID})

	// Tenant A's experience alert: no device, but a tenant label our OWN prober
	// wrote from the catalogue row, and a summary carrying A's target name.
	expA := models.Alert{
		ID: "exp-a", Rule: "ExperienceLatencyOverBudget", Severity: "critical",
		Summary:     "Experience target " + demTarget + " (https) p95 is 812 ms, over its declared budget",
		Description: "Site HQ, app checkout.",
		Labels:      map[string]string{"tenant": a.tenantID, "target": demTarget, "kind": "https", "site": "HQ", "app": "checkout"},
		FiredAt:     time.Now().UTC(),
	}
	// A genuinely platform-owned stack alert: no device AND no owner. It must
	// stay visible to everyone — that is the behaviour the fix must not break.
	stack := models.Alert{
		ID: "stack-1", Rule: "StackDiskLow", Severity: "critical",
		Summary: "platform disk is nearly full", FiredAt: time.Now().UTC(),
	}
	devB := models.Alert{
		ID: "dev-b-1", Rule: "HighCPU", Severity: "critical", DeviceID: "dev-b",
		Summary: "dev-b cpu high", FiredAt: time.Now().UTC(),
	}
	s.alerts.SeedActiveForTest(expA, stack, devB)

	// The same three folded into episodes, which carry the summary too.
	s.observeAlertTransition(expA, true)
	s.observeAlertTransition(stack, true)
	s.observeAlertTransition(devB, true)

	leak := func(t *testing.T, surface string, body []byte) {
		t.Helper()
		if strings.Contains(string(body), demTarget) {
			t.Errorf("TENANT LEAK on %s: org-B user was served org-A's experience target %q\n%s", surface, demTarget, body)
		}
	}
	sees := func(t *testing.T, surface string, body []byte) {
		t.Helper()
		if !strings.Contains(string(body), demTarget) {
			t.Errorf("%s: the OWNING tenant can no longer see its own experience target %q — the leak must not be fixed by blanking the field\n%s", surface, demTarget, body)
		}
	}

	// ── 1. GET /api/alerts (main.go handleAlerts) ────────────────────────────
	st, body := do(t, srv, "GET", "/api/alerts", b.token, nil)
	if st != 200 {
		t.Fatalf("B /api/alerts: %d %s", st, body)
	}
	leak(t, "GET /api/alerts", body)
	if !strings.Contains(string(body), "platform disk") {
		t.Errorf("GET /api/alerts: an UNOWNED stack alert must stay visible to every tenant\n%s", body)
	}
	if !strings.Contains(string(body), "dev-b cpu high") {
		t.Errorf("GET /api/alerts: tenant B lost its own device alert\n%s", body)
	}
	st, body = do(t, srv, "GET", "/api/alerts", a.token, nil)
	if st != 200 {
		t.Fatalf("A /api/alerts: %d %s", st, body)
	}
	sees(t, "GET /api/alerts", body)

	// ── 2. GET /api/alerts/episodes (alerts.EpisodeStore.List) ───────────────
	st, body = do(t, srv, "GET", "/api/alerts/episodes", b.token, nil)
	if st != 200 {
		t.Fatalf("B episodes: %d %s", st, body)
	}
	leak(t, "GET /api/alerts/episodes", body)
	if !strings.Contains(string(body), "platform disk") {
		t.Errorf("GET /api/alerts/episodes: an UNOWNED stack episode must stay visible\n%s", body)
	}
	st, body = do(t, srv, "GET", "/api/alerts/episodes", a.token, nil)
	if st != 200 {
		t.Fatalf("A episodes: %d %s", st, body)
	}
	sees(t, "GET /api/alerts/episodes", body)

	// ── 3. POST /api/graphql { alerts } ──────────────────────────────────────
	gql := map[string]any{"query": "{ alerts { id rule summary } }"}
	st, body = do(t, srv, "POST", "/api/graphql", b.token, gql)
	if st != 200 {
		t.Fatalf("B graphql: %d %s", st, body)
	}
	leak(t, "POST /api/graphql alerts", body)
	st, body = do(t, srv, "POST", "/api/graphql", a.token, gql)
	if st != 200 {
		t.Fatalf("A graphql: %d %s", st, body)
	}
	sees(t, "POST /api/graphql alerts", body)

	// ── 4. GET /api/search/global (search_global.go) ─────────────────────────
	st, body = do(t, srv, "GET", "/api/search/global?q=shop.acme", b.token, nil)
	if st != 200 {
		t.Fatalf("B search: %d %s", st, body)
	}
	leak(t, "GET /api/search/global", body)
	st, body = do(t, srv, "GET", "/api/search/global?q=shop.acme", a.token, nil)
	if st != 200 {
		t.Fatalf("A search: %d %s", st, body)
	}
	sees(t, "GET /api/search/global", body)

	// ── 5. the WebSocket alert feed's per-client filter (tenancy.go) ─────────
	claimsB := jwtClaims{Sub: b.user, Role: "operator", Tenant: b.tenantID}
	claimsA := jwtClaims{Sub: a.user, Role: "operator", Tenant: a.tenantID}
	if s.alertVisibleTo(expA, claimsB) {
		t.Errorf("TENANT LEAK on the WebSocket alert feed: org-B would be broadcast org-A's experience alert")
	}
	if !s.alertVisibleTo(expA, claimsA) {
		t.Errorf("the WebSocket alert feed dropped the owning tenant's own experience alert")
	}
	if !s.alertVisibleTo(stack, claimsB) {
		t.Errorf("the WebSocket alert feed dropped an UNOWNED stack alert")
	}

	// ── 6. the dashboard's Critical Threats tile (dashboard.go) ──────────────
	// B's own critical alerts are its device alert plus the unowned stack one.
	// A's experience alert must not be counted into B's tile.
	if got := criticalThreatTile(t, s.currentMetricTiles(claimsB)); got != "2" {
		t.Errorf("dashboard Critical Threats for org-B is %q, want \"2\" (its device alert + the unowned stack alert) — org-A's experience alert is being counted", got)
	}
	if got := criticalThreatTile(t, s.currentMetricTiles(claimsA)); got != "2" {
		t.Errorf("dashboard Critical Threats for org-A is %q, want \"2\" (its own experience alert + the unowned stack alert)", got)
	}

	// ── 7. the scheduled-report renderer (report_scheduler.go) ───────────────
	rs := newReportScheduler(s, filepath.Join(t.TempDir(), "report_runs.json"))
	for _, al := range rs.tenantAlerts(b.tenantID) {
		if strings.Contains(al.Summary, demTarget) {
			t.Errorf("TENANT LEAK in a scheduled report: org-B's report would render org-A's experience target %q", demTarget)
		}
	}
	ownSeen := false
	for _, al := range rs.tenantAlerts(a.tenantID) {
		if strings.Contains(al.Summary, demTarget) {
			ownSeen = true
		}
	}
	if !ownSeen {
		t.Errorf("a scheduled report for the OWNING tenant lost its own experience alert")
	}

	// ── 8. the topology view (topology_view.go) ──────────────────────────────
	// Device-less alerts are dropped by toAlertFacts (they bind to no node), so
	// nothing renders — but the scoped list must not carry it either.
	st, body = do(t, srv, "GET", "/api/topology/view", b.token, nil)
	if st != 200 {
		t.Fatalf("B topology view: %d %s", st, body)
	}
	leak(t, "GET /api/topology/view", body)
}

func criticalThreatTile(t *testing.T, tiles []MetricTile) string {
	t.Helper()
	for _, tile := range tiles {
		if tile.Title == "Critical Threats" {
			return tile.Value
		}
	}
	t.Fatalf("no Critical Threats tile: %+v", tiles)
	return ""
}

// TestDigitalExperienceEpisodeStaysWithItsTenant is the store-level half: an
// episode with no resource but a real owner is NOT platform-global.
func TestDigitalExperienceEpisodeStaysWithItsTenant(t *testing.T) {
	store := alerts.NewEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"), 15*time.Minute, 6, 15*time.Minute)
	store.Observe("tenant-a", "", "ExperienceLatencyOverBudget", "critical", "Experience target "+demTarget+" p95 is 812 ms", true)
	store.Observe("", "", "StackDiskLow", "critical", "platform disk is nearly full", true)

	eps, _, _ := store.List("tenant-b", false, alerts.EpisodeQuery{})
	for _, ep := range eps {
		if strings.Contains(ep.Summary, demTarget) {
			t.Errorf("TENANT LEAK: tenant-b listed tenant-a's device-less experience episode: %+v", ep)
		}
	}
	if len(eps) != 1 || !strings.Contains(eps[0].Summary, "platform disk") {
		t.Errorf("tenant-b must still see the UNOWNED stack episode and only that: %+v", eps)
	}
	own, _, _ := store.List("tenant-a", false, alerts.EpisodeQuery{})
	found := false
	for _, ep := range own {
		if strings.Contains(ep.Summary, demTarget) {
			found = true
		}
	}
	if !found {
		t.Errorf("the owning tenant lost its own experience episode: %+v", own)
	}
}
