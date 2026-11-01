// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nms_alert_isolation_test.go — §3a cross-org isolation for NMS connector
// alerts (NMS-first plan F2).
//
// THE DEFECT. alertTenant derived an alert's owner only from its device, so a
// device-less connector alert (NMSIntegrationDown: "your vManage stopped
// answering") was platform-owned — the tenant whose controller it is never saw
// it. The visibility chokepoint used a separate free function, so fixing one of
// the two would have left the episode owned by the tenant while the alert list
// still hid it (or the reverse).
//
// THE RULE THIS PINS. One derivation, s.alertOwner, for both. An NMS* alert is
// owned by its (tenant_id, integration_id) label pair ONLY when that exact pair
// is an enabled integration in the NMS runtime's snapshot; anything else —
// a forged tenant_id, a disabled integration, an id enabled only under another
// tenant — is platform-only. Device alerts are unchanged.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
	"netops/backend/nms"
)

const (
	nmsMarkA      = "ctl-acme-a.example"   // in tenant A's connector alert
	nmsMarkB      = "ctl-acme-b.example"   // in tenant B's connector alert (SAME integration id)
	nmsMarkForged = "forged-ctl.example"   // tenant_id=A, integration id not enabled anywhere
	nmsMarkOff    = "disabled-ctl.example" // tenant_id=B, integration disabled
	nmsSharedID   = "vmanage-1"            // integration ids are unique only per tenant
)

func nmsDownAlert(id, tenant, integration, mark string) models.Alert {
	return models.Alert{
		ID: id, Rule: "NMSIntegrationDown", Severity: "warning",
		Summary: "NMS integration " + integration + " (" + mark + ") is not answering",
		Labels:  map[string]string{"tenant_id": tenant, "integration_id": integration, "vendor": "cisco_sdwan"},
		FiredAt: time.Now().UTC(),
	}
}

// nmsTwoOrgFixture builds two orgs with one tenant + operator each, an NMS
// runtime whose snapshot holds (A, vmanage-1) and (B, vmanage-1) enabled and
// (B, off-1) disabled, and the alert set the test asserts on.
func nmsTwoOrgFixture(t *testing.T) (srv *httptest.Server, s *server, admin string, a, b *orgFixture, set map[string]models.Alert) {
	t.Helper()
	srv, s = newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)
	store := newAlertEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"))
	store.SetNowForTest(func() time.Time { return time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC) })
	s.alertEpisodes = store

	admin = login(t, srv, "admin", "Passw0rd!2345").Token
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, body := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "NMS Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, body)
		}
		orgID := idOf(t, body)
		st, body = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "NMS Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, body)
		}
		tenantID := idOf(t, body)
		user := "nms-user-" + name
		st, body = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, body)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b = fix["A"], fix["B"]

	ctx := context.Background()
	mem := nms.NewMemStore()
	for _, ic := range []nms.Integration{
		{Tenant: a.tenantID, ID: nmsSharedID, Vendor: "cisco_sdwan", Enabled: true},
		{Tenant: b.tenantID, ID: nmsSharedID, Vendor: "cisco_sdwan", Enabled: true},
		{Tenant: b.tenantID, ID: "off-1", Vendor: "cisco_sdwan", Enabled: false},
	} {
		if err := mem.Upsert(ctx, ic); err != nil {
			t.Fatal(err)
		}
	}
	s.nms = newNMSRuntime(mem)
	if _, err := s.nms.RefreshEnabled(ctx); err != nil {
		t.Fatal(err)
	}

	s.discovery.Upsert(models.Device{ID: "nms-dev-a", Name: "nms-dev-a", TenantID: a.tenantID})
	s.discovery.Upsert(models.Device{ID: "nms-dev-b", Name: "nms-dev-b", TenantID: b.tenantID})

	set = map[string]models.Alert{
		"nmsA":   nmsDownAlert("nms-a", a.tenantID, nmsSharedID, nmsMarkA),
		"nmsB":   nmsDownAlert("nms-b", b.tenantID, nmsSharedID, nmsMarkB),
		"forged": nmsDownAlert("nms-forged", a.tenantID, "not-enabled", nmsMarkForged),
		"off":    nmsDownAlert("nms-off", b.tenantID, "off-1", nmsMarkOff),
		"devA": {ID: "dev-a-1", Rule: "HighCPU", Severity: "critical", DeviceID: "nms-dev-a",
			Summary: "nms-dev-a cpu high", FiredAt: time.Now().UTC()},
		"devB": {ID: "dev-b-1", Rule: "HighCPU", Severity: "critical", DeviceID: "nms-dev-b",
			Summary: "nms-dev-b cpu high", FiredAt: time.Now().UTC()},
	}
	all := make([]models.Alert, 0, len(set))
	for _, k := range []string{"nmsA", "nmsB", "forged", "off", "devA", "devB"} {
		all = append(all, set[k])
		s.observeAlertTransition(set[k], true)
	}
	s.alerts.SeedActiveForTest(all...)
	return srv, s, admin, a, b, set
}

func TestNMSAlertCrossOrgIsolation(t *testing.T) {
	srv, s, admin, a, b, set := nmsTwoOrgFixture(t)

	contains := func(body []byte, mark string) bool { return strings.Contains(string(body), mark) }
	get := func(t *testing.T, path, token string) []byte {
		t.Helper()
		st, body := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		return body
	}

	// ── the owner derivation itself (episodes + incidents use alertTenant) ───
	for k, want := range map[string]string{
		"nmsA": a.tenantID, "nmsB": b.tenantID, "forged": "", "off": "",
		"devA": a.tenantID, "devB": b.tenantID,
	} {
		if got := s.alertTenant(set[k]); got != want {
			t.Errorf("alertTenant(%s) = %q, want %q", k, got, want)
		}
	}

	// ── GET /api/alerts ──────────────────────────────────────────────────────
	bodyA := get(t, "/api/alerts", a.token)
	if !contains(bodyA, nmsMarkA) {
		t.Errorf("tenant A cannot see its own connector alert\n%s", bodyA)
	}
	for _, m := range []string{nmsMarkB, nmsMarkForged, nmsMarkOff, "nms-dev-b cpu"} {
		if contains(bodyA, m) {
			t.Errorf("LEAK on GET /api/alerts: tenant A was served %q\n%s", m, bodyA)
		}
	}
	if !contains(bodyA, "nms-dev-a cpu") {
		t.Errorf("regression: tenant A lost its own device alert\n%s", bodyA)
	}
	bodyB := get(t, "/api/alerts", b.token)
	if !contains(bodyB, nmsMarkB) {
		t.Errorf("tenant B cannot see its own connector alert (same integration id as A)\n%s", bodyB)
	}
	for _, m := range []string{nmsMarkA, nmsMarkForged, nmsMarkOff, "nms-dev-a cpu"} {
		if contains(bodyB, m) {
			t.Errorf("LEAK on GET /api/alerts: tenant B was served %q\n%s", m, bodyB)
		}
	}
	bodyAdmin := get(t, "/api/alerts", admin)
	for _, m := range []string{nmsMarkA, nmsMarkB, nmsMarkForged, nmsMarkOff, "nms-dev-a cpu", "nms-dev-b cpu"} {
		if !contains(bodyAdmin, m) {
			t.Errorf("the cross-tenant platform view lost %q\n%s", m, bodyAdmin)
		}
	}

	// ── ?as_tenant / X-Acting-Tenant into the other org are ignored ──────────
	if body := get(t, "/api/alerts?as_tenant="+b.tenantID, a.token); contains(body, nmsMarkB) || !contains(body, nmsMarkA) {
		t.Errorf("?as_tenant=%s widened or blanked tenant A's alert view\n%s", b.tenantID, body)
	}
	if body := get(t, "/api/alerts/episodes?as_tenant="+b.tenantID, a.token); contains(body, nmsMarkB) {
		t.Errorf("?as_tenant=%s served tenant B's connector episode to tenant A\n%s", b.tenantID, body)
	}

	// ── GET /api/alerts/episodes ─────────────────────────────────────────────
	type listResp struct {
		Episodes []AlertEpisode `json:"episodes"`
	}
	episodes := func(token string) []AlertEpisode {
		t.Helper()
		var lr listResp
		if err := json.Unmarshal(get(t, "/api/alerts/episodes", token), &lr); err != nil {
			t.Fatal(err)
		}
		return lr.Episodes
	}
	idBySummary := func(eps []AlertEpisode, mark string) string {
		for _, ep := range eps {
			if strings.Contains(ep.Summary, mark) {
				return ep.ID
			}
		}
		return ""
	}
	epsA := episodes(a.token)
	if idBySummary(epsA, nmsMarkA) == "" {
		t.Errorf("tenant A cannot list its own connector episode: %+v", epsA)
	}
	for _, m := range []string{nmsMarkB, nmsMarkForged, nmsMarkOff} {
		if idBySummary(epsA, m) != "" {
			t.Errorf("LEAK on GET /api/alerts/episodes: tenant A listed %q", m)
		}
	}
	if idBySummary(episodes(b.token), nmsMarkB) == "" {
		t.Errorf("tenant B cannot list its own connector episode")
	}
	// The forged and the disabled alert are both platform-owned with the same
	// signal and no resource, so the episode store folds them into ONE platform
	// episode (TenantID ""): find it by owner, not by summary.
	epsAdmin := episodes(admin)
	bEp, forgedEp := idBySummary(epsAdmin, nmsMarkB), ""
	for _, ep := range epsAdmin {
		if ep.TenantID == "" && ep.Signal == "NMSIntegrationDown" {
			forgedEp = ep.ID
		}
		if strings.Contains(ep.Summary, nmsMarkA) && ep.TenantID != a.tenantID {
			t.Errorf("A's connector episode is owned by %q, want %q", ep.TenantID, a.tenantID)
		}
		if strings.Contains(ep.Summary, nmsMarkB) && ep.TenantID != b.tenantID {
			t.Errorf("B's connector episode is owned by %q, want %q", ep.TenantID, b.tenantID)
		}
	}
	if bEp == "" || forgedEp == "" || idBySummary(epsAdmin, nmsMarkA) == "" {
		t.Fatalf("the platform owner must list every connector episode, incl. the platform-owned one: %+v", epsAdmin)
	}

	// ── B's episode, and a platform-only (forged) one, → 404 for A ───────────
	for _, id := range []string{bEp, forgedEp} {
		if st, body := do(t, srv, "POST", "/api/alerts/episodes/"+id+"/ack", a.token, map[string]any{}); st != http.StatusNotFound {
			t.Errorf("tenant A acking episode %s must 404 (existence hidden), got %d %s", id, st, body)
		}
	}
	{
		bts, _ := json.Marshal(map[string]any{})
		req, err := http.NewRequest("POST", srv.URL+"/api/alerts/episodes/"+bEp+"/ack", bytes.NewReader(bts))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.token)
		req.Header.Set("X-Acting-Tenant", b.tenantID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("X-Acting-Tenant into org B must not reach B's connector episode: %d", resp.StatusCode)
		}
	}
	for _, ep := range episodes(admin) {
		if ep.ID == bEp && ep.AcknowledgedBy != "" {
			t.Errorf("a refused cross-tenant ack mutated B's episode: %+v", ep)
		}
	}

	// ── WebSocket feed filter + scheduled reports use the same rule ──────────
	claimsA := jwtClaims{Sub: a.user, Role: "operator", Tenant: a.tenantID}
	claimsB := jwtClaims{Sub: b.user, Role: "operator", Tenant: b.tenantID}
	if !s.alertVisibleTo(set["nmsA"], claimsA) || s.alertVisibleTo(set["nmsA"], claimsB) {
		t.Error("WebSocket feed: tenant A's connector alert must reach A and only A")
	}
	if s.alertVisibleTo(set["forged"], claimsA) {
		t.Error("WebSocket feed: a forged tenant_id label reached the tenant it names")
	}
	rs := newReportScheduler(s, filepath.Join(t.TempDir(), "report_runs.json"))
	sawOwn := false
	for _, al := range rs.tenantAlerts(a.tenantID) {
		if strings.Contains(al.Summary, nmsMarkB) || strings.Contains(al.Summary, nmsMarkForged) {
			t.Errorf("scheduled report for A rendered %q", al.Summary)
		}
		if strings.Contains(al.Summary, nmsMarkA) {
			sawOwn = true
		}
	}
	if !sawOwn {
		t.Error("scheduled report for A lost its own connector alert")
	}

	// ── the operator-visibility restriction applies to the resolved owner ────
	v := s.alertVisibilityForScope(TenantGlobal, true, nil, []string{a.tenantID})
	if v.visible(set["nmsA"]) {
		t.Error("RESTRICTION LEAK: a restricted tenant's connector alert reached the operator's Global view")
	}
	if !v.visible(set["nmsB"]) {
		t.Error("the restriction on A hid an unrestricted tenant's connector alert")
	}
}

// TestNMSAlertOwnerFollowsTheSnapshot: disabling the integration (or turning
// NMS off) moves the alert back to platform-only on the next refresh, on BOTH
// the owner and the visibility path.
func TestNMSAlertOwnerFollowsTheSnapshot(t *testing.T) {
	_, s, _, a, _, set := nmsTwoOrgFixture(t)
	claimsA := jwtClaims{Sub: a.user, Role: "operator", Tenant: a.tenantID}
	if s.alertTenant(set["nmsA"]) != a.tenantID || !s.alertVisibleTo(set["nmsA"], claimsA) {
		t.Fatal("precondition: A owns and sees its connector alert")
	}

	ctx := context.Background()
	if err := s.nms.Store().Upsert(ctx, nms.Integration{Tenant: a.tenantID, ID: nmsSharedID, Vendor: "cisco_sdwan", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.nms.RefreshEnabled(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.alertTenant(set["nmsA"]); got != "" {
		t.Errorf("a disabled integration still owns its alert: %q", got)
	}
	if s.alertVisibleTo(set["nmsA"], claimsA) {
		t.Error("visibility and ownership disagree: the alert is platform-owned but still shown to A")
	}
	if got := s.alertTenant(set["nmsB"]); got == "" {
		t.Error("disabling A's integration removed B's integration of the same id")
	}

	s.nms = nil // FEATURE_NMS_INTEGRATIONS off
	if got := s.alertTenant(set["nmsB"]); got != "" {
		t.Errorf("with NMS off, a connector alert must be platform-only, got %q", got)
	}
}

// TestAlertOwnerUnit pins the branches of the one owner derivation.
func TestAlertOwnerUnit(t *testing.T) {
	_, s := newTestServerState(t)
	ctx := context.Background()
	mem := nms.NewMemStore()
	if err := mem.Upsert(ctx, nms.Integration{Tenant: "t_a", ID: "i-1", Vendor: "cisco_sdwan", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.discovery.Upsert(models.Device{ID: "unit-dev", Name: "unit-dev", TenantID: "T_A"})

	nmsLabels := map[string]string{"tenant_id": "t_a", "integration_id": "i-1"}
	cases := []struct {
		name string
		a    models.Alert
		want string
	}{
		{"device → discovery tenant (normalised)", models.Alert{Rule: "HighCPU", DeviceID: "unit-dev"}, "t_a"},
		{"unknown device → platform", models.Alert{Rule: "HighCPU", DeviceID: "nope"}, ""},
		{"device wins over NMS labels", models.Alert{Rule: "NMSIntegrationDown", DeviceID: "nope", Labels: nmsLabels}, ""},
		{"Experience → S17 tenant label", models.Alert{Rule: "ExperienceLatencyOverBudget", Labels: map[string]string{"tenant": " T_B "}}, "t_b"},
		{"Experience ignores tenant_id", models.Alert{Rule: "ExperienceLatencyOverBudget", Labels: nmsLabels}, ""},
		{"NMS enabled pair", models.Alert{Rule: "NMSIntegrationDown", Labels: nmsLabels}, "t_a"},
		{"NMS tenant label case-insensitive", models.Alert{Rule: "NMSIngestSilent", Labels: map[string]string{"tenant_id": " T_A", "integration_id": "i-1 "}}, "t_a"},
		{"NMS pair not enabled", models.Alert{Rule: "NMSIntegrationDown", Labels: map[string]string{"tenant_id": "t_b", "integration_id": "i-1"}}, ""},
		{"NMS missing integration_id", models.Alert{Rule: "NMSIntegrationDown", Labels: map[string]string{"tenant_id": "t_a"}}, ""},
		{"NMS missing tenant_id", models.Alert{Rule: "NMSIntegrationDown", Labels: map[string]string{"integration_id": "i-1"}}, ""},
		{"NMS 'tenant' label is not tenant_id", models.Alert{Rule: "NMSIntegrationDown", Labels: map[string]string{"tenant": "t_a", "integration_id": "i-1"}}, ""},
		{"NMS no labels", models.Alert{Rule: "NMSIntegrationDown"}, ""},
		{"non-NMS rule with NMS labels → platform", models.Alert{Rule: "CollectorFailing", Labels: nmsLabels}, ""},
		{"prefix is case-sensitive", models.Alert{Rule: "nmsIntegrationDown", Labels: nmsLabels}, ""},
	}

	// Before the runtime exists, and before its first refresh, no NMS alert has
	// an owner.
	if got := s.alertOwner(models.Alert{Rule: "NMSIntegrationDown", Labels: nmsLabels}); got != "" {
		t.Errorf("NMS off: owner = %q, want platform", got)
	}
	s.nms = newNMSRuntime(mem)
	if got := s.alertOwner(models.Alert{Rule: "NMSIntegrationDown", Labels: nmsLabels}); got != "" {
		t.Errorf("before the first refresh: owner = %q, want platform", got)
	}
	if _, err := s.nms.RefreshEnabled(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if got := s.alertOwner(c.a); got != c.want {
			t.Errorf("%s: alertOwner = %q, want %q", c.name, got, c.want)
		}
		if got := s.alertTenant(c.a); got != s.alertOwner(c.a) {
			t.Errorf("%s: alertTenant %q disagrees with alertOwner", c.name, got)
		}
	}

	// A visibility value built without a server keeps the old, label-only
	// answer: NMS alerts are platform-only there (default-closed).
	bare := alertVisibility{tenant: "t_a", ids: map[string]bool{}}
	if bare.visible(models.Alert{Rule: "NMSIntegrationDown", Labels: nmsLabels}) {
		t.Error("a server-less alertVisibility believed an NMS label")
	}
	if !s.alertVisibilityForScope("t_a", false, map[string]bool{}, nil).visible(models.Alert{Rule: "NMSIntegrationDown", Labels: nmsLabels}) {
		t.Error("the server-resolved visibility must follow alertOwner")
	}
}
