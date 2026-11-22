// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// teams_rca_isolation_test.go — §3a for the tenant Microsoft Teams problem
// destination (PUT /api/itsm/teams-rca, read through GET /api/notify/itsm):
//
//   - each org's tenant admin sets and reads ONLY its own Teams lane;
//     ?tenant= / as_tenant into the other org is ignored for a scoped admin;
//   - the webhook URL is write-only: no read returns it, a blank save keeps it;
//   - an operator (no administration:admin) cannot write it, an anonymous
//     caller cannot reach it;
//   - the RCA worker, the watch router and the cloud notices resolve a
//     tenant's Teams lane from that tenant's config only — never another
//     tenant's, never the platform's own "" config.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

func TestTeamsRCADestination_CrossOrgIsolation(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true") // no DNS in the save-time URL pre-check
	srv, s := newTestServerState(t)
	s.itsmCfg = newITSMConfigStore(nil, t.TempDir()+"/itsm.json")
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	type fx struct{ tenantID, token, opToken string }
	fix := map[string]*fx{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Teams Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Teams Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		f := &fx{tenantID: tenantID}
		for _, role := range []string{"admin", "operator"} {
			user := "teams-" + role + "-" + strings.ToLower(name)
			st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
				"username": user, "password": "Passw0rd!2345", "role": role, "tenant_id": tenantID,
			})
			if st != 201 {
				t.Fatalf("create %s %s: %d %s", role, name, st, b)
			}
			tok := login(t, srv, user, "Passw0rd!2345").Token
			if role == "admin" {
				f.token = tok
			} else {
				f.opToken = tok
			}
		}
		fix[name] = f
	}
	a, b := fix["A"], fix["B"]

	const (
		hookA = "https://contoso-a.webhook.office.com/webhookb2/TA/IncomingWebhook/secretA"
		hookB = "https://prod-9.westus.logic.azure.com:443/workflows/TB/triggers/manual/paths/invoke?sig=secretB"
		hookP = "https://platform.webhook.office.com/webhookb2/TP/IncomingWebhook/secretPlatform"
	)
	put := func(token, query string, body map[string]any) (int, string) {
		t.Helper()
		st, out := do(t, srv, "PUT", "/api/itsm/teams-rca"+query, token, body)
		return st, string(out)
	}
	mustPut := func(token, query string, body map[string]any) {
		t.Helper()
		if st, out := put(token, query, body); st != 200 {
			t.Fatalf("PUT teams-rca%s: %d %s", query, st, out)
		}
	}

	// Gate: anonymous → 401, an operator → 403, http (not https) → 400.
	if st, _ := put("", "", map[string]any{"enabled": true, "webhook_url": hookA}); st != http.StatusUnauthorized {
		t.Fatalf("anonymous PUT = %d, want 401", st)
	}
	if st, _ := put(a.opToken, "", map[string]any{"enabled": true, "webhook_url": hookA}); st != http.StatusForbidden {
		t.Fatalf("operator PUT = %d, want 403", st)
	}
	if st, out := put(a.token, "", map[string]any{"enabled": true, "webhook_url": "http://contoso-a.webhook.office.com/x"}); st != http.StatusBadRequest || strings.Contains(out, "contoso-a") {
		t.Fatalf("http webhook PUT = %d %s, want 400 without echoing the URL", st, out)
	}

	// Each org sets its own lane; A opts its watch alerts out, B keeps the default.
	mustPut(a.token, "", map[string]any{"enabled": true, "webhook_url": hookA, "watch_alerts": false})
	mustPut(b.token, "", map[string]any{"enabled": true, "webhook_url": hookB})
	// A scoped admin cannot point B's lane anywhere: ?tenant= / as_tenant are
	// ignored, so this lands on A's OWN key (and is then put back).
	mustPut(a.token, "?tenant="+b.tenantID+"&as_tenant="+b.tenantID, map[string]any{"enabled": true, "webhook_url": hookA + "-hijack"})
	mustPut(a.token, "", map[string]any{"enabled": true, "webhook_url": hookA})
	// A blank URL keeps the stored one (write-only).
	mustPut(a.token, "", map[string]any{"enabled": true})
	// The platform's own "" config has a Teams lane too.
	s.itsmCfg.SetConfigForTest("", itsmConfig{Teams: teamsRCAConfig{Enabled: true, WebhookURL: hookP}})

	for name, want := range map[string]string{a.tenantID: hookA, b.tenantID: hookB} {
		sc, ok := s.itsmCfg.SystemConfigFor(name, "teams")
		if !ok || sc.APIToken != want {
			t.Fatalf("tenant %s resolves Teams %q ok=%v, want its own %q", name, sc.APIToken, ok, want)
		}
	}

	read := func(token, query string) map[string]any {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/notify/itsm"+query, token, nil)
		if st != 200 {
			t.Fatalf("GET itsm%s: %d %s", query, st, body)
		}
		for _, secret := range []string{hookA, hookB, hookP, "secretA", "secretB", "secretPlatform", "webhook.office.com", "logic.azure.com"} {
			if strings.Contains(string(body), secret) {
				t.Fatalf("GET itsm leaked a Teams webhook (%q): %s", secret, body)
			}
		}
		var out struct {
			Tenant string         `json:"tenant"`
			Teams  map[string]any `json:"teams"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		out.Teams["tenant"] = out.Tenant
		return out.Teams
	}
	ta := read(a.token, "")
	if ta["has_webhook"] != true || ta["configured"] != true || ta["watch_alerts"] != false {
		t.Fatalf("A's Teams view = %v", ta)
	}
	if tb := read(b.token, ""); tb["watch_alerts"] != true || tb["configured"] != true {
		t.Fatalf("B's Teams view = %v", tb)
	}
	if cross := read(b.token, "?tenant="+a.tenantID+"&as_tenant="+a.tenantID); cross["watch_alerts"] != true || cross["tenant"] == strings.ToLower(a.tenantID) {
		t.Fatalf("B read A's Teams lane via ?tenant= / as_tenant: %v", cross)
	}

	// Lane resolution for the watch router and the cloud notices.
	cfgA, _ := s.itsmCfg.ConfigFor(a.tenantID)
	cfgB, _ := s.itsmCfg.ConfigFor(b.tenantID)
	if lanes := tenantWatchLanesFrom(cfgA); len(lanes) != 0 {
		t.Fatalf("A opted its watches out of Teams, lanes = %+v", lanes)
	}
	if lanes := tenantWatchLanesFrom(cfgB); len(lanes) != 1 || lanes[0].System != notify.TenantLaneTeams || lanes[0].Secret != hookB {
		t.Fatalf("B's watch lanes = %+v", lanes)
	}
	if tg := rcaNotifyTargets(s.itsmCfg, a.tenantID); len(tg) != 1 || tg[0].System != "teams" || tg[0].Secret != hookA {
		t.Fatalf("A's cloud notice targets = %+v", tg)
	}
	for _, tenant := range []string{"", "global", TenantGlobal} {
		if lanes := s.tenantWatchLanes(tenant); len(lanes) != 0 {
			t.Fatalf("platform tenant %q resolved watch lanes %+v", tenant, lanes)
		}
	}

	// Delivery through the production resolver: B's monitor reaches B's Teams
	// only — labels claiming A never steer it — and no secret reaches a log.
	d := notify.NewDispatcher()
	t.Cleanup(d.Close)
	logs := &capturedLogs{}
	d.SetLogger(logs.log)
	probe := &laneProbe{fail: map[string]bool{}}
	s.notifier = d
	s.tenantWatch = notify.NewTenantWatchRouter(d, notify.TenantWatchDeps{
		Lanes: s.tenantWatchLanes,
		Build: probe.build,
		Log:   logs.log,
	})
	s.tenantWatchFire(b.tenantID, models.Alert{ID: "cloud-monitor-b1", Rule: "High CPU", Severity: "warning",
		Summary: "cpu 95", Labels: map[string]string{"tenant_id": a.tenantID}})
	s.tenantWatchFire(a.tenantID, models.Alert{ID: "cloud-monitor-a1", Rule: "High CPU", Summary: "cpu 96"})
	s.tenantWatchFire("", models.Alert{ID: "cloud-monitor-p1", Rule: "High CPU", Summary: "cpu 97"})
	settle(t, d, func() bool { return len(probe.snapshot()) == 1 })
	time.Sleep(50 * time.Millisecond) // a stray second delivery would land now
	hits := probe.snapshot()
	if len(hits) != 1 || hits[0].secret != hookB || hits[0].system != notify.TenantLaneTeams {
		t.Fatalf("B's monitor must reach only B's Teams lane: %+v", hits)
	}

	probe.fail[hookB] = true
	s.tenantWatchFire(b.tenantID, models.Alert{ID: "cloud-monitor-b2", Rule: "High CPU", Summary: "cpu 99"})
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(logs.text(), "did not go out") {
		if time.Now().After(deadline) {
			t.Fatalf("a failed Teams send was not logged:\n%s", logs.text())
		}
		time.Sleep(20 * time.Millisecond)
	}
	all := logs.text()
	for _, secret := range []string{hookA, hookB, hookP, "secretA", "secretB", "secretPlatform"} {
		if strings.Contains(all, secret) {
			t.Fatalf("Teams webhook %q leaked into a log line:\n%s", secret, all)
		}
	}
	if !strings.Contains(all, "tenant-teams") {
		t.Fatalf("the failure log must name the fixed tenant-teams lane:\n%s", all)
	}
}

// TestTenantWatchLanesFromTeams pins the Teams half of the pure lane decision:
// enabled + secret + opted in, defaulting ON like Slack.
func TestTenantWatchLanesFromTeams(t *testing.T) {
	off := false
	for name, c := range map[string]struct {
		cfg  itsmConfig
		want int
	}{
		"teams default on":   {itsmConfig{Teams: teamsRCAConfig{Enabled: true, WebhookURL: "https://h/x"}}, 1},
		"teams opted out":    {itsmConfig{Teams: teamsRCAConfig{Enabled: true, WebhookURL: "https://h/x", WatchAlerts: &off}}, 0},
		"teams disabled":     {itsmConfig{Teams: teamsRCAConfig{WebhookURL: "https://h/x"}}, 0},
		"teams no webhook":   {itsmConfig{Teams: teamsRCAConfig{Enabled: true}}, 0},
		"slack + teams both": {itsmConfig{Slack: slackRCAConfig{Enabled: true, WebhookURL: "https://s/x"}, Teams: teamsRCAConfig{Enabled: true, WebhookURL: "https://h/x"}}, 2},
	} {
		if got := len(tenantWatchLanesFrom(c.cfg)); got != c.want {
			t.Errorf("%s: %d lanes, want %d", name, got, c.want)
		}
		// Cloud notices ignore the watch choice: an enabled lane with a secret routes.
		wantCloud := 0
		if c.cfg.Teams.Enabled && c.cfg.Teams.WebhookURL != "" {
			wantCloud = 1
		}
		if c.cfg.Slack.Enabled && c.cfg.Slack.WebhookURL != "" {
			wantCloud++
		}
		if got := len(cloudNotifyLanes(c.cfg)); got != wantCloud {
			t.Errorf("%s: %d cloud lanes, want %d", name, got, wantCloud)
		}
	}
}
