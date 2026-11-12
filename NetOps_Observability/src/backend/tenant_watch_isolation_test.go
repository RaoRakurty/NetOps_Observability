// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tenant_watch_isolation_test.go — §3a isolation test for tracker 359 (owner
// decision 2026-11-12): a tenant's OWN watch alerts (BGP-watch prefix classes,
// cloud monitors) reach that tenant's own RCA lanes and nobody else's.
//
// Built on the org_isolation_test.go template: two ORGS, each with one tenant
// and one tenant-scoped admin, configuring their lanes through the REAL
// handlers (httptest + auth middleware). Delivery runs through a real
// notify.Dispatcher pool; only the final sender is a fake, so no message ever
// leaves the process.
//
// Asserted:
//   - tenant A's watch alert reaches A's Slack/PagerDuty lane, never B's;
//   - the per-lane defaults: Slack ON, PagerDuty only when opted in;
//   - a global/empty-tenant alert reaches no tenant lane (not even the
//     platform's own "" config);
//   - BGP peer-down never reaches a tenant lane (the platform still gets it);
//   - nothing in the request or the alert can redirect delivery: the tenant is
//     the evaluator's, labels claiming another tenant are ignored, and a scoped
//     admin's ?tenant= / as_tenant cannot write or read another tenant's lanes;
//   - one message per episode (fire + clear), re-fires deduped;
//   - lane secrets never appear in a log line.

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/bgpwatch"
	"netops/backend/models"
	"netops/backend/notify"
)

// laneProbe is the fake final sender: it records (secret, alert, resolve).
type laneProbe struct {
	mu   sync.Mutex
	hits []laneProbeHit
	fail map[string]bool // secret → fail every send with an error naming it
}

type laneProbeHit struct {
	system, secret, alertID string
	resolve                 bool
}

type laneProbeSender struct {
	p *laneProbe
	l notify.TenantLane
}

func (s *laneProbeSender) Name() string { return "probe-" + s.l.System }

func (s *laneProbeSender) rec(a models.Alert, resolve bool) error {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if s.p.fail[s.l.Secret] {
		// The worst case: a sender whose own error text carries the secret.
		return fmt.Errorf("Post %q: connection refused", s.l.Secret)
	}
	s.p.hits = append(s.p.hits, laneProbeHit{system: s.l.System, secret: s.l.Secret, alertID: a.ID, resolve: resolve})
	return nil
}

func (s *laneProbeSender) Send(a models.Alert) error { return s.rec(a, false) }

type laneProbePD struct{ laneProbeSender }

func (s *laneProbePD) SendResolve(a models.Alert) error { return s.rec(a, true) }

func (p *laneProbe) build(l notify.TenantLane) notify.Channel {
	if l.System == notify.TenantLanePagerDuty {
		return &laneProbePD{laneProbeSender{p: p, l: l}}
	}
	return &laneProbeSender{p: p, l: l}
}

func (p *laneProbe) snapshot() []laneProbeHit {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]laneProbeHit(nil), p.hits...)
}

func (p *laneProbe) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hits = nil
}

// platformProbe stands in for the platform-global channel list.
type platformProbe struct {
	mu  sync.Mutex
	ids []string
}

func (p *platformProbe) Name() string { return "platform-probe" }
func (p *platformProbe) Send(a models.Alert) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ids = append(p.ids, a.ID)
	return nil
}
func (p *platformProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ids)
}

type capturedLogs struct {
	mu    sync.Mutex
	lines []string
}

func (c *capturedLogs) log(level, msg string, fields map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf("%s %s %v", level, msg, fields))
}

func (c *capturedLogs) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

// settle waits until the delivery pool has drained and in-flight sends have
// had time to land, so "B received nothing" is not a race.
func settle(t *testing.T, d *notify.Dispatcher, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if d.QueueDepth() == 0 && cond() {
			time.Sleep(100 * time.Millisecond)
			if d.QueueDepth() == 0 && cond() {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("delivery did not settle")
}

func TestTenantWatchDelivery_CrossOrgIsolation(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true") // no DNS in the save-time URL pre-check
	srv, s := newTestServerState(t)
	s.itsmCfg = newITSMConfigStore(s, t.TempDir()+"/itsm.json")
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// ── org A and org B, each: org → tenant → tenant-scoped admin ────────────
	type fx struct{ tenantID, token string }
	fix := map[string]*fx{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Watch Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Watch Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "watch-admin-" + strings.ToLower(name)
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &fx{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	const (
		hookA = "https://hooks.example.test/services/TA/BA/secretA"
		keyA  = "rk-secret-tenant-a"
		hookB = "https://hooks.example.test/services/TB/BB/secretB"
		keyB  = "rk-secret-tenant-b"
		hookP = "https://hooks.example.test/services/TP/BP/secretPlatform"
		keyP  = "rk-secret-platform"
	)
	put := func(token, path string, body map[string]any) {
		t.Helper()
		if st, out := do(t, srv, "PUT", path, token, body); st != 200 {
			t.Fatalf("PUT %s: %d %s", path, st, out)
		}
	}
	// A opts PagerDuty IN; Slack is left at its default (ON).
	put(a.token, "/api/itsm/slack-rca", map[string]any{"enabled": true, "webhook_url": hookA})
	put(a.token, "/api/itsm/pagerduty-rca", map[string]any{"enabled": true, "routing_key": keyA, "watch_alerts": true})
	// B never touches the choice: Slack default ON, PagerDuty default OFF.
	put(b.token, "/api/itsm/slack-rca", map[string]any{"enabled": true, "webhook_url": hookB})
	put(b.token, "/api/itsm/pagerduty-rca", map[string]any{"enabled": true, "routing_key": keyB})
	// A scoped admin cannot point B's lane anywhere: ?tenant= is ignored for a
	// scoped principal, so this lands on A's OWN key (and is then reverted).
	put(a.token, "/api/itsm/pagerduty-rca?tenant="+b.tenantID, map[string]any{"enabled": true, "watch_alerts": false})
	put(a.token, "/api/itsm/pagerduty-rca", map[string]any{"enabled": true, "watch_alerts": true})
	// The platform's OWN "" config has lanes too — a tenant-less alert must
	// still never reach them.
	s.itsmCfg.SetConfigForTest("", itsmConfig{
		Slack:     slackRCAConfig{Enabled: true, WebhookURL: hookP},
		PagerDuty: pagerDutyRCAConfig{Enabled: true, RoutingKey: keyP, WatchAlerts: func() *bool { v := true; return &v }()},
	})

	// Each tenant's read of its own choice; ?tenant= / as_tenant into the other
	// org is ignored for a scoped admin.
	readWatch := func(token, query string) (pd, slack bool) {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/notify/itsm"+query, token, nil)
		if st != 200 {
			t.Fatalf("GET itsm%s: %d %s", query, st, body)
		}
		var out struct {
			PagerDuty struct {
				WatchAlerts bool `json:"watch_alerts"`
			} `json:"pagerduty"`
			Slack struct {
				WatchAlerts bool `json:"watch_alerts"`
			} `json:"slack"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{hookA, keyA, hookB, keyB, "secretA", "secretB"} {
			if strings.Contains(string(body), secret) {
				t.Fatalf("GET itsm leaked a lane secret: %s", body)
			}
		}
		return out.PagerDuty.WatchAlerts, out.Slack.WatchAlerts
	}
	if pd, sl := readWatch(a.token, ""); !pd || !sl {
		t.Fatalf("A's choice: pd=%v slack=%v, want pd on (opted in) + slack on (default)", pd, sl)
	}
	if pd, sl := readWatch(b.token, ""); pd || !sl {
		t.Fatalf("B's choice: pd=%v slack=%v, want pd OFF (default) + slack on (default)", pd, sl)
	}
	if pd, _ := readWatch(b.token, "?tenant="+a.tenantID+"&as_tenant="+a.tenantID); pd {
		t.Fatal("B read A's lane choice via ?tenant= / as_tenant")
	}

	// ── delivery plumbing: a real dispatcher pool, fake final senders ─────────
	d := notify.NewDispatcher()
	t.Cleanup(d.Close)
	logs := &capturedLogs{}
	d.SetLogger(logs.log)
	plat := &platformProbe{}
	d.Register(plat)
	probe := &laneProbe{fail: map[string]bool{}}
	s.notifier = d
	s.tenantWatch = notify.NewTenantWatchRouter(d, notify.TenantWatchDeps{
		Lanes: s.tenantWatchLanes, // the production resolver
		Build: probe.build,
		Log:   logs.log,
	})

	now := time.Unix(1_700_000_000, 0).UTC()
	prefixAlert := func(tenant, prefix string, class bgpwatch.IncidentClass) bgpwatch.Alert {
		return bgpwatch.Alert{
			ID: "bgp:" + tenant + ":" + prefix + ":" + string(class), Rule: "bgp_" + string(class),
			Severity: bgpwatch.SevCritical, Tenant: tenant, Resource: prefix, Class: class,
			Summary: "class " + string(class), FiredAt: now,
			// Labels claiming the OTHER tenant must never steer delivery.
			Labels: map[string]string{"prefix": prefix, "class": string(class), "source": "bgp-watch",
				"tenant": b.tenantID, "tenant_id": b.tenantID},
		}
	}
	secretsOf := func(hits []laneProbeHit) map[string]int {
		out := map[string]int{}
		for _, h := range hits {
			out[h.secret]++
		}
		return out
	}

	// 1. A's hijack (origin change) reaches A's Slack AND A's PagerDuty
	//    (opted in) — never B's, never the platform's lanes — and the
	//    platform channel still receives it.
	hijack := prefixAlert(a.tenantID, "203.0.113.0/24", bgpwatch.ClassOriginChange)
	for i := 0; i < 3; i++ { // the evaluator's cool-down re-notify: one message only
		s.bgpWatchNotify(hijack)
	}
	settle(t, d, func() bool { return len(probe.snapshot()) == 2 && plat.count() == 3 })
	if got := secretsOf(probe.snapshot()); got[hookA] != 1 || got[keyA] != 1 || len(got) != 2 {
		t.Fatalf("A's hijack must reach exactly A's two lanes once each, got %v", got)
	}

	// 2. B's route leak reaches B's Slack only (PagerDuty not opted in).
	probe.reset()
	s.bgpWatchNotify(prefixAlert(b.tenantID, "198.51.100.0/24", bgpwatch.ClassRouteLeak))
	settle(t, d, func() bool { return len(probe.snapshot()) == 1 })
	if got := secretsOf(probe.snapshot()); got[hookB] != 1 || len(got) != 1 {
		t.Fatalf("B's leak must reach only B's Slack (PagerDuty is opt-in), got %v", got)
	}

	// 3. Peer-down (and its recovery, and the "no longer measured" notices)
	//    never reach a tenant lane; the platform channel still gets them.
	probe.reset()
	before := plat.count()
	peer := bgpwatch.Alert{ID: "bgp:" + a.tenantID + ":peer:r1|192.0.2.1", Rule: "bgp_peer_down",
		Severity: bgpwatch.SevHigh, Tenant: a.tenantID, Resource: "r1", Class: bgpwatch.ClassNone, FiredAt: now}
	s.bgpWatchNotify(peer)
	s.bgpWatchResolve(bgpwatch.Alert{ID: peer.ID, Rule: "bgp_peer_down", Tenant: a.tenantID, Resolved: true})
	s.bgpWatchNotify(bgpwatch.Alert{ID: "bgp:" + a.tenantID + ":203.0.113.0/24:unknown", Rule: "bgp_measurement_lost",
		Tenant: a.tenantID, Class: bgpwatch.ClassUnknown})
	// A peer-down that tries to pass as a prefix class by carrying one.
	s.bgpWatchNotify(bgpwatch.Alert{ID: "forged", Rule: "bgp_peer_down", Tenant: a.tenantID, Class: bgpwatch.ClassOriginChange})
	settle(t, d, func() bool { return plat.count() == before+3 })
	if hits := probe.snapshot(); len(hits) != 0 {
		t.Fatalf("peer-down / measurement-lost reached a tenant lane: %+v", hits)
	}

	// 4. A tenant-less or platform alert reaches no tenant lane — including the
	//    platform's own "" lanes.
	for _, tenant := range []string{"", "global", TenantGlobal, " GLOBAL "} {
		s.bgpWatchNotify(prefixAlert(tenant, "192.0.2.0/24", bgpwatch.ClassBogon))
		s.tenantWatchFire(tenant, models.Alert{ID: "cloud-monitor-p1", Rule: "cpu", Summary: "x"})
	}
	settle(t, d, func() bool { return true })
	if hits := probe.snapshot(); len(hits) != 0 {
		t.Fatalf("a global/empty-tenant alert reached a lane: %+v", hits)
	}

	// 5. A's cloud monitor (the wiring's TenantFire seam) — labels claiming B
	//    are ignored; it goes to A.
	monitor := models.Alert{ID: "cloud-monitor-m1", Rule: "High CPU", Severity: "warning",
		Summary: `Cloud monitor "High CPU": cpu 95`, Labels: map[string]string{"tenant_id": b.tenantID}}
	s.tenantWatchFire(a.tenantID, monitor)
	settle(t, d, func() bool { return len(probe.snapshot()) == 2 })
	if got := secretsOf(probe.snapshot()); got[hookA] != 1 || got[keyA] != 1 || len(got) != 2 {
		t.Fatalf("A's monitor must reach only A's lanes, got %v", got)
	}

	// 6. Clearing A's hijack: one clear per lane its start reached; a second
	//    clear of the same episode is not re-sent.
	probe.reset()
	cleared := hijack
	cleared.Resolved, cleared.Summary = true, "Cleared: 203.0.113.0/24 is no longer classified origin_change."
	s.bgpWatchResolve(cleared)
	s.bgpWatchResolve(cleared)
	settle(t, d, func() bool { return len(probe.snapshot()) == 2 })
	var pdResolve, slackClear int
	for _, h := range probe.snapshot() {
		switch {
		case h.secret == keyA && h.resolve:
			pdResolve++
		case h.secret == hookA && !h.resolve:
			slackClear++
		default:
			t.Fatalf("unexpected clear delivery %+v", h)
		}
	}
	if pdResolve != 1 || slackClear != 1 {
		t.Fatalf("want one PagerDuty resolve + one Slack clear, got pd=%d slack=%d", pdResolve, slackClear)
	}

	// 7. A failing lane is counted + logged, and no lane secret reaches any
	//    log line (the sender's own error names its secret here).
	probe.fail[hookB] = true
	s.bgpWatchNotify(prefixAlert(b.tenantID, "198.51.100.128/25", bgpwatch.ClassRPKIInvalid))
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(logs.text(), "did not go out") {
		if time.Now().After(deadline) {
			t.Fatalf("a failed tenant send was not logged:\n%s", logs.text())
		}
		time.Sleep(20 * time.Millisecond)
	}
	all := logs.text()
	for _, secret := range []string{hookA, keyA, hookB, keyB, hookP, keyP, "secretA", "secretB", "secretPlatform"} {
		if strings.Contains(all, secret) {
			t.Fatalf("lane secret %q leaked into a log line:\n%s", secret, all)
		}
	}
	if !strings.Contains(all, "tenant-slack") || !strings.Contains(all, b.tenantID) {
		t.Fatalf("the failure log must name the fixed lane and the tenant:\n%s", all)
	}
	waitFor := time.Now().Add(5 * time.Second)
	for !strings.Contains(metricsText(s), `netops_notify_failures_total{channel="tenant-slack"} 1`) && time.Now().Before(waitFor) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(metricsText(s), `netops_notify_failures_total{channel="tenant-slack"} 1`) {
		t.Fatalf("the failure must be counted on the tenant-slack delivery counter:\n%s", metricsText(s))
	}
}

// TestTenantWatchLanesFrom pins the pure lane decision: enabled + secret +
// opted in, with Slack defaulting ON and PagerDuty defaulting OFF.
func TestTenantWatchLanesFrom(t *testing.T) {
	on, off := true, false
	cases := []struct {
		name string
		cfg  itsmConfig
		want []string
	}{
		{"nothing configured", itsmConfig{}, nil},
		{"slack default on", itsmConfig{Slack: slackRCAConfig{Enabled: true, WebhookURL: "https://h/x"}}, []string{"slack"}},
		{"slack opted out", itsmConfig{Slack: slackRCAConfig{Enabled: true, WebhookURL: "https://h/x", WatchAlerts: &off}}, nil},
		{"pagerduty default off", itsmConfig{PagerDuty: pagerDutyRCAConfig{Enabled: true, RoutingKey: "rk"}}, nil},
		{"pagerduty opted in", itsmConfig{PagerDuty: pagerDutyRCAConfig{Enabled: true, RoutingKey: "rk", WatchAlerts: &on}}, []string{"pagerduty"}},
		{"opted in but lane disabled", itsmConfig{
			Slack:     slackRCAConfig{WebhookURL: "https://h/x", WatchAlerts: &on},
			PagerDuty: pagerDutyRCAConfig{RoutingKey: "rk", WatchAlerts: &on}}, nil},
		{"opted in but no secret", itsmConfig{
			Slack:     slackRCAConfig{Enabled: true, WatchAlerts: &on},
			PagerDuty: pagerDutyRCAConfig{Enabled: true, WatchAlerts: &on}}, nil},
	}
	for _, c := range cases {
		var got []string
		for _, l := range tenantWatchLanesFrom(c.cfg) {
			got = append(got, l.System)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: lanes %v, want %v", c.name, got, c.want)
		}
	}
}

// TestBGPWatchTenantOwned pins which BGP-watch alerts are tenant-owned.
func TestBGPWatchTenantOwned(t *testing.T) {
	for _, class := range []bgpwatch.IncidentClass{bgpwatch.ClassOriginChange, bgpwatch.ClassRPKIInvalid,
		bgpwatch.ClassBogon, bgpwatch.ClassRouteLeak, bgpwatch.ClassVisibilityLoss} {
		if !bgpWatchTenantOwned(bgpwatch.Alert{Rule: "bgp_" + string(class), Class: class}) {
			t.Errorf("prefix class %s must reach the tenant lane", class)
		}
	}
	for name, a := range map[string]bgpwatch.Alert{
		"peer down":                 {Rule: "bgp_peer_down", Class: bgpwatch.ClassNone},
		"peer back up":              {Rule: "bgp_peer_down"},
		"peer measurement lost":     {Rule: "bgp_peer_measurement_lost", Class: bgpwatch.ClassUnknown},
		"prefix measurement lost":   {Rule: "bgp_measurement_lost", Class: bgpwatch.ClassUnknown},
		"peer down forging a class": {Rule: "bgp_peer_down", Class: bgpwatch.ClassOriginChange},
	} {
		if bgpWatchTenantOwned(a) {
			t.Errorf("%s must never reach a tenant lane", name)
		}
	}
}

func metricsText(s *server) string {
	var sb strings.Builder
	s.notifier.WriteMetrics(&sb)
	s.tenantWatch.WriteMetrics(&sb)
	return sb.String()
}
