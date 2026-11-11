// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// platform_alert_route_test.go — the Platform alerts page's routes through the
// REAL router + auth middleware (owner decision 2026-11-11: platform self-health
// alerts are configured in the GUI, not via env).
//
// §3a rule 3: the record is platform-GLOBAL plumbing, so the gate is
// requirePlatformAdmin. A tenant admin and an org admin each hold full
// administration:admin inside their scope and MUST be refused — a scope-blind
// requireAdmin here would hand every customer's administrator the operator's
// pager.

import (
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/platformalert"
	"netops/backend/internal/platformdb"
	"netops/backend/notify"
)

type platformAlertFixture struct {
	*featureFixture
	key string
}

func newPlatformAlertFixture(t *testing.T) *platformAlertFixture {
	t.Helper()
	f := newFeatureFixture(t)
	key := t.TempDir() + "/platform_alert_route.json"
	f.s.platformAlerts = platformalert.NewStore(platformalert.StoreDeps{Key: key, Load: platformdb.Load, Save: platformdb.Save})
	f.s.platformAlertRouter = platformalert.NewRouter(platformalert.RouterDeps{Store: f.s.platformAlerts, Budgets: notify.NewPushBudgets(30, 10, nil)})
	return &platformAlertFixture{featureFixture: f, key: key}
}

func platformAlertBody() map[string]any {
	return map[string]any{
		"ntfy": map[string]any{"enabled": true, "server": "https://ntfy.sh", "topic": "corr-ops-route",
			"token": "placeholder-" + strings.Repeat("q", 16), "tiers": map[string]any{"page": true, "warning": true}},
		"sms": map[string]any{"enabled": false, "max_per_hour": 10, "tiers": map[string]any{"page": true}},
	}
}

func TestPlatformAlertRouteIsPlatformAdminOnly(t *testing.T) {
	f := newPlatformAlertFixture(t)
	if st, b := f.call("POST", "/api/orgs", f.admin, map[string]any{"name": "Acme Corp"}); st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	if st, _ := f.call("POST", "/api/tenants", f.admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"}); st != 201 {
		t.Fatal("create tenant")
	}
	for _, u := range []map[string]any{
		{"username": "orgboss", "password": "Passw0rd!2345", "role": "org-admin", "tenant_id": "acme-prod"},
		{"username": "tadmin", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": "acme-prod"},
	} {
		if st, _ := f.call("POST", "/api/users", f.admin, u); st != 201 {
			t.Fatal("create user")
		}
	}
	const route = "/api/platform/alerting/host-route"
	// Unauthenticated: 401 on every verb.
	for _, m := range []string{"GET", "PUT"} {
		if st, _ := f.call(m, route, "", platformAlertBody()); st != 401 {
			t.Errorf("unauthenticated %s = %d, want 401", m, st)
		}
	}
	if st, _ := f.call("POST", route+"/test", "", map[string]any{"channel": "ntfy"}); st != 401 {
		t.Errorf("unauthenticated test = %d, want 401", st)
	}
	// Tenant and org administrators: 403, including through as_tenant.
	for _, who := range []string{"orgboss", "tadmin"} {
		tok := login(t, f.ts, who, "Passw0rd!2345").Token
		if st, _ := f.call("GET", route, tok, nil); st != 403 {
			t.Errorf("%s GET = %d, want 403", who, st)
		}
		if st, _ := f.call("GET", route+"?as_tenant=acme-prod", tok, nil); st != 403 {
			t.Errorf("%s as_tenant GET = %d, want 403", who, st)
		}
		if st, _ := f.call("PUT", route, tok, platformAlertBody()); st != 403 {
			t.Errorf("%s PUT = %d, want 403", who, st)
		}
		if st, _ := f.call("POST", route+"/test", tok, map[string]any{"channel": "ntfy"}); st != 403 {
			t.Errorf("%s test = %d, want 403", who, st)
		}
	}
	if f.s.platformAlerts.Current().PageRouted() {
		t.Fatal("a refused caller changed the platform alert route")
	}
	// The platform administrator: allowed, and the secret never comes back.
	st, b := f.call("PUT", route, f.admin, platformAlertBody())
	if st != 200 {
		t.Fatalf("platform admin PUT = %d %s", st, b)
	}
	st, b = f.call("GET", route, f.admin, nil)
	if st != 200 || strings.Contains(string(b), strings.Repeat("q", 16)) {
		t.Fatalf("platform admin GET = %d %s", st, b)
	}
	var v platformalert.View
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if !v.PageRouted || !v.Ntfy.TokenSet {
		t.Fatalf("view: %+v", v)
	}
	// Audited, as a cross-tenant (platform) action.
	evs, err := f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range evs {
		if e.Detail["action"] == "platform_alert_route_set" && e.Status == 200 {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("audit rows = %d, want 1", found)
	}
}

// A product (tenant-facing) ntfy channel may not publish onto the topic the
// platform route now takes from the GUI — the successor of the
// WATCHDOG_NTFY_TOPIC refusal, which also still stands.
func TestProductNtfyRefusesThePlatformAlertTopic(t *testing.T) {
	t.Setenv("WATCHDOG_NTFY_TOPIC", "")
	f := newPlatformAlertFixture(t)
	f.s.notifyCfg = newNotifyConfigStore(t.TempDir()+"/notify.json", f.s)
	if st, b := f.call("PUT", "/api/platform/alerting/host-route", f.admin, platformAlertBody()); st != 200 {
		t.Fatalf("PUT route = %d %s", st, b)
	}
	st, b := f.call("PUT", "/api/notify/ntfy", f.admin, map[string]any{"enabled": true, "topic": "corr-ops-route", "min_severity": "critical"})
	if st != 400 || !strings.Contains(string(b), "platform alert topic") {
		t.Fatalf("product ntfy on the platform topic = %d %s, want 400", st, b)
	}
	if st, b := f.call("PUT", "/api/notify/ntfy", f.admin, map[string]any{"enabled": true, "topic": "corr-product", "min_severity": "critical"}); st != 200 {
		t.Fatalf("a distinct product topic must be accepted: %d %s", st, b)
	}
}

// The retired env names are reported, never read.
func TestRetiredPlatformAlertEnvIsReportedNotRead(t *testing.T) {
	t.Setenv("PLATFORM_ALERTS_NTFY_TOPIC", "env-topic")
	t.Setenv("WATCHDOG_NTFY_TOPIC", "wd-topic")
	ts, s := newTestServerState(t)
	_ = ts
	s.pushBudgets = notify.NewPushBudgets(30, 10, nil)
	store, router, ignored := s.buildPlatformAlertRoute()
	if store.Current().PageRouted() || len(router.Targets("page")) != 0 {
		t.Fatal("env must not configure the platform alert route")
	}
	joined := strings.Join(ignored, ",")
	if !strings.Contains(joined, "PLATFORM_ALERTS_NTFY_TOPIC") || !strings.Contains(joined, "WATCHDOG_NTFY_TOPIC") {
		t.Fatalf("ignored env must be reported for the page: %v", ignored)
	}
}
