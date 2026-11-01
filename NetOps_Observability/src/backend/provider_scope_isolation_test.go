// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// provider_scope_isolation_test.go — tracker 365, exercised through the REAL
// router + auth middleware (org_isolation_test.go template).
//
// The incident (2026-10-25): picking "Provider" in the scope switcher sent
// X-Acting-Tenant: global, which withActingTenant treated as "no narrowing",
// so the platform owner saw every tenant's NMS integrations unlabelled and
// deleted another tenant's real vManage integration from what looked like
// their own list.
//
// The rule now: "global" (Provider) is a real, NON-cross narrowing to the
// platform's own rows — both spellings, "" and "global" (internal/owner) —
// while "" / "all" stays the cross-tenant "All tenants" view, every row
// carrying its tenant. A non-owner sending "global" gets it only if bound to
// a scope that reaches the Global tenant; otherwise it is ignored.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/collectors"
	"netops/backend/internal/saved"
	"netops/backend/models"
	"netops/backend/nms"
)

// doActing is do() plus an X-Acting-Tenant header ("" sends none).
func doActing(t *testing.T, srv *httptest.Server, method, path, token, acting string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if acting != "" {
		req.Header.Set("X-Acting-Tenant", acting)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func TestProviderScopeIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)
	store := newAlertEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"))
	store.SetNowForTest(func() time.Time { return time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC) })
	s.alertEpisodes = store
	s.nms = newNMSRuntime(nms.NewMemStore())

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// ── org A → tenant A → operator; plus an org-admin of org A (NOT bound to
	// the Global tenant or its org) ─────────────────────────────────────────
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Retail Org"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	orgA := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Retail", "org_id": orgA})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantA := idOf(t, b)
	createUserID(t, srv, admin, map[string]any{
		"username": "retail-op", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantA,
	})
	bossID := createUserID(t, srv, admin, map[string]any{
		"username": "retail-boss", "password": "Passw0rd!2345", "role": "org-admin", "tenant_id": tenantA,
	})
	if st, b := do(t, srv, "POST", "/api/bindings", admin, map[string]any{
		"principal_id": bossID, "role_id": "org-admin", "scope_id": "org:" + orgA,
	}); st != 201 {
		t.Fatalf("grant org-admin binding: %d %s", st, b)
	}
	userA := login(t, srv, "retail-op", "Passw0rd!2345").Token
	boss := login(t, srv, "retail-boss", "Passw0rd!2345").Token

	// ── devices: platform in BOTH spellings, and tenant A's own ─────────────
	for _, d := range []map[string]any{
		{"id": "plat-blank", "name": "plat-blank", "address": "10.9.0.1", "tenant_id": ""},
		{"id": "plat-global", "name": "plat-global", "address": "10.9.0.2", "tenant_id": TenantGlobal},
		{"id": "retail-edge", "name": "retail-edge", "address": "10.1.0.1", "tenant_id": tenantA},
	} {
		if st, b := do(t, srv, "POST", "/api/devices", admin, d); st != 201 {
			t.Fatalf("create device %v: %d %s", d["id"], st, b)
		}
	}

	listDevices := func(token, acting, query string) map[string]models.Device {
		t.Helper()
		st, body := doActing(t, srv, "GET", "/api/devices"+query, token, acting, nil)
		if st != 200 {
			t.Fatalf("GET /api/devices%s (acting %q): %d %s", query, acting, st, body)
		}
		var devs []models.Device
		if err := json.Unmarshal(body, &devs); err != nil {
			t.Fatalf("decode devices: %v (%s)", err, body)
		}
		out := map[string]models.Device{}
		for _, d := range devs {
			out[d.ID] = d
		}
		return out
	}
	keys := func(m map[string]models.Device) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	wantIDs := func(name string, got map[string]models.Device, want ...string) {
		t.Helper()
		sort.Strings(want)
		if g := keys(got); strings.Join(g, ",") != strings.Join(want, ",") {
			t.Fatalf("%s: devices %v, want %v", name, g, want)
		}
	}

	// 1) Provider (header and ?as_tenant) lists ONLY platform devices, both spellings.
	wantIDs("owner + X-Acting-Tenant: global", listDevices(admin, "global", ""), "plat-blank", "plat-global")
	wantIDs("owner + ?as_tenant=global", listDevices(admin, "", "?as_tenant=global"), "plat-blank", "plat-global")
	wantIDs("owner + X-Acting-Tenant: GLOBAL (case)", listDevices(admin, " GLOBAL ", ""), "plat-blank", "plat-global")

	// 2) All tenants (no header, or "all") lists both, each labelled.
	for _, acting := range []string{"", "all"} {
		all := listDevices(admin, acting, "")
		wantIDs("owner all-tenants ("+acting+")", all, "plat-blank", "plat-global", "retail-edge")
		if all["retail-edge"].TenantID != tenantA {
			t.Fatalf("all-tenants view: retail-edge tenant_id = %q, want %q (rows must be labelled)", all["retail-edge"].TenantID, tenantA)
		}
		if all["plat-global"].TenantID != TenantGlobal {
			t.Fatalf("all-tenants view: plat-global tenant_id = %q, want %q", all["plat-global"].TenantID, TenantGlobal)
		}
	}

	// 3) Another tenant's device id under Provider: 404 read, delete refused.
	if st, _ := doActing(t, srv, "GET", "/api/devices/retail-edge", admin, "global", nil); st != 404 {
		t.Fatalf("Provider GET of a tenant's device: %d, want 404", st)
	}
	if st, _ := doActing(t, srv, "DELETE", "/api/devices/retail-edge", admin, "global", nil); st != 404 {
		t.Fatalf("Provider DELETE of a tenant's device: %d, want 404", st)
	}
	if _, ok := listDevices(admin, "", "")["retail-edge"]; !ok {
		t.Fatal("Provider DELETE removed another tenant's device")
	}
	// …while the platform's own untagged device IS reachable under Provider.
	if st, b := doActing(t, srv, "GET", "/api/devices/plat-blank", admin, "global", nil); st != 200 {
		t.Fatalf("Provider GET of its own untagged device: %d %s, want 200", st, b)
	}

	// 4) A tenant user sending "global" is ignored: own rows only.
	wantIDs("tenant user + global", listDevices(userA, "global", ""), "retail-edge")
	wantIDs("tenant user + ?as_tenant=global", listDevices(userA, "", "?as_tenant=global"), "retail-edge")
	// 5) An org-admin NOT bound to the Global tenant is ignored too.
	wantIDs("org-admin (other org) + global", listDevices(boss, "global", ""), "retail-edge")

	// ── saved objects ───────────────────────────────────────────────────────
	mkSaved := func(token, acting, name, tenant string) string {
		t.Helper()
		st, body := doActing(t, srv, "POST", "/api/saved", token, acting, map[string]any{
			"type": "saved_search", "name": name, "tenant_id": tenant, "body": map[string]any{"q": name},
		})
		if st != 201 {
			t.Fatalf("create saved %s: %d %s", name, st, body)
		}
		return idOf(t, body)
	}
	mkSaved(admin, "", "plat-saved-blank", "")
	mkSaved(admin, "", "plat-saved-global", TenantGlobal)
	retailSaved := mkSaved(userA, "", "retail-saved", "")
	// A create under Provider is stamped Provider (from the scope, not the body).
	provSaved := mkSaved(admin, "global", "prov-created", tenantA)

	listSaved := func(token, acting string) []string {
		t.Helper()
		st, body := doActing(t, srv, "GET", "/api/saved?type=saved_search", token, acting, nil)
		if st != 200 {
			t.Fatalf("GET /api/saved: %d %s", st, body)
		}
		var objs []saved.Object
		if err := json.Unmarshal(body, &objs); err != nil {
			t.Fatalf("decode saved: %v (%s)", err, body)
		}
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			out = append(out, o.Name)
		}
		sort.Strings(out)
		return out
	}
	if got := strings.Join(listSaved(admin, "global"), ","); got != "plat-saved-blank,plat-saved-global,prov-created" {
		t.Fatalf("Provider saved list = %s, want platform-only", got)
	}
	if got := strings.Join(listSaved(userA, "global"), ","); got != "retail-saved" {
		t.Fatalf("tenant user + global saved list = %s, want own only", got)
	}
	if got := len(listSaved(admin, "")); got != 4 {
		t.Fatalf("all-tenants saved list has %d objects, want 4", got)
	}
	if st, _ := doActing(t, srv, "GET", "/api/saved/"+provSaved, admin, "", nil); st != 200 {
		t.Fatalf("all-tenants GET of the Provider-created object: %d", st)
	}
	if o, ok := s.saved.Get(provSaved); !ok || o.TenantID != TenantGlobal {
		t.Fatalf("Provider-scope create stamped tenant %q, want %q (owner from the scope, never the body)", o.TenantID, TenantGlobal)
	}
	if st, _ := doActing(t, srv, "GET", "/api/saved/"+retailSaved, admin, "global", nil); st != 404 {
		t.Fatalf("Provider GET of a tenant's saved object: %d, want 404", st)
	}
	if st, _ := doActing(t, srv, "DELETE", "/api/saved/"+retailSaved, admin, "global", nil); st != 404 {
		t.Fatalf("Provider DELETE of a tenant's saved object: %d, want 404", st)
	}
	if _, ok := s.saved.Get(retailSaved); !ok {
		t.Fatal("Provider DELETE removed another tenant's saved object")
	}

	// ── alerts + episodes ───────────────────────────────────────────────────
	now := time.Now().UTC()
	retailAlert := models.Alert{ID: "al-retail", Rule: "HighCPU", Severity: "critical", DeviceID: "retail-edge", Summary: "retail cpu high", FiredAt: now}
	platAlert := models.Alert{ID: "al-plat", Rule: "HighCPU", Severity: "critical", DeviceID: "plat-blank", Summary: "provider cpu high", FiredAt: now}
	stackAlert := models.Alert{ID: "al-stack", Rule: "StackDiskLow", Severity: "warning", Summary: "platform disk nearly full", FiredAt: now}
	s.alerts.SeedActiveForTest(retailAlert, platAlert, stackAlert)
	for _, a := range []models.Alert{retailAlert, platAlert, stackAlert} {
		s.observeAlertTransition(a, true)
	}
	alertsBody := func(token, acting, path string) string {
		t.Helper()
		st, body := doActing(t, srv, "GET", path, token, acting, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		return string(body)
	}
	for _, path := range []string{"/api/alerts", "/api/alerts/episodes"} {
		prov := alertsBody(admin, "global", path)
		if strings.Contains(prov, "retail cpu high") {
			t.Fatalf("Provider %s served another tenant's alert:\n%s", path, prov)
		}
		if !strings.Contains(prov, "provider cpu high") || !strings.Contains(prov, "platform disk nearly full") {
			t.Fatalf("Provider %s lost the platform's own alerts:\n%s", path, prov)
		}
		ten := alertsBody(userA, "global", path)
		if strings.Contains(ten, "provider cpu high") || strings.Contains(ten, "platform disk nearly full") {
			t.Fatalf("tenant user + global %s was served platform alerts:\n%s", path, ten)
		}
		if !strings.Contains(ten, "retail cpu high") {
			t.Fatalf("tenant user %s lost its own alert:\n%s", path, ten)
		}
		all := alertsBody(admin, "", path)
		for _, want := range []string{"retail cpu high", "provider cpu high", "platform disk nearly full"} {
			if !strings.Contains(all, want) {
				t.Fatalf("all-tenants %s missing %q:\n%s", path, want, all)
			}
		}
	}
	// Triage of a tenant's episode under Provider → 404.
	var retailEp string
	{
		var lr struct {
			Episodes []AlertEpisode `json:"episodes"`
		}
		if err := json.Unmarshal([]byte(alertsBody(admin, "", "/api/alerts/episodes")), &lr); err != nil {
			t.Fatal(err)
		}
		for _, ep := range lr.Episodes {
			if ep.Resource == "retail-edge" {
				retailEp = ep.ID
			}
		}
	}
	if retailEp == "" {
		t.Fatal("no retail episode to triage")
	}
	if st, b := doActing(t, srv, "POST", "/api/alerts/episodes/"+retailEp+"/ack", admin, "global", map[string]any{}); st != 404 {
		t.Fatalf("Provider ack of a tenant's episode: %d %s, want 404", st, b)
	}

	// ── NMS integrations (the incident surface) ─────────────────────────────
	mkInt := func(token, acting, name string) string {
		t.Helper()
		st, body := doActing(t, srv, "POST", "/api/nms/integrations", token, acting, map[string]any{
			"vendor": "generic", "displayName": name, "baseUrl": "https://" + name + ".example",
		})
		if st != 201 {
			t.Fatalf("create integration %s: %d %s", name, st, body)
		}
		return idOf(t, body)
	}
	retailInt := mkInt(userA, "", "retail-vmanage")
	provInt := mkInt(admin, "global", "provider-vmanage")
	type pubInt struct {
		ID       string `json:"id"`
		TenantID string `json:"tenantId"`
	}
	listInts := func(token, acting string) map[string]string {
		t.Helper()
		st, body := doActing(t, srv, "GET", "/api/nms/integrations", token, acting, nil)
		if st != 200 {
			t.Fatalf("GET /api/nms/integrations: %d %s", st, body)
		}
		var r struct {
			Integrations []pubInt `json:"integrations"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatalf("decode integrations: %v (%s)", err, body)
		}
		out := map[string]string{}
		for _, c := range r.Integrations {
			out[c.ID] = c.TenantID
		}
		return out
	}
	prov := listInts(admin, "global")
	if len(prov) != 1 || prov[provInt] != TenantGlobal {
		t.Fatalf("Provider NMS list = %v, want only the platform integration %s (tenant %q)", prov, provInt, TenantGlobal)
	}
	all := listInts(admin, "")
	if len(all) != 2 || all[retailInt] != tenantA || all[provInt] != TenantGlobal {
		t.Fatalf("all-tenants NMS list = %v, want both, labelled (%s→%s, %s→%s)", all, retailInt, tenantA, provInt, TenantGlobal)
	}
	if st, _ := doActing(t, srv, "GET", "/api/nms/integrations/"+retailInt, admin, "global", nil); st != 404 {
		t.Fatalf("Provider GET of a tenant's integration: %d, want 404", st)
	}
	if st, _ := doActing(t, srv, "DELETE", "/api/nms/integrations/"+retailInt, admin, "global", nil); st != 404 {
		t.Fatalf("Provider DELETE of a tenant's integration: %d, want 404 (the 2026-10-25 incident)", st)
	}
	if _, ok := listInts(admin, "")[retailInt]; !ok {
		t.Fatal("Provider DELETE removed another tenant's integration (the 2026-10-25 incident)")
	}
	if got := listInts(userA, "global"); len(got) != 1 || got[retailInt] != tenantA {
		t.Fatalf("tenant user + global NMS list = %v, want only its own", got)
	}
}

// The platform owner keeps the platform aggregates on /api/health while scoped
// to Provider (an identity question, not a view scope).
func TestHealthDetailOwnerKeepsAggregatesUnderProvider(t *testing.T) {
	srv, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)
	s.collectors = collectors.NewPool(func() []collectors.Target { return nil })
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	for _, acting := range []string{"", "global"} {
		st, body := doActing(t, srv, "GET", "/api/health", admin, acting, nil)
		if st != 200 {
			t.Fatalf("GET /api/health (acting %q): %d %s", acting, st, body)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if _, ok := out["discovery"]; !ok {
			t.Fatalf("owner (acting %q) lost the platform health aggregates: %s", acting, body)
		}
	}
}
