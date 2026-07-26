package main

// metrics_forecast_isolation_test.go — CLAUDE.md §3a rule 5 for
// GET /api/metrics/forecast.
//
// The capacity forecast reads the same per-interface utilization series the
// Metrics Explorer reads, so it must enforce the same per-tenant device boundary
// (VictoriaMetrics extra_filters[], see metrics_query.go). Exercised end-to-end
// through the REAL router + auth middleware over a HOSTILE fake VictoriaMetrics
// that returns BOTH tenants' series regardless of the filters it was sent: that
// proves the enforcement, not the mock. We assert both halves —
//   1. the query sent upstream carries the caller's own device selector and never
//      another tenant's identifiers (the enforcement point), and
//   2. the rendered response never names another tenant's device (defense in
//      depth, since this handler assembles its rows in Go).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// forecastVMRecorder is a fake VictoriaMetrics that records every query_range URL
// and always answers with two devices' series — one per tenant — plus a
// platform-owned device. It deliberately IGNORES extra_filters[], so any leak is
// the handler's, not the fixture's.
type forecastVMRecorder struct {
	mu   sync.Mutex
	urls []string
}

func (f *forecastVMRecorder) add(u string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.urls = append(f.urls, u)
}

func (f *forecastVMRecorder) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.urls...)
}

// extraFilters returns the extra_filters[] values of every recorded request.
func (f *forecastVMRecorder) extraFilters(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, raw := range f.all() {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("bad recorded url %q: %v", raw, err)
		}
		out = append(out, u.Query()["extra_filters[]"]...)
	}
	return out
}

func startForecastVM(t *testing.T, rec *forecastVMRecorder) {
	t.Helper()
	// Two full weeks of 6h points so the trend is a real forecast, not
	// "building_baseline"; the values matter less than the labels.
	series := func(dev, name string) string {
		var b strings.Builder
		b.WriteString(`{"metric":{"device":"` + dev + `","index":"1","ifName":"Gi0/1","hostname":"` + name + `"},"values":[`)
		const start = 1_700_000_000
		for i := 0; i < 120; i++ { // 120 × 6h = 30 days
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`[` + intToString(start+i*21600) + `,"0.5"]`)
		}
		b.WriteString(`]}`)
		return b.String()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"result":[` +
			series("dev-a", "leaf-a") + `,` +
			series("dev-b", "leaf-b") + `,` +
			series("dev-plat", "leaf-plat") + `]}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
}

// forecastDevices lists the device ids in a /api/metrics/forecast response.
func forecastDevices(t *testing.T, body []byte) []string {
	t.Helper()
	var r struct {
		Interfaces []forecastRow `json:"interfaces"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode forecast: %v (%s)", err, body)
	}
	out := make([]string, 0, len(r.Interfaces))
	for _, row := range r.Interfaces {
		out = append(out, row.Device)
	}
	return out
}

func TestMetricsForecastCrossTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	rec := &forecastVMRecorder{}
	startForecastVM(t, rec)

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, each with one tenant and one tenant-scoped operator.
	type fx struct{ orgID, tenantID, user, token string }
	f := map[string]*fx{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Forecast Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Forecast Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "fc-user-" + name
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": RoleOperator, "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		f[name] = &fx{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}

	// Inventory: one device per tenant plus a platform-owned (untagged) one.
	s.discovery.Upsert(models.Device{ID: "dev-a", Name: "leaf-a", Address: "10.0.0.1", TenantID: f["A"].tenantID})
	s.discovery.Upsert(models.Device{ID: "dev-b", Name: "leaf-b", Address: "10.0.0.2", TenantID: f["B"].tenantID})
	s.discovery.Upsert(models.Device{ID: "dev-plat", Name: "leaf-plat", Address: "10.0.0.3"})

	// 1) A scoped tenant sees ONLY its own device — the upstream offered all three.
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "GET", "/api/metrics/forecast", f[name].token, nil)
		if st != 200 {
			t.Fatalf("tenant %s forecast: %d %s", name, st, b)
		}
		want := "dev-" + strings.ToLower(name)
		got := forecastDevices(t, b)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("CROSS-TENANT LEAK: tenant %s forecast lists %v, want exactly [%s]\n%s", name, got, want, b)
		}
		other := "dev-b"
		if name == "B" {
			other = "dev-a"
		}
		if strings.Contains(string(b), other) || strings.Contains(string(b), "dev-plat") {
			t.Fatalf("CROSS-TENANT LEAK: tenant %s response names a foreign device:\n%s", name, b)
		}
	}

	// 2) The query actually sent upstream is device-bounded and never names
	//    another tenant's device (the boundary is enforced at the source, not by
	//    post-filtering a full-fleet answer).
	filters := rec.extraFilters(t)
	if len(filters) == 0 {
		t.Fatal("scoped tenant query carried NO extra_filters[] — the VM read was unscoped")
	}
	joined := strings.Join(filters, " ")
	if !strings.Contains(joined, "dev-a") || !strings.Contains(joined, "dev-b") {
		t.Fatalf("expected each tenant's own selector in %v", filters)
	}
	for _, raw := range rec.all() {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		fs := strings.Join(u.Query()["extra_filters[]"], " ")
		if strings.Contains(fs, "dev-a") && strings.Contains(fs, "dev-b") {
			t.Errorf("one request mixed both tenants' devices: %s", fs)
		}
	}

	// 3) The platform owner is cross-tenant: no filter, and it sees the whole fleet.
	st, b := do(t, srv, "GET", "/api/metrics/forecast", admin, nil)
	if st != 200 {
		t.Fatalf("owner forecast: %d %s", st, b)
	}
	owner := strings.Join(forecastDevices(t, b), ",")
	for _, want := range []string{"dev-a", "dev-b", "dev-plat"} {
		if !strings.Contains(owner, want) {
			t.Errorf("platform owner forecast missing %s: %v", want, owner)
		}
	}

	// 4) as_tenant into ANOTHER org is ignored for a scoped principal (it may only
	//    ever narrow to a tenant it reaches — never widen into org B).
	st, b = do(t, srv, "GET", "/api/metrics/forecast?as_tenant="+f["B"].tenantID, f["A"].token, nil)
	if st != 200 {
		t.Fatalf("A with as_tenant=B: %d %s", st, b)
	}
	if got := forecastDevices(t, b); len(got) != 1 || got[0] != "dev-a" {
		t.Fatalf("as_tenant escalation: tenant A sees %v, want [dev-a]\n%s", got, b)
	}
}

// A tenant with no visible device must fail CLOSED: a match-nothing selector and
// an empty forecast — never an unfiltered fleet-wide read.
func TestMetricsForecastDevicelessTenantFailsClosed(t *testing.T) {
	srv, s := newTestServerState(t)
	rec := &forecastVMRecorder{}
	startForecastVM(t, rec)

	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Empty Tenant"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "fc-empty", "password": "Passw0rd!2345", "role": RoleOperator, "tenant_id": tenantID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	token := login(t, srv, "fc-empty", "Passw0rd!2345").Token

	// Someone else's device exists in the fleet.
	s.discovery.Upsert(models.Device{ID: "dev-other", Name: "leaf-other", Address: "10.0.0.9", TenantID: "t-other"})

	st, b = do(t, srv, "GET", "/api/metrics/forecast", token, nil)
	if st != 200 {
		t.Fatalf("deviceless tenant forecast: %d %s", st, b)
	}
	if got := forecastDevices(t, b); len(got) != 0 {
		t.Fatalf("deviceless tenant must see nothing, got %v\n%s", got, b)
	}
	filters := rec.extraFilters(t)
	if len(filters) == 0 {
		t.Fatal("deviceless tenant query carried NO extra_filters[] — unscoped read")
	}
	for _, f := range filters {
		if !strings.Contains(f, "__netops_no_visible_device__") {
			t.Errorf("expected the match-nothing selector, got %q", f)
		}
	}
}

// A scoped principal must be REFUSED (not served unscoped) when the metrics
// upstream cannot enforce label scoping — extra_filters[] is a VictoriaMetrics
// extension Prometheus ignores. Mirrors proxyMetrics' fail-closed rule.
func TestMetricsForecastRefusesScopedQueryOnNonVictoriaUpstream(t *testing.T) {
	srv, s := newTestServerState(t)
	t.Setenv("VICTORIA_URL", "http://prometheus:9090")

	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Prom Tenant"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "fc-prom", "password": "Passw0rd!2345", "role": RoleOperator, "tenant_id": tenantID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	s.discovery.Upsert(models.Device{ID: "dev-p", Name: "leaf-p", Address: "10.0.0.7", TenantID: tenantID})
	token := login(t, srv, "fc-prom", "Passw0rd!2345").Token

	if st, b := do(t, srv, "GET", "/api/metrics/forecast", token, nil); st != http.StatusNotImplemented {
		t.Fatalf("scoped forecast on a Prometheus upstream: %d %s, want 501", st, b)
	}
}

// forecastScope.permits is the in-Go row guard: default-closed for a scoped
// principal (including a series carrying no device-identifying label at all).
func TestForecastScopePermits(t *testing.T) {
	scoped := forecastScope{
		scoped: true,
		ids:    map[string]bool{"dev-a": true},
		names:  map[string]bool{"leaf-a": true},
	}
	cases := []struct {
		lbl  map[string]string
		want bool
	}{
		{map[string]string{"device": "dev-a"}, true},
		{map[string]string{"hostname": "leaf-a"}, true},
		{map[string]string{"source": "leaf-a"}, true},
		{map[string]string{"device": "dev-b"}, false},
		{map[string]string{"hostname": "leaf-b"}, false},
		{map[string]string{"job": "victoria"}, false}, // no device identity → not its data
		{nil, false},
	}
	for _, c := range cases {
		if got := scoped.permits(c.lbl); got != c.want {
			t.Errorf("scoped.permits(%v) = %v, want %v", c.lbl, got, c.want)
		}
	}
	if (forecastScope{denyAll: true}).permits(map[string]string{"device": "dev-a"}) {
		t.Error("a restricted-tenant operator must see nothing")
	}
	excl := forecastScope{denied: map[string]bool{"dev-x": true, "leaf-x": true}}
	if excl.permits(map[string]string{"device": "dev-x"}) || excl.permits(map[string]string{"source": "leaf-x"}) {
		t.Error("operator-restricted device must be excluded from the Global view")
	}
	if !excl.permits(map[string]string{"device": "dev-ok"}) {
		t.Error("unrestricted device must stay visible in the Global view")
	}
}
