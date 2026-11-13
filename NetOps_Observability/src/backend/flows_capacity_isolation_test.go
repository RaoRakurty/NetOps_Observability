// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// GET /api/flows/capacity (tracker 400 (d)), §3a.5, through the REAL router and
// auth middleware over a HOSTILE fake VictoriaMetrics that answers every query
// with three devices' series (tenant A's, tenant B's, the platform's) whatever
// extra_filters[] it was sent. So a leak would be the handler's, not the mock's.
// Also the known-p95 scenario with exact numbers: a 100 Mb/s link at a p95 of
// 40 Mb/s reads 40 %, 60 Mb/s of headroom, and a 50 %→63 % ramp over 14 days
// reaches 90 % in exactly 27 days.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"netops/backend/models"
)

func startCapacityVM(t *testing.T, rec *forecastVMRecorder) {
	t.Helper()
	labels := func(dev string) string {
		return `{"device":"` + dev + `","index":"1","ifName":"Gi0/1","hostname":"host-` + dev + `"}`
	}
	devs := []string{"dev-a", "dev-b", "dev-plat"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.URL.String())
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		var parts []string
		if strings.HasSuffix(r.URL.Path, "/query_range") {
			// Daily p95: 50, 51, … 63 % of 100 Mb/s over 14 days, in only.
			for _, d := range devs {
				var vals []string
				if strings.Contains(q, "device_if_in_octets") {
					for i := 0; i < 14; i++ {
						vals = append(vals, `[`+intToString(1_794_000_000+i*86400)+`,"`+intToString((50+i)*1_000_000)+`"]`)
					}
				}
				parts = append(parts, `{"metric":`+labels(d)+`,"values":[`+strings.Join(vals, ",")+`]}`)
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[` + strings.Join(parts, ",") + `]}}`))
			return
		}
		val := "0"
		switch {
		case strings.Contains(q, "device_if_speed"):
			val = "100000000"
		case strings.HasPrefix(q, "quantile_over_time") && strings.Contains(q, "device_if_out_octets"):
			val = "40000000"
		case strings.HasPrefix(q, "quantile_over_time"):
			val = "25000000"
		case strings.HasPrefix(q, "max_over_time"):
			val = "70000000"
		}
		for _, d := range devs {
			parts = append(parts, `{"metric":`+labels(d)+`,"value":[1794549600,"`+val+`"]}`)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(parts, ",") + `]}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
}

type flowCapFixture struct {
	srv    *httptest.Server
	s      *server
	admin  string
	tenant map[string]string // name → tenant id
	token  map[string]string // name → scoped operator token
}

func newFlowCapFixture(t *testing.T) flowCapFixture {
	t.Helper()
	srv, s := newTestServerState(t)
	f := flowCapFixture{srv: srv, s: s, admin: login(t, srv, "admin", "Passw0rd!2345").Token, tenant: map[string]string{}, token: map[string]string{}}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", f.admin, map[string]any{"name": "Cap Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		st, b = do(t, srv, "POST", "/api/tenants", f.admin, map[string]any{"name": "Cap Tenant " + name, "org_id": idOf(t, b)})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		f.tenant[name] = idOf(t, b)
		user := "cap-user-" + name
		if st, b := do(t, srv, "POST", "/api/users", f.admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": RoleOperator, "tenant_id": f.tenant[name],
		}); st != 201 {
			t.Fatalf("create user: %d %s", st, b)
		}
		f.token[name] = login(t, srv, user, "Passw0rd!2345").Token
	}
	s.discovery.Upsert(models.Device{ID: "dev-a", Name: "leaf-a", Address: "10.0.0.1", TenantID: f.tenant["A"]})
	s.discovery.Upsert(models.Device{ID: "dev-b", Name: "leaf-b", Address: "10.0.0.2", TenantID: f.tenant["B"]})
	s.discovery.Upsert(models.Device{ID: "dev-plat", Name: "leaf-plat", Address: "10.0.0.3"})
	return f
}

type flowCapBody struct {
	Interfaces []struct {
		DeviceID    string   `json:"device_id"`
		DeviceName  string   `json:"device_name"`
		Exporter    string   `json:"exporter"`
		SpeedBasis  string   `json:"speed_basis"`
		P95Pct      *float64 `json:"p95_pct"`
		P95Bps      *float64 `json:"p95_bps"`
		PeakPct     *float64 `json:"peak_pct"`
		HeadroomBps *float64 `json:"headroom_bps"`
		Forecast    struct {
			Status   string   `json:"status"`
			DaysTo90 *float64 `json:"days_to_90"`
		} `json:"forecast"`
	} `json:"interfaces"`
	Total int `json:"total"`
}

func decodeFlowCap(t *testing.T, b []byte) flowCapBody {
	t.Helper()
	var c flowCapBody
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode capacity: %v (%s)", err, b)
	}
	return c
}

func TestFlowsCapacityCrossTenantIsolationAndKnownP95(t *testing.T) {
	rec := &forecastVMRecorder{}
	startCapacityVM(t, rec)
	f := newFlowCapFixture(t)

	for _, name := range []string{"A", "B"} {
		st, b := do(t, f.srv, "GET", "/api/flows/capacity?since=24h", f.token[name], nil)
		if st != 200 {
			t.Fatalf("tenant %s capacity: %d %s", name, st, b)
		}
		want, other := "dev-a", "dev-b"
		if name == "B" {
			want, other = "dev-b", "dev-a"
		}
		c := decodeFlowCap(t, b)
		if len(c.Interfaces) != 1 || c.Interfaces[0].DeviceID != want || c.Total != 1 {
			t.Fatalf("CROSS-TENANT LEAK: tenant %s sees %+v, want exactly %s\n%s", name, c.Interfaces, want, b)
		}
		if strings.Contains(string(b), other) || strings.Contains(string(b), "dev-plat") || strings.Contains(string(b), "leaf-plat") {
			t.Fatalf("CROSS-TENANT LEAK: tenant %s answer names a foreign device:\n%s", name, b)
		}
		row := c.Interfaces[0]
		if row.SpeedBasis != "reported" || *row.P95Pct != 40 || *row.P95Bps != 40e6 || *row.PeakPct != 70 || *row.HeadroomBps != 60e6 {
			t.Fatalf("known p95: %+v", row)
		}
		if row.Forecast.Status != "rising" || row.Forecast.DaysTo90 == nil || *row.Forecast.DaysTo90 != 27 {
			t.Fatalf("ramp forecast: %+v", row.Forecast)
		}
		if row.DeviceName != "leaf-"+strings.ToLower(name) || row.Exporter == "" {
			t.Fatalf("device naming: %+v", row)
		}
	}
	// Every upstream read carried a boundary, and none mixed the two tenants.
	urls := rec.all()
	if len(urls) == 0 {
		t.Fatal("no upstream read")
	}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		fs := strings.Join(u.Query()["extra_filters[]"], " ")
		if fs == "" {
			t.Fatalf("an unscoped VictoriaMetrics read: %s", raw)
		}
		if strings.Contains(fs, "dev-a") && strings.Contains(fs, "dev-b") {
			t.Errorf("one read mixed both tenants: %s", fs)
		}
		// The daily read is bounded to the displayed rows' devices, never fleet-wide.
		if strings.HasSuffix(u.Path, "/query_range") && !strings.Contains(u.Query().Get("query"), `device=~"`) {
			t.Errorf("the forecast read is not bounded to the displayed devices: %s", u.Query().Get("query"))
		}
	}
	// The platform operator sees the fleet.
	st, b := do(t, f.srv, "GET", "/api/flows/capacity", f.admin, nil)
	if st != 200 || decodeFlowCap(t, b).Total != 3 {
		t.Fatalf("owner capacity: %d %s", st, b)
	}
	// ?as_tenant into another org is ignored.
	st, b = do(t, f.srv, "GET", "/api/flows/capacity?as_tenant="+f.tenant["B"], f.token["A"], nil)
	if c := decodeFlowCap(t, b); st != 200 || len(c.Interfaces) != 1 || c.Interfaces[0].DeviceID != "dev-a" {
		t.Fatalf("as_tenant escalation: %d %s", st, b)
	}
}

func TestFlowsCapacityExplicitWindowEvaluatesAtItsEnd(t *testing.T) {
	rec := &forecastVMRecorder{}
	startCapacityVM(t, rec)
	f := newFlowCapFixture(t)
	st, b := do(t, f.srv, "GET", "/api/flows/capacity?from=1794546000&to=1794549600", f.token["A"], nil)
	if st != 200 {
		t.Fatalf("capacity: %d %s", st, b)
	}
	saw := 0
	for _, raw := range rec.all() {
		u, _ := url.Parse(raw) // recorded from a live request; parse cannot fail meaningfully here
		if q := u.Query().Get("query"); strings.Contains(q, "_over_time(") && !strings.Contains(q, "[1d:5m]") {
			saw++
			if !strings.Contains(q, "[3600s:5m] @ 1794549600") {
				t.Errorf("a past window must be evaluated at its end: %s", q)
			}
		}
	}
	if saw != 4 {
		t.Fatalf("want the four p95/peak reads, saw %d", saw)
	}
}

func TestFlowsCapacityFailsClosed(t *testing.T) {
	rec := &forecastVMRecorder{}
	startCapacityVM(t, rec)
	f := newFlowCapFixture(t)
	// A scoped tenant with no device: the match-nothing selector, no rows.
	st, b := do(t, f.srv, "POST", "/api/tenants", f.admin, map[string]any{"name": "Cap Empty"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	if st, b := do(t, f.srv, "POST", "/api/users", f.admin, map[string]any{
		"username": "cap-empty", "password": "Passw0rd!2345", "role": RoleOperator, "tenant_id": idOf(t, b),
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	tok := login(t, f.srv, "cap-empty", "Passw0rd!2345").Token
	st, b = do(t, f.srv, "GET", "/api/flows/capacity", tok, nil)
	if c := decodeFlowCap(t, b); st != 200 || len(c.Interfaces) != 0 {
		t.Fatalf("deviceless tenant: %d %s", st, b)
	}
	for _, fl := range rec.extraFilters(t) {
		if !strings.Contains(fl, "__netops_no_visible_device__") && !strings.Contains(fl, "dev-") {
			t.Errorf("unexpected filter %q", fl)
		}
	}
	// Hostile parameters: 400 and no upstream read.
	before := len(rec.all())
	for _, path := range []string{
		"/api/flows/capacity?since=45d", "/api/flows/capacity?days=13", "/api/flows/capacity?days=31",
		"/api/flows/capacity?limit=0", "/api/flows/capacity?from=x&to=y",
	} {
		if st, b := do(t, f.srv, "GET", path, f.token["A"], nil); st != 400 {
			t.Errorf("%s: %d %s, want 400", path, st, b)
		}
	}
	if len(rec.all()) != before {
		t.Fatalf("a rejected request still read VictoriaMetrics")
	}
	// A Prometheus upstream cannot honour extra_filters[]: refused, not unscoped.
	t.Setenv("VICTORIA_URL", "http://prometheus:9090")
	if st, b := do(t, f.srv, "GET", "/api/flows/capacity", f.token["A"], nil); st != http.StatusNotImplemented {
		t.Fatalf("non-Victoria upstream: %d %s, want 501", st, b)
	}
}

// The capacity tab sits behind explore, like every flow read (owner decision
// 2026-11-13 (b)): a role that can read the infrastructure area but not
// Explore is refused before any upstream read.
func TestFlowsCapacityExploreGate(t *testing.T) {
	rec := &forecastVMRecorder{}
	startCapacityVM(t, rec)
	s := flowsPermServer(t)
	w := httptest.NewRecorder()
	s.handleFlowsCapacity(w, req(http.MethodGet, "/api/flows/capacity", "", jwtClaims{Sub: "i@acme", Role: "infra-reader", Tenant: "acme"}))
	if w.Code != http.StatusForbidden || len(rec.all()) != 0 {
		t.Fatalf("infra-only role: status %d, %d upstream reads; want 403 and none", w.Code, len(rec.all()))
	}
	w = httptest.NewRecorder()
	s.handleFlowsCapacity(w, req(http.MethodGet, "/api/flows/capacity", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("explore reader: status %d %s", w.Code, w.Body.String())
	}
}
