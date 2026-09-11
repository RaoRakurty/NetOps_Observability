// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// path_health_scope_isolation_test.go — CLAUDE.md §3a rule 5 isolation test for
// /api/paths/health.
//
// THE DEFECT (2026-09-11 sweep). handlePathsHealth derived the caller's device
// boundary into phFilters, handed it to the resolver, and then ran its EIGHT
// baseline queries through s.vmInstant — a helper whose whole body was
// `vmInstantScoped(ctx, query, nil)`. Those eight reads carried no tenant scope
// at all, so a tenant-scoped operator's path list was built from the WHOLE
// fleet's probe series: another tenant's destination host (the `dst` label,
// echoed as path_id and dst on the wire) and that destination's latency and
// jitter percentiles.
//
// The guard that should have caught it, TestMetricsRoutesCarryCallerScope, was
// aimed at "/api/rca/path/health" — a route this server does not register. It
// skipped with "route made no VictoriaMetrics call in this fixture" and had
// been passing that way. Aiming it at /api/paths/health turns it red.
//
// The second half is the tier-2 precompute read: fetchHourBaselines asked
// netops.path_baselines for EVERY path_id at the '__all__' scope. Its written
// justification was that these rows derive from series "/api/paths/health
// already serves unscoped" — true only while the bug above was live.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// fleetVM emulates VictoriaMetrics closely enough for an isolation test: it
// honours extra_filters[] the way the server does, by dropping series whose
// `device` label is not named by the filter. An UNFILTERED query therefore gets
// the whole fleet — which is exactly the leak under test.
type fleetVM struct {
	mu      sync.Mutex
	queries []url.Values
	series  []map[string]string // labels; "__value__" holds the sample
}

func (f *fleetVM) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.queries = append(f.queries, q)
		f.mu.Unlock()

		var allow *regexp.Regexp
		for _, ef := range q["extra_filters[]"] {
			if m := regexp.MustCompile(`device=~"([^"]*)"`).FindStringSubmatch(ef); m != nil {
				allow = regexp.MustCompile(`^(?:` + m[1] + `)$`)
			}
		}
		type res struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		}
		out := []res{}
		for _, s := range f.series {
			if allow != nil && !allow.MatchString(s["device"]) {
				continue
			}
			lbl := map[string]string{}
			for k, v := range s {
				if k != "__value__" {
					lbl[k] = v
				}
			}
			out = append(out, res{Metric: lbl, Value: [2]any{1.0, s["__value__"]}})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": out},
		})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
	t.Setenv("METRICS_URL", srv.URL)
}

func (f *fleetVM) unfiltered() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []url.Values
	for _, q := range f.queries {
		if len(q["extra_filters[]"]) == 0 {
			out = append(out, q)
		}
	}
	return out
}

// captureCH records the SQL every ClickHouse read carries and answers empty.
type captureCH struct {
	mu  sync.Mutex
	sql []string
}

func (c *captureCH) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // best-effort: a short read only weakens the assertion
		c.mu.Lock()
		c.sql = append(c.sql, string(b)+" "+r.URL.RawQuery)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

func (c *captureCH) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.sql, "\n")
}

func TestPathsHealthHonoursTheCallerDeviceBoundary(t *testing.T) {
	vm := &fleetVM{series: []map[string]string{
		// Tenant A's probe. Its destination host is the field that must never
		// reach tenant B.
		{"device": "dev-a", "dst": "payroll-a.internal.example", "__value__": "41"},
		// Tenant B's own probe.
		{"device": "dev-b", "dst": "erp-b.internal.example", "__value__": "12"},
	}}
	vm.start(t)
	ch := &captureCH{}
	ch.start(t)
	t.Setenv("FEATURE_PATH_BASELINES", "true")

	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	mk := func(name string) string {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		return idOf(t, b)
	}
	tenantA, tenantB := mk("A"), mk("B")
	s.discovery.Upsert(models.Device{ID: "dev-a", Name: "dev-a", TenantID: tenantA})
	s.discovery.Upsert(models.Device{ID: "dev-b", Name: "dev-b", TenantID: tenantB})

	st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "bob-b", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantB,
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	tokenB := login(t, srv, "bob-b", "Passw0rd!2345").Token

	st, body := do(t, srv, "GET", "/api/paths/health", tokenB, nil)
	if st != 200 {
		t.Fatalf("paths health: %d %s", st, body)
	}

	// 1. No VictoriaMetrics read made while serving this request may be
	//    unfiltered. Eight of them were.
	if un := vm.unfiltered(); len(un) > 0 {
		t.Fatalf("%d VictoriaMetrics queries ran with no extra_filters[] while serving a tenant-scoped caller; first was %q",
			len(un), un[0].Get("query"))
	}

	// 2. The leaked field, named: tenant A's destination host.
	if strings.Contains(string(body), "payroll-a.internal.example") {
		t.Fatalf("tenant B's path list names tenant A's measured destination (path_id/dst payroll-a.internal.example):\n%s", body)
	}
	if !strings.Contains(string(body), "erp-b.internal.example") {
		t.Fatalf("tenant B must still see its OWN path — the fix must not empty the view:\n%s", body)
	}

	// 3. The tier-2 precompute read may only name the caller's own paths.
	sql := ch.joined()
	if strings.Contains(sql, "path_baselines") {
		if strings.Contains(sql, "payroll-a.internal.example") {
			t.Fatalf("the path_baselines read named tenant A's path:\n%s", sql)
		}
		if !strings.Contains(sql, "path_id IN (") {
			t.Fatalf("the path_baselines read is not bounded to the caller's paths:\n%s", sql)
		}
	}
}

// The platform owner legitimately reads across tenants, so the same request
// must still return both paths — the fix is a boundary, not a blanket.
func TestPathsHealthPlatformOwnerStillSeesTheFleet(t *testing.T) {
	vm := &fleetVM{series: []map[string]string{
		{"device": "dev-a", "dst": "payroll-a.internal.example", "__value__": "41"},
		{"device": "dev-b", "dst": "erp-b.internal.example", "__value__": "12"},
	}}
	vm.start(t)

	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	s.discovery.Upsert(models.Device{ID: "dev-a", Name: "dev-a", TenantID: "tenant-a"})
	s.discovery.Upsert(models.Device{ID: "dev-b", Name: "dev-b", TenantID: "tenant-b"})

	st, body := do(t, srv, "GET", "/api/paths/health", admin, nil)
	if st != 200 {
		t.Fatalf("paths health: %d %s", st, body)
	}
	for _, want := range []string{"payroll-a.internal.example", "erp-b.internal.example"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("the platform owner must still see %s:\n%s", want, body)
		}
	}
}
