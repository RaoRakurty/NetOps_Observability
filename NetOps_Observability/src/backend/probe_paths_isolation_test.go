// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// probe_paths_isolation_test.go — §3a cross-org isolation for the measured-path
// surface (Paths redesign P3). GET /api/probe/paths used to be classed as
// stack-wide "infra" and returned every path to any authenticated caller; once
// tenants name their own targets, a path is that tenant's data.

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/dem"
	"netops/backend/models"
)

func TestProbePathsCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.remotePaths = newRemotePathStore()
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
		user := "paths-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// Each tenant's remote vantage pushes ONE trace to the same destination
	// under the SAME vantage id, and each body forges the OTHER tenant as owner.
	push := func(token, forged, hop string) {
		t.Helper()
		body := []map[string]any{{
			"vantage_id": "lan-1", "dst": "198.51.100.7", "method": "icmp", "tenant_id": forged,
			"hops": []map[string]any{{"ttl": 1, "ip": hop}}, "reached": true, "ts": time.Now().UTC(),
		}}
		if st, rb := do(t, srv, "POST", "/api/probe/paths", token, body); st != 202 {
			t.Fatalf("push: %d %s", st, rb)
		}
	}
	push(a.token, b.tenantID, "10.1.0.1")
	push(b.token, a.tenantID, "10.2.0.1")
	push(admin, a.tenantID, "10.9.0.1") // the platform owner's "All tenants" view stamps the platform

	list := func(token, query string) []collectors.PathResult {
		t.Helper()
		st, rb := do(t, srv, "GET", "/api/probe/paths"+query, token, nil)
		if st != 200 {
			t.Fatalf("GET: %d %s", st, rb)
		}
		var out []collectors.PathResult
		if err := json.Unmarshal(rb, &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rb)
		}
		return out
	}
	only := func(who string, got []collectors.PathResult, tenant, hop string) {
		t.Helper()
		if len(got) != 1 || got[0].TenantID != tenant || got[0].Hops[0].IP != hop {
			t.Fatalf("%s: got %+v, want exactly its own path (tenant %s, hop %s)", who, got, tenant, hop)
		}
	}

	// 1) Own-only, and the forged body tenant was ignored (owner = the pusher).
	only("tenant A", list(a.token, ""), a.tenantID, "10.1.0.1")
	only("tenant B", list(b.token, ""), b.tenantID, "10.2.0.1")

	// 2) as_tenant into another org is ignored for a non-owner.
	only("tenant A as_tenant=B", list(a.token, "?as_tenant="+b.tenantID), a.tenantID, "10.1.0.1")

	// 3) The same vantage id did not let one tenant replace another's traces,
	//    and the platform owner (cross-tenant) reads all three, the platform's
	//    own untagged one included.
	if all := list(admin, ""); len(all) != 3 {
		t.Fatalf("platform owner sees %d paths, want 3: %+v", len(all), all)
	}

	// 4) PATH_GRAPH_TENANT names the owner of UNTAGGED paths only: on a
	//    single-tenant install that tenant reads the install-time traces; the
	//    other tenant still does not.
	t.Setenv("PATH_GRAPH_TENANT", a.tenantID)
	if got := list(a.token, ""); len(got) != 2 {
		t.Fatalf("with PATH_GRAPH_TENANT=A, tenant A reads its own + the untagged path, got %+v", got)
	}
	only("tenant B with PATH_GRAPH_TENANT=A", list(b.token, ""), b.tenantID, "10.2.0.1")
}

// The pure rule, including the restriction and the Provider scope.
func TestProbePathsVisibleToRule(t *testing.T) {
	t.Setenv("PATH_GRAPH_TENANT", "")
	paths := []collectors.PathResult{
		{Dst: "a", TenantID: "acme"},
		{Dst: "g", TenantID: "Globex "},
		{Dst: "p"}, // platform-owned
	}
	dsts := func(ps []collectors.PathResult) string {
		out := ""
		for _, p := range ps {
			out += p.Dst
		}
		return out
	}
	cases := []struct {
		name string
		v    tenantVisibility
		want string
	}{
		{"tenant reads its own", tenantVisibility{tenant: "acme"}, "a"},
		{"case-tolerant owner", tenantVisibility{tenant: "globex"}, "g"},
		{"Provider reads the platform's", tenantVisibility{tenant: "global"}, "p"},
		{"unbound scope reads nothing", tenantVisibility{tenant: ""}, ""},
		{"cross reads all", tenantVisibility{tenant: "global", cross: true}, "agp"},
		{"restriction hides on the cross path", tenantVisibility{tenant: "global", cross: true, hiddenTenants: map[string]bool{"acme": true}}, "gp"},
		{"operator scoped into a restricted tenant", tenantVisibility{tenant: "acme", deny: true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dsts(probePathsVisibleTo(c.v, paths)); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// GET /api/probe/targets/suggested: the caller's OWN inventory edges and its
// OWN catalogue count — never another tenant's devices; as_tenant ignored.
func TestProbeTargetSuggestionsCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.demTargets = dem.NewFileStore(filepath.Join(t.TempDir(), "dem.json"))
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Sugg Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Sugg Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "sugg-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]
	for _, d := range []models.Device{
		{ID: "edge-a", Name: "edge-a", Address: "192.0.2.10", TenantID: a.tenantID, Labels: map[string]string{"device_type": "router", "site": "branch-a"}},
		{ID: "sw-a", Name: "sw-a", Address: "192.0.2.11", TenantID: a.tenantID, Labels: map[string]string{"device_type": "switch"}},
		{ID: "edge-b", Name: "edge-b", Address: "192.0.2.20", TenantID: b.tenantID, Labels: map[string]string{"device_type": "router", "site": "branch-b"}},
		{ID: "edge-loop", Name: "edge-loop", Address: "127.0.0.1", TenantID: a.tenantID, Labels: map[string]string{"device_type": "router"}},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatal(err)
		}
	}
	// Tenant B already traces its edge; tenant A traces nothing.
	// (Seeded through the store: the DEM routes are wired by main, not the harness.)
	if _, err := s.demTargets.Create(context.Background(), dem.Target{
		TenantID: b.tenantID, Name: "Path to edge-b", Kind: dem.KindICMP, Host: "192.0.2.20", TracePath: true,
	}); err != nil {
		t.Fatalf("B create target: %v", err)
	}
	type resp struct {
		Tracing     int `json:"tracing"`
		Suggestions []struct {
			DeviceID string `json:"device_id"`
			Address  string `json:"address"`
			Site     string `json:"site"`
			Traced   bool   `json:"traced"`
		} `json:"suggestions"`
	}
	get := func(token, q string) resp {
		t.Helper()
		st, rb := do(t, srv, "GET", "/api/probe/targets/suggested"+q, token, nil)
		if st != 200 {
			t.Fatalf("GET: %d %s", st, rb)
		}
		var r resp
		if err := json.Unmarshal(rb, &r); err != nil {
			t.Fatalf("decode: %v (%s)", err, rb)
		}
		return r
	}
	ra := get(a.token, "")
	if ra.Tracing != 0 || len(ra.Suggestions) != 1 || ra.Suggestions[0].DeviceID != "edge-a" || ra.Suggestions[0].Site != "branch-a" {
		t.Fatalf("tenant A: %+v (own router only: not its switch, not a loopback address, never B's edge)", ra)
	}
	rb := get(b.token, "")
	if rb.Tracing != 1 || len(rb.Suggestions) != 1 || rb.Suggestions[0].DeviceID != "edge-b" || !rb.Suggestions[0].Traced {
		t.Fatalf("tenant B: %+v", rb)
	}
	if r := get(a.token, "?as_tenant="+b.tenantID); len(r.Suggestions) != 1 || r.Suggestions[0].DeviceID != "edge-a" || r.Tracing != 0 {
		t.Fatalf("as_tenant into B must be ignored: %+v", r)
	}
	if st, _ := do(t, srv, "POST", "/api/probe/targets/suggested", a.token, nil); st != 405 {
		t.Fatalf("POST: %d, want 405", st)
	}
}

// Layer 2: the projector resolves, checks against the OWNING tenant's own
// inventory and pins. An internal address is published only for the tenant
// that owns it; a never-probed address and an untraced target are not.
func TestProberTargetCollectChecksTheOwnersInventory(t *testing.T) {
	_, s := newTestServerState(t)
	s.demTargets = dem.NewFileStore(filepath.Join(t.TempDir(), "dem.json"))
	ctx := context.Background()
	for _, d := range []models.Device{
		{ID: "a1", Name: "a1", Address: "10.40.0.1", TenantID: "acme"},
		{ID: "b1", Name: "b1", Address: "10.50.0.1", TenantID: "globex"},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(tenant, host string, trace, stamp bool) {
		t.Helper()
		if _, err := s.demTargets.Create(ctx, dem.Target{TenantID: tenant, Name: tenant + " " + host, Kind: dem.KindICMP, Host: host, TracePath: trace, StampProbe: stamp}); err != nil {
			t.Fatalf("create %s %s: %v", tenant, host, err)
		}
	}
	mk("acme", "10.40.0.1", true, true)        // acme's own internal edge → published, both lists
	mk("acme", "10.50.0.1", true, false)       // globex's device: internal, NOT owned by acme → dropped
	mk("globex", "203.0.113.9", true, false)   // public → published for globex
	mk("globex", "198.51.100.4", false, false) // not traced → not a prober target at all
	tr, st, dropped, err := s.proberTargetCollect()(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1 (acme naming globex's internal address)", dropped)
	}
	got := map[string]string{}
	for _, w := range tr {
		got[w.Addr] = w.Tenant
	}
	if len(tr) != 2 || got["10.40.0.1"] != "acme" || got["203.0.113.9"] != "globex" {
		t.Fatalf("traceroute list = %+v", tr)
	}
	if len(st) != 1 || st[0].Addr != "10.40.0.1" || st[0].Tenant != "acme" {
		t.Fatalf("stamp list = %+v", st)
	}
}
