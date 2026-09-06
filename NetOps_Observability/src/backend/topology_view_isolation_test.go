// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// topology_view_isolation_test.go — CROSS-ORG isolation for GET /api/topology/view
// (CLAUDE.md §3a rule 5). Tracker #133(d): the route was classified "scoped" and
// its VictoriaMetrics boundary was pinned (metrics_route_scope_isolation_test.go),
// but nothing asserted the thing an operator actually reads — the NODE SET.
//
// The projection resolves LLDP/CDP neighbours against the caller's visible
// inventory, and `topoLinkMaps`'s own comment says why that slice must be scoped:
// a neighbour string that happens to match another tenant's hostname would
// resolve to that tenant's device id. This drives the REAL router + auth
// middleware and asserts that neither tenant ever sees the other's devices — in
// explore mode, through an `as_tenant` widening attempt, or as a path-trace
// endpoint.

import (
	"encoding/json"
	"testing"

	"netops/backend/alerts"
	"netops/backend/models"
	"netops/backend/topology"
)

func TestTopologyViewHTTPIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil) // the minimal test server leaves it nil
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	onboard := func(org, tenant, slug string) onboardResponse {
		st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
			"org_name": org, "tenant_name": tenant, "tenant_slug": slug,
		})
		if st != 201 {
			t.Fatalf("onboard %s: %d %s", org, st, b)
		}
		var r onboardResponse
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	acme := onboard("Acme Corp", "Acme Prod", "acme-prod")
	globex := onboard("Globex Inc", "Globex Prod", "globex-prod")

	mkUser := func(name, tenantID string) string {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": name, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		return login(t, srv, name, "Passw0rd!2345").Token
	}
	alice := mkUser("alice", acme.Tenant.ID)
	bob := mkUser("bob", globex.Tenant.ID)

	// Deliberately OVERLAPPING hostnames and addresses: the two tenants each run a
	// "core-sw1" at 10.0.0.1. Identity resolution that is not tenant-bounded
	// resolves one tenant's neighbour onto the other's device, and the leak renders
	// as a perfectly plausible node — which is what makes it dangerous.
	devices := []models.Device{
		{ID: "acme-core", Name: "core-sw1", Address: "10.0.0.1", TenantID: acme.Tenant.ID, Source: "test"},
		{ID: "acme-edge", Name: "edge-rtr1", Address: "10.0.0.2", TenantID: acme.Tenant.ID, Source: "test"},
		{ID: "globex-core", Name: "core-sw1", Address: "10.0.0.1", TenantID: globex.Tenant.ID, Source: "test"},
	}
	for _, d := range devices {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatalf("seed device %s: %v", d.ID, err)
		}
	}

	get := func(token, path string) topology.View {
		st, b := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, b)
		}
		var v topology.View
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("decode view: %v (%s)", err, b)
		}
		return v
	}
	nodeIDs := func(v topology.View) map[string]bool {
		out := map[string]bool{}
		for _, n := range v.Nodes {
			out[n.ID] = true
		}
		return out
	}

	// 1) OWN-ONLY LIST. Each tenant's canvas holds its own devices and nothing else.
	acmeView := get(alice, "/api/topology/view?mode=explore")
	got := nodeIDs(acmeView)
	if !got["acme-core"] || !got["acme-edge"] {
		t.Fatalf("acme is missing its own devices: %v", got)
	}
	if got["globex-core"] {
		t.Fatalf("CROSS-TENANT LEAK: acme's topology contains globex-core (%v)", got)
	}
	if acmeView.Scope.TenantID != acme.Tenant.ID {
		t.Fatalf("view scope = %q, want %q", acmeView.Scope.TenantID, acme.Tenant.ID)
	}

	globexView := get(bob, "/api/topology/view?mode=explore")
	got = nodeIDs(globexView)
	if !got["globex-core"] {
		t.Fatalf("globex is missing its own device: %v", got)
	}
	if got["acme-core"] || got["acme-edge"] {
		t.Fatalf("CROSS-TENANT LEAK: globex's topology contains acme devices (%v)", got)
	}

	// 2) `as_tenant` INTO ANOTHER ORG IS IGNORED — the selector only ever narrows.
	got = nodeIDs(get(bob, "/api/topology/view?mode=explore&as_tenant="+acme.Tenant.ID))
	if got["acme-core"] || got["acme-edge"] {
		t.Fatalf("as_tenant leak: bob?as_tenant=acme saw acme devices (%v)", got)
	}

	// 3) A CROSS-TENANT ENDPOINT IS NOT TRACEABLE. Naming another tenant's device
	//    as a path endpoint must neither resolve a path nor materialize the node —
	//    the id is not even an existence oracle.
	trace := get(alice, "/api/topology/view?mode=path_trace&src=acme-core&dst=globex-core")
	if nodeIDs(trace)["globex-core"] {
		t.Fatalf("path-trace leak: acme traced to globex-core and got the node back")
	}
	for _, hop := range trace.Path {
		if hop == "globex-core" {
			t.Fatalf("path-trace leak: globex-core appears as a hop on acme's path: %v", trace.Path)
		}
	}

	// 4) THE PLATFORM OWNER (cross-tenant) legitimately sees both.
	got = nodeIDs(get(admin, "/api/topology/view?mode=explore"))
	if !got["acme-core"] || !got["globex-core"] {
		t.Fatalf("platform owner did not see the whole estate: %v", got)
	}

	// 5) THE PLATFORM OWNER NARROWED to one tenant sees only that tenant — the
	//    override narrows for a cross-tenant principal too.
	got = nodeIDs(get(admin, "/api/topology/view?mode=explore&as_tenant="+globex.Tenant.ID))
	if !got["globex-core"] {
		t.Fatalf("narrowed owner lost the tenant's own device: %v", got)
	}
	if got["acme-core"] || got["acme-edge"] {
		t.Fatalf("narrowed owner leak: admin?as_tenant=globex saw acme devices (%v)", got)
	}

	// ── 6) A CROSS-TENANT CLOUD NODE IS NOT AN ENDPOINT (#130) ───────────────
	//
	// Path Trace now reaches into the cloud slice, which carries its OWN
	// default-closed gate (CLOUD_FIXTURE_TENANT) — a different tenancy rule from
	// the device fabric's. Naming a cloud node the caller may not read must
	// neither resolve a path nor return the node: the id stays a non-oracle.
	dir := t.TempDir()
	writeTopologyFixture(t, dir)
	t.Setenv("CLOUD_FIXTURES_DIR", dir)
	t.Setenv("CLOUD_FIXTURE_TENANT", acme.Tenant.ID)

	// Acme owns the fixtures: the cloud subnet IS on its canvas and IS offerable
	// as an endpoint — and because no seam adjacency has been discovered, the
	// answer is the honest NO-SEAM state, never a fabricated hop.
	acmeTrace := get(alice, "/api/topology/view?mode=path_trace&src=acme-core&dst=subnet-app")
	if !nodeIDs(acmeTrace)["subnet-app"] {
		t.Fatalf("the owner tenant must see its own cloud endpoint: %v", nodeIDs(acmeTrace))
	}
	if len(acmeTrace.Path) != 0 {
		t.Fatalf("no seam is discovered — no path may be invented, got %v", acmeTrace.Path)
	}
	if acmeTrace.PathState != topology.PathStateNoSeam {
		t.Fatalf("path_state = %q, want %q", acmeTrace.PathState, topology.PathStateNoSeam)
	}

	// Globex may not read the fixtures at all: no node, no path, and no state —
	// even the failure reason must not confirm that the id exists.
	globexTrace := get(bob, "/api/topology/view?mode=path_trace&src=globex-core&dst=subnet-app")
	if nodeIDs(globexTrace)["subnet-app"] {
		t.Fatalf("CROSS-TENANT LEAK: globex saw acme's cloud node")
	}
	if len(globexTrace.Path) != 0 || globexTrace.PathState != "" {
		t.Fatalf("cross-tenant cloud endpoint leaked a verdict: path=%v state=%q",
			globexTrace.Path, globexTrace.PathState)
	}
	// ...and `as_tenant` into the owner org does not widen the cloud gate either.
	widen := get(bob, "/api/topology/view?mode=path_trace&src=globex-core&dst=subnet-app&as_tenant="+acme.Tenant.ID)
	if nodeIDs(widen)["subnet-app"] || len(widen.Path) != 0 {
		t.Fatalf("as_tenant leak: bob?as_tenant=acme reached the cloud slice")
	}
}
