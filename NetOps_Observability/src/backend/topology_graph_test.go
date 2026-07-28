package main

import (
	"context"
	"encoding/json"
	"testing"

	"netops/backend/topology"
)

// TestTopologyStoreIsolation: the in-memory store scopes a Snapshot to the tenant.
func TestTopologyStoreIsolation(t *testing.T) {
	m := topology.NewMemStore()
	if err := m.ReplaceAll(context.Background(), topology.GraphRecords{Nodes: []topology.NodeRecord{
		{TenantID: "acme", ID: "a1"}, {TenantID: "globex", ID: "g1"},
	}}); err != nil {
		t.Fatal(err)
	}
	acme, _ := m.Snapshot(context.Background(), "acme", false)
	if len(acme.Nodes) != 1 || acme.Nodes[0].ID != "a1" {
		t.Errorf("scoped snapshot leaked: %+v", acme.Nodes)
	}
	all, _ := m.Snapshot(context.Background(), "", true)
	if len(all.Nodes) != 2 {
		t.Errorf("cross snapshot should see both, got %+v", all.Nodes)
	}
}

// TestTopologyGraphHTTPIsolation: GET /api/topology/graph returns only the
// caller's tenant's graph; the platform owner sees all.
func TestTopologyGraphHTTPIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.topology = newTopologyStore() // the minimal test server doesn't wire it
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

	// Seed the persistent graph directly (the reconciler doesn't run in tests).
	if err := s.topology.ReplaceAll(context.Background(), topology.GraphRecords{Nodes: []topology.NodeRecord{
		{TenantID: acme.Tenant.ID, ID: "acme-dev1", Label: "acme-dev1"},
		{TenantID: globex.Tenant.ID, ID: "globex-dev1", Label: "globex-dev1"},
	}}); err != nil {
		t.Fatal(err)
	}

	// A user scoped to acme sees ONLY acme's node.
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "alice", "password": "Passw0rd!2345", "role": "operator", "tenant_id": acme.Tenant.ID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	alice := login(t, srv, "alice", "Passw0rd!2345").Token
	st, b := do(t, srv, "GET", "/api/topology/graph", alice, nil)
	if st != 200 {
		t.Fatalf("graph: %d %s", st, b)
	}
	var gv topologyGraphResponse
	if err := json.Unmarshal(b, &gv); err != nil {
		t.Fatal(err)
	}
	if len(gv.Nodes) != 1 || gv.Nodes[0].ID != "acme-dev1" {
		t.Errorf("CROSS-TENANT LEAK: acme user saw %+v, want only acme-dev1", gv.Nodes)
	}

	// The platform owner sees both tenants' nodes.
	_, b2 := do(t, srv, "GET", "/api/topology/graph", admin, nil)
	var gv2 topologyGraphResponse
	_ = json.Unmarshal(b2, &gv2)
	if len(gv2.Nodes) < 2 {
		t.Errorf("platform owner should see all nodes, got %+v", gv2.Nodes)
	}
}
