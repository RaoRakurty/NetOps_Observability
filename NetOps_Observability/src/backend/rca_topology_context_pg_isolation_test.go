// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// rca_topology_context_pg_isolation_test.go — the RCA topology context's one
// Postgres-backed read (the persisted reconciled graph, migration 0012
// topology_nodes/topology_edges under FORCE-RLS) proved against a REAL
// Postgres as the non-superuser app role (CLAUDE.md §3a.4/§17): the reader
// returns only the object owner's graph rows, both for that tenant's own user
// (RLS-scoped read) and for the platform owner (cross-tenant read, narrowed by
// the reader to the object's owner). Gated on DATABASE_URL_TEST, like every
// root-package pg test; CI's pgintegration leg sets it.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/rca"
	"netops/backend/models"
	"netops/backend/topology"
)

func TestPgRCATopologyContextGraphReadIsOwnerScoped(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres topology-context isolation test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute) // a fresh database runs every migration first
	defer cancel()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	t.Cleanup(ps.DB().Close)
	store := topology.NewPGStore(ps.DB())

	// No neighbour tables in this test: the collector answers an empty set, so
	// every drawn edge below comes from the Postgres graph.
	fakeTopologyCollector(t, map[string]string{})
	t.Setenv("VICTORIA_URL", "http://127.0.0.1:1")

	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-core", Name: "acme-core", TenantID: acme.ID, LastSeen: now},
		{ID: "acme-edge", Name: "acme-edge", TenantID: acme.ID, LastSeen: now},
		{ID: "globex-core", Name: "globex-core", TenantID: globex.ID, LastSeen: now},
		{ID: "globex-edge", Name: "globex-edge", TenantID: globex.ID, LastSeen: now},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("upsert %s: %v", dev.ID, err)
		}
	}
	// ReplaceAll writes at platform scope with each row's own tenant_id, as the
	// reconciler does; RLS WITH CHECK validates each.
	if err := store.ReplaceAll(ctx, topology.GraphRecords{
		Nodes: []topology.NodeRecord{
			{TenantID: acme.ID, ID: "acme-core", Label: "acme-core", FirstSeen: now.Add(-time.Hour), LastSeen: now},
			{TenantID: acme.ID, ID: "acme-edge", Label: "acme-edge", FirstSeen: now.Add(-time.Hour), LastSeen: now},
			{TenantID: globex.ID, ID: "globex-core", Label: "globex-core", FirstSeen: now.Add(-time.Hour), LastSeen: now},
			{TenantID: globex.ID, ID: "globex-edge", Label: "globex-edge", FirstSeen: now.Add(-time.Hour), LastSeen: now},
		},
		Edges: []topology.EdgeRecord{
			{TenantID: acme.ID, ID: "e-acme", Source: "acme-core", Target: "acme-edge", Protocol: "lldp", Resolved: true, FirstSeen: now.Add(-time.Hour), LastSeen: now},
			{TenantID: globex.ID, ID: "e-globex", Source: "globex-core", Target: "globex-edge", Protocol: "lldp", Resolved: true, FirstSeen: now.Add(-time.Hour), LastSeen: now},
			// a globex row that names acme's device id — must never reach acme's read.
			{TenantID: globex.ID, ID: "e-globex-x", Source: "globex-core", Target: "acme-core", Protocol: "cdp", FirstSeen: now.Add(-time.Hour), LastSeen: now},
		},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	s := &server{discovery: d, tenants: ts, topology: store}

	graphEdges := func(claims jwtClaims, owner string, anchors ...string) map[string]bool {
		t.Helper()
		r, err := serverTopologySource{s: s, claims: claims}.ReadTopology(ctx, rca.TopologyQuery{OwnerTenant: owner, Devices: anchors, Now: now})
		if err != nil {
			t.Fatalf("ReadTopology: %v", err)
		}
		out := map[string]bool{}
		for _, l := range r.Links {
			out[l.ID] = true
		}
		var graphRead rca.TopologySourceRead
		for _, rd := range r.Reads {
			if rd.Kind == rca.TopoSrcGraph {
				graphRead = rd
			}
		}
		if graphRead.Status != rca.TopoReadOK {
			t.Fatalf("the Postgres graph must be READ (not unavailable): %+v", graphRead)
		}
		return out
	}

	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: acme.ID}
	got := graphEdges(acmeUser, acme.ID, "acme-core")
	if !got["e-acme"] || got["e-globex"] || got["e-globex-x"] {
		t.Fatalf("acme's own read (RLS-scoped) = %v, want only e-acme", got)
	}

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	got = graphEdges(owner, acme.ID, "acme-core")
	if !got["e-acme"] || got["e-globex"] || got["e-globex-x"] {
		t.Fatalf("the platform owner reading acme's object = %v, want only acme's rows", got)
	}
	got = graphEdges(owner, globex.ID, "globex-core")
	if !got["e-globex"] || got["e-acme"] {
		t.Fatalf("the platform owner reading globex's object = %v, want only globex's rows", got)
	}

	// The store itself (RLS) is the backstop: acme's scoped snapshot holds no
	// globex row even before the reader filters.
	snap, err := store.Snapshot(ctx, acme.ID, false)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for _, e := range snap.Edges {
		if e.TenantID != acme.ID {
			t.Fatalf("RLS LEAK: acme's snapshot carries %s of tenant %s", e.ID, e.TenantID)
		}
	}

	// The operator-visibility restriction reaches the graph read too.
	if _, err := ts.SetOperatorRestricted(globex.ID, true); err != nil {
		t.Fatalf("restrict globex: %v", err)
	}
	r, err := serverTopologySource{s: s, claims: owner}.ReadTopology(ctx, rca.TopologyQuery{OwnerTenant: globex.ID, Devices: []string{"globex-core"}, Now: now})
	if err != nil || len(r.Links)+len(r.Inventory) != 0 {
		t.Fatalf("a restricted tenant's graph must read as empty to the operator: %v %+v", err, r)
	}
}
