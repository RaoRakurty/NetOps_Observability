package backend

// topology_reconcile_test.go — §3a regression guard for the reconciler's
// neighbour resolution (audit S3): the resolution universe must be partitioned
// PER TENANT. A neighbour advertised to tenant A whose hostname/mgmt-IP
// collides with tenant B's device must resolve to an ext: boundary node —
// never to B's device id.

import (
	"strings"
	"testing"

	"netops/backend/collectors"
	"netops/backend/models"
)

func TestObserveTopoLinksResolvesPerTenant(t *testing.T) {
	devs := []models.Device{
		{ID: "dev-a1", Name: "edge-1", Address: "10.1.0.1", TenantID: "acme"},
		{ID: "dev-a2", Name: "core-a", Address: "10.1.0.2", TenantID: "acme"},
		// Tenant B owns a device whose NAME and ADDRESS collide with what
		// tenant A's device sees as a neighbour.
		{ID: "dev-b1", Name: "shared-core", Address: "10.9.0.9", TenantID: "globex"},
	}
	neighbors := []collectors.LLDPNeighbor{
		// A's edge sees its own core: must resolve WITHIN acme.
		{LocalDevice: "dev-a1", LocalPort: "Eth1", RemSysName: "core-a", RemPort: "Eth9", Proto: "lldp"},
		// A's edge sees a neighbour named exactly like GLOBEX's device: must
		// NOT resolve to dev-b1 (the S3 leak) — it stays an unmanaged boundary.
		{LocalDevice: "dev-a1", LocalPort: "Eth2", RemSysName: "shared-core", RemChassis: "10.9.0.9", RemPort: "Eth3", Proto: "lldp"},
		// GLOBEX's own view of its device remains resolvable for globex.
		{LocalDevice: "dev-b1", LocalPort: "Eth7", RemSysName: "shared-core", RemPort: "Eth8", Proto: "lldp"},
	}

	links := observeTopoLinks(devs, neighbors, nil)

	var sawOwn, sawBoundary bool
	for _, l := range links {
		if l.Source == "dev-a1" && l.Target == "dev-a2" {
			sawOwn = true
		}
		if l.Source == "dev-a1" && l.Target == "dev-b1" {
			t.Fatalf("TENANT LEAK (S3): tenant A's neighbour resolved to tenant B's device id: %+v", l)
		}
		if l.Source == "dev-a1" && strings.Contains(strings.ToLower(l.Target), "shared-core") && l.Target != "dev-b1" {
			sawBoundary = true // ext:/unresolved boundary node — the honest rendering
		}
	}
	if !sawOwn {
		t.Fatalf("same-tenant neighbour must still resolve: %+v", links)
	}
	if !sawBoundary {
		t.Fatalf("cross-tenant-colliding neighbour must survive as an unmanaged boundary, not vanish: %+v", links)
	}
}
