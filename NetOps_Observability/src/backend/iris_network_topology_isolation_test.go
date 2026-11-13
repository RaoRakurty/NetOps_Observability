// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_network_topology_isolation_test.go — CLAUDE.md §3a rule 5 for Iris's
// whole-network topology seam (get_network_topology). org_isolation_test.go is
// the template; ai_troubleshoot_deps_test.go is the seam-level sibling.
//
// The adversarial fixture is twoTenantOverlay: two tenants whose SD-WAN
// overlays use the SAME colour, the SAME system-ips and the SAME transport
// addresses, plus LLDP evidence in which each tenant's device names the
// other's as its neighbour. Every read below must stay inside the caller.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/alerts"
	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

func netTopoServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	snap, tenantOf := twoTenantOverlay(t)
	d := discovery.NewDiscoveryAggregator()
	i := 0
	for id, tn := range tenantOf {
		i++
		if err := d.Upsert(models.Device{ID: id, Name: id, Address: fmt.Sprintf("10.7.0.%d", i), TenantID: tn,
			Vendor: "cisco", Labels: map[string]string{"site": tn + "-site-" + id[len(id)-1:]}}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	s := &server{roles: roles, discovery: d}
	s.alerts = alerts.NewEngine("", nil)
	s.sdwanOverlay.Store(snap)
	s.topoLinks = func(context.Context) ([]collectors.LLDPNeighbor, error) {
		return []collectors.LLDPNeighbor{
			{LocalDevice: "acme-e0", LocalPort: "Gi1", RemSysName: "acme-e1", RemPort: "Gi2", Proto: "lldp"},
			// Cross-tenant evidence: each side names the other tenant's device.
			{LocalDevice: "acme-e2", LocalPort: "Gi3", RemSysName: "globex-e0", RemPort: "Gi4", Proto: "lldp"},
			{LocalDevice: "globex-e1", LocalPort: "Gi5", RemSysName: "acme-e0", RemPort: "Gi6", Proto: "cdp"},
		}, nil
	}
	return s
}

func netTopoOf(t *testing.T, s *server, claims jwtClaims) ai.NetworkTopology {
	t.Helper()
	deps := aiTSDeps(t, s, claims)
	if deps.NetworkTopology == nil {
		t.Fatal("the whole-network seam must be wired when there is an inventory")
	}
	nt, err := deps.NetworkTopology(context.Background(), aiTSPrincipal())
	if err != nil {
		t.Fatalf("NetworkTopology: %v", err)
	}
	return nt
}

func TestIrisNetworkTopologyIsTheCallersOwn(t *testing.T) {
	s := netTopoServer(t)
	for _, tc := range []struct {
		name   string
		claims jwtClaims
		own    string
		other  string
	}{
		{"acme sees acme only", acme(), "acme", "globex"},
		{"globex sees globex only", globex(), "globex", "acme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nt := netTopoOf(t, s, tc.claims)
			// What the caller's OWN device heard on the wire (an LLDP neighbour
			// name) is the caller's telemetry and stays, as an EXTERNAL
			// neighbour — exactly as the canvas draws it. Everything else
			// about the other tenant must be absent, so the external link ends
			// are set aside before the leak check.
			own := nt
			own.Links = nil
			for _, l := range nt.Links {
				if strings.Contains(l.A, tc.other) {
					t.Fatalf("TENANT LEAK: the other tenant's own telemetry reached %s: %+v", tc.own, l)
				}
				if strings.Contains(l.B, tc.other) && !l.External {
					t.Fatalf("TENANT LEAK: the other tenant's device resolved as a managed neighbour: %+v", l)
				}
				if !l.External {
					own.Links = append(own.Links, l)
				}
			}
			dump := fmt.Sprintf("%+v %+v", own, *own.Overlay)
			if strings.Contains(dump, tc.other) {
				t.Fatalf("TENANT LEAK: %s's topology names %s: %s", tc.own, tc.other, dump)
			}
			if !nt.Collected || nt.DevicesTotal != 3 {
				t.Fatalf("own devices: collected=%v total=%d", nt.Collected, nt.DevicesTotal)
			}
			if nt.Overlay == nil || nt.Overlay.Members != 3 || nt.Overlay.Pairs != 3 {
				t.Fatalf("own overlay (3 edges, full mesh) expected: %+v", nt.Overlay)
			}
			if nt.Overlay.Shape != "full_mesh" {
				t.Fatalf("shape = %s, want full_mesh", nt.Overlay.Shape)
			}
			for _, x := range nt.Overlay.Transports {
				if x.Members != 3 {
					t.Fatalf("transport membership must count only the caller's edges: %+v", x)
				}
			}
			// Management addresses never leave the seam.
			if strings.Contains(dump, "10.7.0.") {
				t.Fatalf("a management address reached the topology read: %s", dump)
			}
		})
	}
}

// The cross-tenant LLDP rows must not join two tenants into one managed
// adjacency, and the other tenant's own neighbour reports never appear.
func TestIrisNetworkTopologyAdjacencyStaysInsideTheTenant(t *testing.T) {
	s := netTopoServer(t)
	nt := netTopoOf(t, s, acme())
	for _, l := range nt.Links {
		if strings.Contains(l.A, "globex") || (strings.Contains(l.B, "globex") && !l.External) || l.Protocol == "cdp" {
			t.Fatalf("TENANT LEAK: an adjacency joins acme to globex: %+v", l)
		}
	}
	found := false
	for _, l := range nt.Links {
		if (l.A == "acme-e0" && l.B == "acme-e1") || (l.A == "acme-e1" && l.B == "acme-e0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the acme-internal LLDP adjacency must be reported: %+v", nt.Links)
	}
}

// as_tenant never widens a non-owner, and the platform owner's selector
// narrows into exactly that tenant.
func TestIrisNetworkTopologyAsTenant(t *testing.T) {
	s := netTopoServer(t)
	sneaky := acme()
	sneaky.ActingTenant = "globex"
	sn := netTopoOf(t, s, sneaky)
	for _, d := range sn.Devices {
		if strings.Contains(d.Name, "globex") {
			t.Fatalf("TENANT LEAK: as_tenant widened a non-owner into globex: %+v", sn.Devices)
		}
	}
	if sn.DevicesTotal != 3 || sn.Overlay == nil || sn.Overlay.Members != 3 {
		t.Fatalf("the selector must not break the caller's own scope: %+v", sn)
	}
	narrowed := superA()
	narrowed.ActingTenant = "globex"
	nt := netTopoOf(t, s, narrowed)
	for _, d := range nt.Devices {
		if strings.Contains(d.Name, "acme") {
			t.Fatalf("the owner narrowed into globex must see globex only: %+v", nt.Devices)
		}
	}
	if nt.DevicesTotal != 3 {
		t.Fatalf("narrowed device count = %d", nt.DevicesTotal)
	}
	// The platform owner's all-tenants view reaches both — and still never
	// pairs one tenant's edge with the other's (identical system-ips).
	all := netTopoOf(t, s, superA())
	if all.DevicesTotal != 6 || all.Overlay == nil || all.Overlay.Pairs != 6 {
		t.Fatalf("owner view: devices=%d overlay=%+v", all.DevicesTotal, all.Overlay)
	}
}

// Right after a restart the overlay snapshot is empty and discovery may hold
// nothing: the read says so instead of describing an empty network.
func TestIrisNetworkTopologyBeforeCollection(t *testing.T) {
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	s := &server{roles: roles, discovery: discovery.NewDiscoveryAggregator()}
	s.alerts = alerts.NewEngine("", nil)
	nt := netTopoOf(t, s, acme())
	if nt.Collected || nt.OverlayRead {
		t.Fatalf("nothing collected, overlay never read: %+v", nt)
	}
	res := ai.RenderNetworkTopology(nt)
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Text, "NOT YET COLLECTED") {
		t.Fatalf("the answer must say the topology is not collected: %+v", res.Items)
	}
}
