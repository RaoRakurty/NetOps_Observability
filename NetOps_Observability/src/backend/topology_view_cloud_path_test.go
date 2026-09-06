package backend

// topology_view_cloud_path_test.go — #130b, the two halves of the honesty claim,
// proved end to end through the real router.
//
// The on-prem↔cloud seam is DISCOVERED data: a cloud VPN/DX row naming the
// address its tunnel terminates on, joined to the managed device that owns that
// address. Two fixtures, deliberately identical apart from that one fact:
//
//	WITH a peer address    → the trace crosses the seam and returns a computed path
//	WITHOUT a peer address → the endpoint is still offerable, and the answer is the
//	                         distinct no-seam state; no hop is invented to bridge it
//
// If the second case ever starts returning a path, something has begun guessing
// the adjacency — which is the token-overlap mistake the frozen path contract
// exists to prevent.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"netops/backend/alerts"
	"netops/backend/cloud"
	"netops/backend/models"
	"netops/backend/topology"
)

func TestPathTraceCrossesTheDiscoveredCloudSeam(t *testing.T) {
	for _, tc := range []struct {
		name    string
		peerIP  string // "" = the provider named no on-prem peer
		wantHop bool
	}{
		{name: "a discovered peer address joins the seam", peerIP: "10.0.0.2", wantHop: true},
		{name: "no peer address discovered", peerIP: "", wantHop: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, s := newTestServerState(t)
			s.alerts = alerts.NewEngine("", nil)
			s.cloud = newCloudStore()
			admin := login(t, srv, "admin", "Passw0rd!2345").Token

			st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
				"org_name": "Acme Corp", "tenant_name": "Acme Prod", "tenant_slug": "acme-prod",
			})
			if st != 201 {
				t.Fatalf("onboard: %d %s", st, b)
			}
			var org onboardResponse
			if err := json.Unmarshal(b, &org); err != nil {
				t.Fatal(err)
			}
			if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
				"username": "alice", "password": "Passw0rd!2345", "role": "operator", "tenant_id": org.Tenant.ID,
			}); st != 201 {
				t.Fatalf("create user: %d %s", st, b)
			}
			alice := login(t, srv, "alice", "Passw0rd!2345").Token

			// The on-prem fabric: a WAN edge at 10.0.0.2 — the address the cloud
			// VPN terminates on in the WITH case. The trace starts AT the edge, so
			// the fabric half needs no discovered adjacency of its own; what is
			// under test is the seam, not LLDP.
			for _, d := range []models.Device{
				{ID: "acme-edge", Name: "wan-edge1", Address: "10.0.0.2", TenantID: org.Tenant.ID, Source: "test"},
			} {
				if err := s.discovery.Upsert(d); err != nil {
					t.Fatalf("seed device %s: %v", d.ID, err)
				}
			}
			dir := t.TempDir()
			writeVPNTopologyFixture(t, dir)
			t.Setenv("CLOUD_FIXTURES_DIR", dir)
			t.Setenv("CLOUD_FIXTURE_TENANT", org.Tenant.ID)

			vpn := cloud.CloudResource{
				Provider: cloud.AWS, Region: "us-west-2",
				ResourceID: "vpn-1", ResourceType: "ec2:vpnconnection", ResourceName: "vpn-1",
				Status: cloud.StatusHealthy, AttachedVpcIDs: []string{"vpc-1"},
				Attrs: map[string]string{},
			}
			if tc.peerIP != "" {
				vpn.Attrs["peer_ip"] = tc.peerIP
			} else {
				// The AWS row still carries provider ids — none of which is an
				// address, so none of which may become an adjacency.
				vpn.Attrs["cgw_id"] = "cgw-0abc"
			}
			if err := s.cloud.ReplaceInventory(context.Background(), org.Tenant.ID, []cloud.CloudResource{vpn}, nil); err != nil {
				t.Fatalf("seed inventory: %v", err)
			}

			st, b = do(t, srv, "GET", "/api/topology/view?mode=path_trace&src=acme-edge&dst=subnet-app", alice, nil)
			if st != 200 {
				t.Fatalf("trace: %d %s", st, b)
			}
			var v topology.View
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatalf("decode: %v (%s)", err, b)
			}

			// EITHER WAY the cloud endpoint is on the canvas — the picker offers a
			// real node and the backend answers honestly, rather than hiding it.
			var sawSubnet bool
			for _, n := range v.Nodes {
				if n.ID == "subnet-app" {
					sawSubnet = true
				}
			}
			if !sawSubnet {
				t.Fatal("the cloud endpoint must be on the canvas in both cases")
			}

			if tc.wantHop {
				want := []string{"acme-edge", "vpn-1", "subnet-app"}
				if len(v.Path) != len(want) {
					t.Fatalf("the discovered seam was not crossed: %v, want %v", v.Path, want)
				}
				for i, h := range want {
					if v.Path[i] != h {
						t.Fatalf("hop %d = %q, want %q (%v)", i, v.Path[i], h, v.Path)
					}
				}
				// The frozen contract's provenance survives the crossing.
				if v.PathSource != topology.PathComputed {
					t.Fatalf("path_source = %q, want %q — a computed path is never 'traced'", v.PathSource, topology.PathComputed)
				}
				if v.PathState != "" {
					t.Fatalf("a resolved path must carry no failure state, got %q", v.PathState)
				}
				return
			}

			if len(v.Path) != 0 {
				t.Fatalf("no seam was discovered — a hop was invented: %v", v.Path)
			}
			if v.PathState != topology.PathStateNoSeam {
				t.Fatalf("path_state = %q, want the distinct %q", v.PathState, topology.PathStateNoSeam)
			}
		})
	}
}

// writeVPNTopologyFixture — one VPC whose subnet's default route points at a VPN
// gateway, so both the subnet and `vpn-1` are nodes on the projected view.
func writeVPNTopologyFixture(t *testing.T, dir string) {
	t.Helper()
	fixture := map[string]any{
		"provider": "aws", "account_id": "123456789012", "region": "us-west-2",
		"vpcs":    []map[string]any{{"id": "vpc-1", "cidr": "10.60.0.0/16", "name": "prod"}},
		"subnets": []map[string]any{{"id": "subnet-app", "cidr": "10.60.10.0/24", "name": "app-a"}},
		"edges": []map[string]any{{
			"from_subnet": "subnet-app", "to": "vpn-1", "to_kind": "vpn_gateway",
			"destination": "10.0.0.0/8", "state": "active", "route_table_name": "rt-app",
		}},
	}
	b, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aws-topology.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
