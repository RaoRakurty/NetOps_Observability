package cloud

// seam_links_test.go — #131c (lateral seam links) and #130b (the on-prem seam).
//
// The rules under test are the ones that keep a seam link from being a lie:
// it is drawn only between devices that are ON the canvas, it is an OBSERVED
// relationship (never the inferred class the route edges use), it never joins
// two tenants, and where the provider named no on-prem peer there is no edge at
// all rather than a plausible one.

import (
	"testing"
	"time"

	"netops/backend/topology"
)

var seamNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// twoVPCTopology: two VPCs, a subnet each, and one TGW attachment per VPC as the
// route target — so both attachment devices exist as NODES on the projected view.
func twoVPCTopology() []Topology {
	return []Topology{{
		Provider: AWS, AccountID: "123456789012", Region: "us-west-2",
		VPCs: []TopoCIDR{
			{ID: "vpc-a", CIDR: "10.10.0.0/16", Name: "prod"},
			{ID: "vpc-b", CIDR: "10.20.0.0/16", Name: "shared"},
		},
		Subnets: []TopoCIDR{
			{ID: "subnet-a", CIDR: "10.10.1.0/24", Name: "app-a"},
			{ID: "subnet-b", CIDR: "10.20.1.0/24", Name: "app-b"},
		},
		Edges: []TopoEdge{
			{FromSubnet: "subnet-a", To: "tgw-attach-a", ToKind: "transit_gateway",
				Destination: "10.20.0.0/16", State: "active", RouteTableName: "rt-a"},
			{FromSubnet: "subnet-b", To: "tgw-attach-b", ToKind: "transit_gateway",
				Destination: "10.10.0.0/16", State: "active", RouteTableName: "rt-b"},
		},
	}}
}

// attachment is one TGW attachment row as the inventory writes it: a seam-family
// resource declaring the VPCs the link joins.
func attachment(tenant, id string, status string) CloudResource {
	return CloudResource{
		TenantID: tenant, Provider: AWS, Region: "us-west-2",
		ResourceID: id, ResourceType: "ec2:tgw-attachment", ResourceName: id,
		Status:         status,
		AttachedVpcIDs: []string{"vpc-a", "vpc-b"},
	}
}

func seamEdges(edges []topology.Edge) []topology.Edge {
	out := []topology.Edge{}
	for _, e := range edges {
		if e.Tags["seam_group_id"] != "" {
			out = append(out, e)
		}
	}
	return out
}

func TestSeamLinksOneEdgePerAttachmentPair(t *testing.T) {
	view := BuildTopologyViewWithInventory(twoVPCTopology(), "acme", seamNow, []CloudResource{
		attachment("acme", "tgw-attach-a", StatusHealthy),
		attachment("acme", "tgw-attach-b", StatusHealthy),
	})
	got := seamEdges(view.Edges)
	if len(got) != 1 {
		t.Fatalf("want exactly one seam edge for one attachment pair, got %d: %+v", len(got), got)
	}
	e := got[0]
	if e.Source != "tgw-attach-a" || e.Target != "tgw-attach-b" {
		t.Fatalf("seam edge joins the wrong devices: %s → %s", e.Source, e.Target)
	}
	// OBSERVED, not inferred: the route edges in the same view are the inferred
	// control-plane class, and the two must never be the same claim.
	if e.Relationship != topology.RelConnectedTo {
		t.Fatalf("seam relationship = %q, want the observed class %q", e.Relationship, topology.RelConnectedTo)
	}
	if e.Confidence <= 0.7 {
		t.Fatalf("an inventory fact must outrank a route inference (0.7); got %v", e.Confidence)
	}
	if e.Tags["seam_group_id"] != seamGroupID(attachment("acme", "tgw-attach-a", StatusHealthy)) {
		t.Fatalf("seam edge does not carry the rollup's seam id: %v", e.Tags)
	}
	if len(e.Evidence) == 0 || e.Evidence[0].Detail == "" {
		t.Fatalf("no edge without evidence: %+v", e.Evidence)
	}
	if e.Status != topology.StatusUp {
		t.Fatalf("two healthy endpoints → up, got %q", e.Status)
	}
}

func TestSeamLinkStatusIsWorstOfAndNeverInvented(t *testing.T) {
	for _, tc := range []struct {
		name, a, b, want string
	}{
		{"one down", StatusHealthy, StatusDown, topology.StatusDown},
		{"one degraded", StatusHealthy, StatusDegraded, topology.StatusDegraded},
		{"unmeasured is not green", StatusHealthy, "", topology.StatusUp},
		{"nothing measured", "", "", topology.StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := BuildTopologyViewWithInventory(twoVPCTopology(), "acme", seamNow, []CloudResource{
				attachment("acme", "tgw-attach-a", tc.a),
				attachment("acme", "tgw-attach-b", tc.b),
			})
			got := seamEdges(view.Edges)
			if len(got) != 1 {
				t.Fatalf("want one seam edge, got %d", len(got))
			}
			if got[0].Status != tc.want {
				t.Fatalf("status = %q, want %q", got[0].Status, tc.want)
			}
		})
	}
}

func TestSeamLinksNeverCrossTenants(t *testing.T) {
	// A cross-tenant principal reads BOTH tenants' inventories. The two
	// attachments declare the same VPC ids — which is exactly how a naive
	// grouping would join them — and must still never be drawn as one link.
	view := BuildTopologyViewWithInventory(twoVPCTopology(), "", seamNow, []CloudResource{
		attachment("acme", "tgw-attach-a", StatusHealthy),
		attachment("globex", "tgw-attach-b", StatusHealthy),
	})
	if got := seamEdges(view.Edges); len(got) != 0 {
		t.Fatalf("CROSS-TENANT SEAM LEAK: %+v", got)
	}
}

func TestSeamLinkNeedsBothDevicesOnTheCanvas(t *testing.T) {
	// tgw-attach-c was never discovered by the egress topology, so it is not a
	// node. No placeholder, no edge — "no seam link discovered" is honest.
	view := BuildTopologyViewWithInventory(twoVPCTopology(), "acme", seamNow, []CloudResource{
		attachment("acme", "tgw-attach-a", StatusHealthy),
		attachment("acme", "tgw-attach-c", StatusHealthy),
	})
	if got := seamEdges(view.Edges); len(got) != 0 {
		t.Fatalf("drew a seam to a node that is not on the canvas: %+v", got)
	}
	for _, n := range view.Nodes {
		if n.ID == "tgw-attach-c" {
			t.Fatal("materialized a node for an undiscovered seam device")
		}
	}
}

func TestSeamLinkNotDrawnForAnUndeclaredAttachment(t *testing.T) {
	// Two seam devices that declare NO attachments are two separate seams
	// (seamGroupID falls back to the resource id) — we never merge two
	// undeclared links by guesswork.
	bare := func(id string) CloudResource {
		return CloudResource{TenantID: "acme", Provider: AWS, ResourceID: id,
			ResourceType: "ec2:tgw-attachment", Status: StatusHealthy}
	}
	view := BuildTopologyViewWithInventory(twoVPCTopology(), "acme", seamNow,
		[]CloudResource{bare("tgw-attach-a"), bare("tgw-attach-b")})
	if got := seamEdges(view.Edges); len(got) != 0 {
		t.Fatalf("guessed a seam from two undeclared endpoints: %+v", got)
	}
}

func TestSeamLinksAreDeterministic(t *testing.T) {
	inv := []CloudResource{
		attachment("acme", "tgw-attach-b", StatusHealthy),
		attachment("acme", "tgw-attach-a", StatusHealthy),
	}
	a := BuildSeamLinks(BuildTopologyView(twoVPCTopology(), "acme", seamNow).Nodes, inv, seamNow)
	b := BuildSeamLinks(BuildTopologyView(twoVPCTopology(), "acme", seamNow).Nodes, inv, seamNow)
	if len(a) != 1 || len(b) != 1 || a[0].ID != b[0].ID || a[0].Source != b[0].Source {
		t.Fatalf("seam links are not deterministic: %+v vs %+v", a, b)
	}
}

func TestSeamLinksBoundThePairwiseExpansion(t *testing.T) {
	// A pathological inventory (many devices declaring one attachment set) must
	// not draw an unbounded number of curves. maxSeamLinkDevices caps it.
	topo := twoVPCTopology()
	inv := []CloudResource{}
	for i := 0; i < 20; i++ {
		id := string(rune('a'+i)) + "-attach"
		topo[0].Edges = append(topo[0].Edges, TopoEdge{
			FromSubnet: "subnet-a", To: id, ToKind: "transit_gateway",
			Destination: "10.20.0.0/16", State: "active", RouteTableName: "rt-a",
		})
		inv = append(inv, attachment("acme", id, StatusHealthy))
	}
	got := seamEdges(BuildTopologyViewWithInventory(topo, "acme", seamNow, inv).Edges)
	want := maxSeamLinkDevices * (maxSeamLinkDevices - 1) / 2
	if len(got) != want {
		t.Fatalf("pairwise expansion unbounded: %d edges, want the capped %d", len(got), want)
	}
}

// ── the on-prem seam (#130b) ────────────────────────────────────────────────

func vpnResource(tenant, id, peerAttr, peerIP string) CloudResource {
	r := CloudResource{
		TenantID: tenant, Provider: AWS, Region: "us-west-2",
		ResourceID: id, ResourceType: "ec2:vpnconnection", ResourceName: id,
		Status: StatusHealthy, AttachedVpcIDs: []string{"vpc-a"},
	}
	if peerAttr != "" {
		r.Attrs = map[string]string{peerAttr: peerIP}
	}
	return r
}

func vpnTopology() []Topology {
	return []Topology{{
		Provider: AWS, AccountID: "1", Region: "us-west-2",
		VPCs:    []TopoCIDR{{ID: "vpc-a", CIDR: "10.10.0.0/16", Name: "prod"}},
		Subnets: []TopoCIDR{{ID: "subnet-a", CIDR: "10.10.1.0/24", Name: "app-a"}},
		Edges: []TopoEdge{{FromSubnet: "subnet-a", To: "vpn-1", ToKind: "vpn_gateway",
			Destination: "192.168.0.0/16", State: "active", RouteTableName: "rt-a"}},
	}}
}

func fixedResolver(addr, dev, tenant string) DeviceResolver {
	return func(resourceTenant, a string) (string, bool) {
		if a != addr {
			return "", false
		}
		if resourceTenant != "" && tenant != "" && resourceTenant != tenant {
			return "", false
		}
		return dev, true
	}
}

func TestOnPremSeamEdgeIsDiscoveredFromThePeerAddress(t *testing.T) {
	for _, attr := range onPremPeerAttrs {
		t.Run(attr, func(t *testing.T) {
			view := BuildTopologyView(vpnTopology(), "acme", seamNow)
			inv := []CloudResource{vpnResource("acme", "vpn-1", attr, "203.0.113.4")}
			got := BuildOnPremSeamEdges(view.Nodes, inv, fixedResolver("203.0.113.4", "wan-edge-1", "acme"), seamNow)
			if len(got) != 1 {
				t.Fatalf("want one on-prem seam edge, got %d", len(got))
			}
			if got[0].Source != "vpn-1" || got[0].Target != "wan-edge-1" {
				t.Fatalf("wrong endpoints: %s → %s", got[0].Source, got[0].Target)
			}
			if got[0].Relationship != topology.RelConnectedTo {
				t.Fatalf("relationship = %q, want the observed class", got[0].Relationship)
			}
			if got[0].Tags["peer_address"] != "203.0.113.4" {
				t.Fatalf("the discovered fact must travel on the edge: %v", got[0].Tags)
			}
		})
	}
}

func TestOnPremSeamEdgeAbsentWhenNoPeerWasDiscovered(t *testing.T) {
	view := BuildTopologyView(vpnTopology(), "acme", seamNow)
	// The AWS VPN row carries cgw_id — an AWS-side identifier, NOT an address we
	// could ever resolve to a device. Nothing here may become an edge.
	inv := []CloudResource{{
		TenantID: "acme", Provider: AWS, ResourceID: "vpn-1", ResourceType: "ec2:vpnconnection",
		Status: StatusHealthy, AttachedVpcIDs: []string{"vpc-a"},
		Attrs: map[string]string{"cgw_id": "cgw-0abc", "vgw_id": "vgw-0def"},
	}}
	if got := BuildOnPremSeamEdges(view.Nodes, inv, fixedResolver("203.0.113.4", "wan-edge-1", "acme"), seamNow); len(got) != 0 {
		t.Fatalf("invented an on-prem seam from an id that is not an address: %+v", got)
	}
}

func TestOnPremSeamEdgeNeverCrossesTenants(t *testing.T) {
	view := BuildTopologyView(vpnTopology(), "", seamNow)
	inv := []CloudResource{vpnResource("globex", "vpn-1", "peer_ip", "203.0.113.4")}
	if got := BuildOnPremSeamEdges(view.Nodes, inv, fixedResolver("203.0.113.4", "acme-wan-edge", "acme"), seamNow); len(got) != 0 {
		t.Fatalf("CROSS-TENANT SEAM LEAK: globex's VPN wired to an acme device: %+v", got)
	}
}

func TestOnPremSeamEdgeNeedsAResolver(t *testing.T) {
	view := BuildTopologyView(vpnTopology(), "acme", seamNow)
	inv := []CloudResource{vpnResource("acme", "vpn-1", "peer_ip", "203.0.113.4")}
	if got := BuildOnPremSeamEdges(view.Nodes, inv, nil, seamNow); len(got) != 0 {
		t.Fatalf("a nil resolver must produce nothing, got %+v", got)
	}
}
