package cloud

import (
	"testing"
	"time"

	"netops/backend/topology"
)

func fixedNow() time.Time { return time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC) }

// A representative AWS egress topology (the aws-topology.json schema): one VPC,
// two subnets, an IGW node, and route edges to the IGW, an NVA (kind from the
// route, not the node row) and a blackholed route.
func sampleAWS() Topology {
	return Topology{
		Provider:  AWS,
		AccountID: "123456789012",
		Region:    "us-west-2",
		VPCs:      []TopoCIDR{{ID: "vpc-1", CIDR: "10.60.0.0/16", Name: "prod"}},
		Subnets: []TopoCIDR{
			{ID: "subnet-pub", CIDR: "10.60.1.0/24", Name: "public-a"},
			{ID: "subnet-app", CIDR: "10.60.10.0/24", Name: "app-a"},
		},
		Nodes: []TopoNode{
			{ID: "igw-1", Kind: "internet_gateway", Name: "prod-igw"},
			// The NVA is a plain EC2 instance in the node rows — its NVA-ness comes
			// from the route's ToKind. The projection must render it as an NVA.
			{ID: "i-nva", Kind: "instance", Name: "vpn-nat", SubnetID: "subnet-pub"},
		},
		Edges: []TopoEdge{
			{FromSubnet: "subnet-pub", To: "igw-1", ToKind: "internet_gateway",
				Destination: "0.0.0.0/0", State: "active", RouteTableName: "rt-public"},
			{FromSubnet: "subnet-app", To: "i-nva", ToKind: "nva",
				Destination: "0.0.0.0/0", State: "active", RouteTableName: "rt-app"},
			{FromSubnet: "subnet-app", To: "i-nva", ToKind: "nva",
				Destination: "192.168.9.0/24", State: "blackhole", RouteTableName: "rt-app"},
		},
	}
}

func TestBuildTopologyView_AWS_ShapeAndGrouping(t *testing.T) {
	v := BuildTopologyView([]Topology{sampleAWS()}, "t_acme", fixedNow())

	if v.LayoutType != "cloud_grouped" || v.Mode != "explore" {
		t.Fatalf("view meta wrong: layout=%q mode=%q", v.LayoutType, v.Mode)
	}
	if v.Scope.TenantID != "t_acme" {
		t.Fatalf("tenant not stamped: %q", v.Scope.TenantID)
	}

	// TWO LEVELS: a region container, and the VPC nested inside it carrying
	// every node in the VPC (subnets + gateways). The nesting is what lets the
	// renderer keep a region's VPCs inside one boundary instead of letting
	// blocks from different regions interleave.
	groupByID := map[string]topology.Group{}
	for _, g := range v.Groups {
		groupByID[g.ID] = g
	}
	region, ok := groupByID["region:aws:us-west-2"]
	if !ok || region.GroupType != "region" {
		t.Fatalf("expected an aws/us-west-2 region group: %+v", v.Groups)
	}
	if region.ParentID != "" {
		t.Fatalf("a region is top level, got parent %q", region.ParentID)
	}
	vpc, ok := groupByID["vpc-1"]
	if !ok || vpc.GroupType != "vpc" {
		t.Fatalf("expected a vpc-1 group: %+v", v.Groups)
	}
	if vpc.ParentID != region.ID {
		t.Fatalf("vpc must nest under its region, got parent %q", vpc.ParentID)
	}
	if want := 4; len(vpc.Children) != want { // 2 subnets + igw + nva
		t.Fatalf("group children = %d, want %d: %v", len(vpc.Children), want, vpc.Children)
	}

	byID := map[string]int{}
	for _, n := range v.Nodes {
		byID[n.ID]++
		if n.Kind != "cloud" {
			t.Fatalf("node %s kind = %q, want cloud", n.ID, n.Kind)
		}
		if n.Health != "unknown" {
			t.Fatalf("node %s health = %q, want unknown (honest, API-discovered)", n.ID, n.Health)
		}
		if n.Tags["provider"] != "aws" {
			t.Fatalf("node %s missing provider tag for the official mark: %v", n.ID, n.Tags)
		}
		if len(n.Evidence) == 0 {
			t.Fatalf("node %s has no evidence", n.ID)
		}
	}
	// The NVA must render with role=nva (route wins over the "instance" node row).
	var nva topologyNodeRole
	for _, n := range v.Nodes {
		if n.ID == "i-nva" {
			nva.role, nva.label, nva.group = n.Role, n.Label, n.GroupID
		}
	}
	if nva.role != "nva" {
		t.Fatalf("NVA role = %q, want nva (route ToKind must win over instance)", nva.role)
	}
	if nva.group != "vpc-1" {
		t.Fatalf("NVA group = %q, want vpc-1 (grouped via its from-subnet's VPC)", nva.group)
	}

	// Subnet node carries its CIDR on the label + tag.
	for _, n := range v.Nodes {
		if n.ID == "subnet-app" {
			if n.Tags["cidr"] != "10.60.10.0/24" {
				t.Fatalf("subnet CIDR tag = %q", n.Tags["cidr"])
			}
			if n.GroupID != "vpc-1" {
				t.Fatalf("subnet group = %q, want vpc-1", n.GroupID)
			}
		}
	}

	// Edges: 3 route facts. The destination CIDR is the label (source_port); the
	// blackhole route is DOWN, not a working egress.
	if len(v.Edges) != 3 {
		t.Fatalf("edges = %d, want 3", len(v.Edges))
	}
	var sawBlackhole bool
	for _, e := range v.Edges {
		if e.Relationship != "routed_adjacency" {
			t.Fatalf("edge %s relationship = %q", e.ID, e.Relationship)
		}
		if e.SourcePort == "" {
			t.Fatalf("edge %s has no destination CIDR label", e.ID)
		}
		if e.SourcePort == "192.168.9.0/24" {
			sawBlackhole = true
			if e.Status != "down" {
				t.Fatalf("blackhole route status = %q, want down", e.Status)
			}
		}
	}
	if !sawBlackhole {
		t.Fatalf("blackhole route edge missing")
	}
}

type topologyNodeRole struct{ role, label, group string }

// Azure VNet with several address prefixes: a subnet inside the SECOND prefix must
// still group under the VNet (multi-prefix containment), and the container reads
// "VNet ·" not "VPC ·".
func TestBuildTopologyView_Azure_MultiPrefixVNet(t *testing.T) {
	topo := Topology{
		Provider: Azure,
		Region:   "westeurope",
		VPCs: []TopoCIDR{
			{ID: "vnet-1", CIDR: "10.30.0.0/16", Name: "prod-weu"},
			{ID: "vnet-1", CIDR: "10.40.0.0/16", Name: "prod-weu"}, // second prefix, same id
		},
		Subnets: []TopoCIDR{
			{ID: "snet-app", CIDR: "10.40.1.0/24", Name: "app"}, // inside the 2nd prefix
		},
		Nodes: []TopoNode{{ID: "vgw-1", Kind: "vpn_gateway", Name: "prod-vgw"}},
		Edges: []TopoEdge{
			{FromSubnet: "snet-app", To: "vgw-1", ToKind: "vpn_gateway",
				Destination: "0.0.0.0/0", State: "active", RouteTableName: "udr-app"},
		},
	}
	v := BuildTopologyView([]Topology{topo}, "", fixedNow())

	// One region + one deduped VNet nested inside it (the VNet's two address
	// prefixes must not become two groups).
	var vnet *topology.Group
	regions := 0
	for i := range v.Groups {
		switch v.Groups[i].GroupType {
		case "vpc":
			if v.Groups[i].ID != "vnet-1" {
				t.Fatalf("unexpected vpc-type group %q — the multi-prefix VNet must dedupe", v.Groups[i].ID)
			}
			vnet = &v.Groups[i]
		case "region":
			regions++
		}
	}
	if vnet == nil || regions != 1 {
		t.Fatalf("expected one region + one deduped vnet group: %+v", v.Groups)
	}
	if vnet.ParentID != "region:azure:westeurope" {
		t.Fatalf("vnet must nest under its region, got %q", vnet.ParentID)
	}
	if got := vnet.Label; got[:4] != "VNet" {
		t.Fatalf("azure container label = %q, want VNet ·…", got)
	}
	var snetGroup string
	for _, n := range v.Nodes {
		if n.ID == "snet-app" {
			snetGroup = n.GroupID
		}
	}
	if snetGroup != "vnet-1" {
		t.Fatalf("subnet in 2nd prefix grouped as %q, want vnet-1", snetGroup)
	}
}

func TestBuildTopologyView_Empty(t *testing.T) {
	v := BuildTopologyView(nil, "t1", fixedNow())
	if len(v.Nodes) != 0 || len(v.Edges) != 0 || len(v.Groups) != 0 {
		t.Fatalf("empty input must yield an empty (but well-formed) view: %+v", v)
	}
	if v.ViewID == "" || v.Scope.TenantID != "t1" {
		t.Fatalf("empty view still needs id + tenant scope: %+v", v)
	}
}

// Live status must reach the nodes — and, more importantly, an UNMEASURED
// component must never render as healthy. "unknown is not green" is the whole
// point of the cloud status vocabulary.
func TestBuildTopologyViewWithStatus(t *testing.T) {
	lookup := func(id string) (NodeStatus, bool) {
		switch id {
		case "igw-1":
			return NodeStatus{Status: StatusDown, Reason: "no route to gateway", Metric: "tunnels 0"}, true
		case "i-nva":
			return NodeStatus{Status: StatusDegraded, Reason: "targets 2/3 healthy"}, true
		case "subnet-pub":
			return NodeStatus{Status: StatusNotMeasured}, true
		}
		return NodeStatus{}, false
	}
	v := BuildTopologyViewWithStatus([]Topology{sampleAWS()}, "t_acme", fixedNow(), lookup)

	byID := map[string]topology.Node{}
	for _, n := range v.Nodes {
		byID[n.ID] = n
	}
	if got := byID["igw-1"].Health; got != topology.HealthCritical {
		t.Errorf("down component health = %q, want critical", got)
	}
	if got := byID["igw-1"].Tags["status_reason"]; got != "no route to gateway" {
		t.Errorf("status reason lost: %q", got)
	}
	if got := byID["igw-1"].Tags["key_metric"]; got != "tunnels 0" {
		t.Errorf("key metric lost: %q", got)
	}
	if got := byID["i-nva"].Health; got != topology.HealthWarning {
		t.Errorf("degraded component health = %q, want warning", got)
	}
	// not_measured and unknown-to-the-lookup must BOTH stay unknown.
	if got := byID["subnet-pub"].Health; got != topology.HealthUnknown {
		t.Errorf("a NOT MEASURED component rendered as %q — unknown must never become green", got)
	}
	if got := byID["subnet-app"].Health; got != topology.HealthUnknown {
		t.Errorf("a component the lookup does not know rendered as %q, want unknown", got)
	}
}

// A nil lookup keeps the pure structural projection — the honest rendering of
// "we could not ask the inventory".
func TestBuildTopologyViewNilStatusIsNotHealthy(t *testing.T) {
	v := BuildTopologyViewWithStatus([]Topology{sampleAWS()}, "t_acme", fixedNow(), nil)
	for _, n := range v.Nodes {
		if n.Health != topology.HealthUnknown {
			t.Fatalf("node %s = %q with no status source; want unknown", n.ID, n.Health)
		}
	}
}
