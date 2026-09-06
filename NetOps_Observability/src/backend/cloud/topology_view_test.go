package cloud

import (
	"bytes"
	"encoding/json"
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

// A REQUIRED array in the wire contract must never serialize as `null`.
//
// This is the defect that blanked the Cloud tab: a REGION group parents VPC
// groups through parent_id and holds no member nodes of its own, so its children
// accumulator stayed nil and encoding/json wrote `"children":null`. The view
// contract declares `children` a required array and every consumer iterates it,
// so the SPA threw `g.children is not iterable` on the first region group and
// React unmounted the entire page — an empty screen, no error, nothing in the
// API log to suggest the payload was at fault (it was a 200 with 15 nodes).
//
// Asserted on the SERIALIZED bytes on purpose: `len(g.Children) == 0` is true for
// both nil and `[]string{}`, so only the JSON tells the two apart.
func TestBuildTopologyViewGroupChildrenNeverNull(t *testing.T) {
	v := BuildTopologyView([]Topology{sampleAWS()}, "t_acme", fixedNow())

	sawRegion := false
	for _, g := range v.Groups {
		if g.GroupType == "region" {
			sawRegion = true
		}
		if g.Children == nil {
			t.Errorf("group %q (%s) has nil Children — the contract requires an array", g.ID, g.GroupType)
		}
	}
	if !sawRegion {
		t.Fatal("fixture produced no region group — this test no longer covers the nil-children case")
	}

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(b, []byte(`"children":null`)) {
		t.Errorf(`serialized view contains "children":null — the Cloud tab crashes on it:\n%s`, b)
	}
}

// #131(d): the unified topology canvas classifies and re-groups cloud entities by
// FACT — the provider/region/vpc fields the discovery actually returned — and
// explicitly NOT by widening the frontend's hostname regex, which is the one
// genuinely weak piece of that classifier and must not spread to cloud. So every
// projected node carries its network context on the node itself, not only on the
// group that contains it.
func TestBuildTopologyViewStampsNetworkContextFactsOnNodes(t *testing.T) {
	v := BuildTopologyView([]Topology{sampleAWS()}, "t_acme", fixedNow())

	byID := map[string]topology.Node{}
	for _, n := range v.Nodes {
		byID[n.ID] = n
	}
	if len(byID) == 0 {
		t.Fatal("projection produced no nodes")
	}

	for id, n := range byID {
		if n.Tags["provider"] != "aws" {
			t.Fatalf("node %s: provider tag = %q, want aws", id, n.Tags["provider"])
		}
		if n.Tags["region"] != "us-west-2" {
			t.Fatalf("node %s: region tag = %q, want us-west-2 — the canvas groups by this fact", id, n.Tags["region"])
		}
	}

	// A resource that sits in a VPC names it; the VPC tag agrees with the group
	// membership the same projection emitted, so the two can never drift.
	for _, id := range []string{"subnet-pub", "subnet-app", "i-nva"} {
		n, ok := byID[id]
		if !ok {
			t.Fatalf("missing node %s", id)
		}
		if n.Tags["vpc"] != "vpc-1" {
			t.Fatalf("node %s: vpc tag = %q, want vpc-1", id, n.Tags["vpc"])
		}
		if n.GroupID != n.Tags["vpc"] {
			t.Fatalf("node %s: group_id %q disagrees with the vpc tag %q", id, n.GroupID, n.Tags["vpc"])
		}
	}

	// A gateway with no resolvable VPC must not invent one — absence stays absence.
	if igw := byID["igw-1"]; igw.GroupID == "" && igw.Tags["vpc"] != "" {
		t.Fatalf("igw-1 has no group but claims vpc %q", igw.Tags["vpc"])
	}
}
