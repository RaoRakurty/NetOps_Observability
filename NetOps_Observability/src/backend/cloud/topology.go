// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// topology.go — the discovered CLOUD EGRESS TOPOLOGY (AWS route tables / Azure
// UDRs), written by deployment/docker/cloud-ingest/discover.py and
// scripts/cloud-discover-azure.py into <fixtures>/aws-topology.json and
// <fixtures>/azure-topology.json.
//
// This is CONTROL-PLANE, INFERRED data (service-path-graph-contract §3 rank 6 /
// §4): "the app subnet's 0.0.0.0/0 points at the NVA's ENI" is a strong, useful
// explanation of an observed hop — and it is NOT permission to assert that traffic
// took it. The loader therefore returns it as RouteRelation material only; nothing
// here can create an authoritative edge. It also carries the VPC/VNet + subnet
// CIDRs, which give every cloud address its NETWORK CONTEXT (§2.1: an address is
// meaningless without one).

// TopoNode is a resource the topology names (instance / NVA / gateway).
type TopoNode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	SubnetID  string `json:"subnet_id"`
	PrivateIP string `json:"private_ip"`
	App       string `json:"app"`
}

// TopoEdge is one ROUTE: from a subnet, destination prefix, to a next hop of a
// known kind (internet_gateway | nat_gateway | nva | vpc_endpoint | vpn_gateway).
type TopoEdge struct {
	FromSubnet     string `json:"from_subnet"`
	FromSubnetName string `json:"from_subnet_name"`
	To             string `json:"to"`
	ToKind         string `json:"to_kind"`
	Destination    string `json:"destination"`
	// State is the route's lifecycle from the provider: "active" (working) vs
	// "blackhole" (target gone — traffic to this CIDR is silently discarded). A
	// blackhole is a live, actionable fault, so we carry it and render its edge
	// as down rather than as a working egress. "" is treated as active.
	State          string `json:"state,omitempty"`
	ViaRouteTable  string `json:"via_route_table"`
	RouteTableName string `json:"route_table_name"`
}

// TopoCIDR is a VPC/VNet or subnet with its prefix.
type TopoCIDR struct {
	ID   string `json:"id"`
	CIDR string `json:"cidr"`
	Name string `json:"name"`
}

// Topology is one provider's discovered egress topology.
type Topology struct {
	Provider  Provider   `json:"provider"`
	AccountID string     `json:"account_id"`
	Region    string     `json:"region"`
	VPCs      []TopoCIDR `json:"vpcs"`
	Subnets   []TopoCIDR `json:"subnets"`
	Nodes     []TopoNode `json:"nodes"`
	Edges     []TopoEdge `json:"edges"`
}

// LoadTopologies reads *-topology.json from dir. A missing dir is not an error —
// the cloud topology is optional enrichment, and its absence must degrade to
// "no inferred support", never to a failure.
func LoadTopologies(dir string) ([]Topology, error) {
	return LoadTopologiesLayered(dir, "")
}

// LoadTopologiesLayered reads fixtureDir then runtimeDir; a runtime file
// shadows the same-named fixture (the static-fixture/live-runtime split — the
// live poller's snapshot wins over the tracked demo fixture when both exist).
// Missing dirs degrade silently, same as LoadTopologies.
func LoadTopologiesLayered(fixtureDir, runtimeDir string) ([]Topology, error) {
	byName := map[string]Topology{}
	var order []string
	for _, dir := range []string{fixtureDir, runtimeDir} {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "-topology.json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- operator-configured fixtures dir
			if err != nil {
				return nil, err
			}
			var t Topology
			if err := json.Unmarshal(raw, &t); err != nil {
				return nil, fmt.Errorf("topology %s: %w", e.Name(), err)
			}
			if !ValidProvider(t.Provider) {
				continue // unsupported provider: skip, never crash
			}
			if _, seen := byName[e.Name()]; !seen {
				order = append(order, e.Name())
			}
			byName[e.Name()] = t // runtime layer shadows fixture
		}
	}
	out := make([]Topology, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out, nil
}

// NetworkContextOf returns the network context (VPC/VNet id) an address belongs to,
// or "" when no discovered CIDR contains it. This is what makes two tenants'
// identical 10.60.10.10 addresses two DIFFERENT endpoints rather than one.
func (t Topology) NetworkContextOf(addr string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	for _, v := range t.VPCs {
		p, err := netip.ParsePrefix(v.CIDR)
		if err != nil {
			continue
		}
		if p.Contains(ip) {
			return v.ID
		}
	}
	return ""
}

// SubnetOf returns the subnet id containing addr ("" when unknown).
func (t Topology) SubnetOf(addr string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	for _, s := range t.Subnets {
		p, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			continue
		}
		if p.Contains(ip) {
			return s.ID
		}
	}
	return ""
}

// NodeKindOf returns the topology's declared kind for a resource id or private IP
// ("nva", "instance", …). It is a LABEL for a node whose identity was already
// established by an observed rank-1/2/3 fact — never an identity of its own.
func (t Topology) NodeKindOf(ref string) string {
	r := strings.ToLower(strings.TrimSpace(ref))
	if r == "" {
		return ""
	}
	// A route's next-hop role (nva / nat_gateway / …) is the SPECIFIC network
	// function the control plane assigns; a node row's "instance"/"vm" is just
	// the compute wrapper. The route role wins over a generic node kind — the
	// discovery poller labels every EC2/VM instance "instance", which was
	// misrendering NVAs as application endpoints in cloud paths.
	nodeKind, nodeID := "", ""
	for _, n := range t.Nodes {
		if strings.ToLower(n.ID) == r || strings.ToLower(n.PrivateIP) == r {
			nodeKind, nodeID = n.Kind, strings.ToLower(n.ID)
			break
		}
	}
	if nodeKind != "" && nodeKind != "instance" && nodeKind != "vm" {
		return nodeKind
	}
	// The route's next hop declares a kind even when the target is not a node
	// row (Azure UDRs point at a bare next-hop IP). When the ref matched a node
	// by IP, the routes may name that node by its resource id — check both.
	for _, e := range t.Edges {
		to := strings.ToLower(e.To)
		if (to == r || (nodeID != "" && to == nodeID)) && e.ToKind != "" {
			return e.ToKind
		}
	}
	return nodeKind
}
