package cloud

// topology_view.go — projects the discovered cloud EGRESS TOPOLOGY (the route-table
// facts loaded by LoadTopologies) into the canonical, renderer-agnostic
// topology.View the Topology Operating Canvas consumes — the SAME wire shape the
// LAN projections emit, so the Cloud tab needs no new frontend type.
//
// The organization mirrors how the AWS/Azure consoles read a network:
//
//	VPC/VNet (group container)
//	  └─ Subnet (node, CIDR on the card)          ── routed_adjacency ──▶ Gateway/NVA
//	        route table: <destination CIDR> via <route-table name> to <egress>
//
// HONESTY (mirrors topology.go's note): a route is CONTROL-PLANE, inferred data —
// "the app subnet's 0.0.0.0/0 points at the NVA" is a strong explanation of how a
// subnet egresses, NOT a claim that traffic took it. Every edge is
// routed_adjacency at moderate confidence, evidence-stamped with the route table.
// Nodes are discovered via the provider API and not (yet) health-monitored, so
// their health is honestly "unknown" — never a fabricated green.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"netops/backend/topology"
)

// gatewayKinds are the route next-hop / node roles that are NETWORK FUNCTIONS
// (an egress edge target), as opposed to a workload ("instance"/"vm"). The Cloud
// NETWORK topology renders these; plain compute workloads are out of scope.
var gatewayKinds = map[string]bool{
	"internet_gateway":     true,
	"nat_gateway":          true,
	"vpc_endpoint":         true,
	"vpn_gateway":          true,
	"transit_gateway":      true,
	"vpc_peering":          true,
	"egress_only_igw":      true,
	"carrier_gateway":      true,
	"local_gateway":        true,
	"nva":                  true,
	"dx":                   true,
	"expressroute_gateway": true,
	"internet":             true,
}

// gatewayLabelPrefix maps a network-function kind to the short console label
// operators recognise. Unknown kinds fall back to a title-cased kind.
var gatewayLabelPrefix = map[string]string{
	"internet_gateway":     "IGW",
	"nat_gateway":          "NAT",
	"vpc_endpoint":         "Endpoint",
	"vpn_gateway":          "VPN GW",
	"transit_gateway":      "Transit GW",
	"vpc_peering":          "Peering",
	"egress_only_igw":      "Egress IGW",
	"carrier_gateway":      "Carrier GW",
	"local_gateway":        "Local GW",
	"nva":                  "NVA",
	"dx":                   "Direct Connect",
	"expressroute_gateway": "ExpressRoute GW",
	"internet":             "Internet",
}

// BuildTopologyView maps the discovered egress topologies of every provider into
// one canonical topology.View, tenant-stamped in its scope. `tenant` is the scope
// the caller is authorized for (already resolved by principalTenant) — it is only
// stamped onto the view; the fixtures themselves are provider-global.
//
// Pure and deterministic (sorted output): no IO, no globals, fully unit-testable.
func BuildTopologyView(topos []Topology, tenant string, now time.Time) topology.View {
	nowStr := now.UTC().Format(time.RFC3339)
	view := topology.View{
		ViewID:      "cloud-network",
		Mode:        topology.ModeExplore,
		Scope:       topology.Scope{TenantID: tenant},
		LayoutType:  "cloud_grouped",
		GeneratedAt: nowStr,
		Overlays:    []string{"health"},
		Nodes:       []topology.Node{},
		Edges:       []topology.Edge{},
		Groups:      []topology.Group{},
	}
	// Group accumulation across all providers, keyed by VPC/VNet id.
	type groupAcc struct {
		label    string
		children []string
		order    int // first-seen order for stable output
	}
	groups := map[string]*groupAcc{}
	groupOrder := 0
	ensureGroup := func(id, label string) {
		if id == "" {
			return
		}
		if _, ok := groups[id]; !ok {
			groups[id] = &groupAcc{label: label, order: groupOrder}
			groupOrder++
		} else if label != "" && groups[id].label == "" {
			groups[id].label = label
		}
	}

	for _, t := range topos {
		provider := string(t.Provider)
		vpcContainer := "VPC"
		if t.Provider == Azure {
			vpcContainer = "VNet"
		}

		// VPC/VNet lookup + prefixes (a VNet may carry several address prefixes,
		// emitted as several vpc rows sharing one id — dedupe by id here).
		type vpcPrefix struct {
			id     string
			prefix netip.Prefix
		}
		var vpcPrefixes []vpcPrefix
		vpcName := map[string]string{}
		vpcPrimaryCIDR := map[string]string{}
		for _, v := range t.VPCs {
			if _, ok := vpcName[v.ID]; !ok {
				vpcName[v.ID] = firstNonEmpty(v.Name, v.ID)
				vpcPrimaryCIDR[v.ID] = v.CIDR
			}
			if p, err := netip.ParsePrefix(strings.TrimSpace(v.CIDR)); err == nil {
				vpcPrefixes = append(vpcPrefixes, vpcPrefix{id: v.ID, prefix: p})
			}
		}
		vpcOfCIDR := func(cidr string) string {
			p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				return ""
			}
			for _, vp := range vpcPrefixes {
				if vp.prefix.Overlaps(p) && vp.prefix.Bits() <= p.Bits() {
					return vp.id
				}
			}
			return ""
		}

		// Register the VPC/VNet groups up front so an empty VPC still renders.
		for _, v := range t.VPCs {
			label := fmt.Sprintf("%s · %s · %s", vpcContainer, vpcName[v.ID], vpcPrimaryCIDR[v.ID])
			ensureGroup(v.ID, label)
		}

		// Subnet nodes, grouped under their VPC by CIDR containment.
		subnetVPC := map[string]string{}
		for _, s := range t.Subnets {
			vpc := vpcOfCIDR(s.CIDR)
			subnetVPC[s.ID] = vpc
			name := firstNonEmpty(s.Name, s.ID)
			label := fmt.Sprintf("Subnet · %s", name)
			if s.CIDR != "" {
				label = fmt.Sprintf("Subnet · %s · %s", name, s.CIDR)
			}
			view.Nodes = append(view.Nodes, cloudNode(s.ID, label, provider, "subnet", vpc,
				map[string]string{"cidr": s.CIDR}, fmt.Sprintf("subnet %s", s.ID)))
			if vpc != "" {
				groups[vpc].children = append(groups[vpc].children, s.ID)
			}
		}

		// Gateways / NVAs: from declared node rows AND from every edge target
		// (the route's next-hop kind is authoritative — it labels an NVA that the
		// node row calls a bare "instance").
		type gw struct {
			kind, name, vpc string
		}
		gws := map[string]*gw{}
		nodeName := map[string]string{}
		for _, n := range t.Nodes {
			if n.Name != "" {
				nodeName[n.ID] = n.Name
			}
			if gatewayKinds[n.Kind] {
				g := &gw{kind: n.Kind, name: firstNonEmpty(n.Name, n.ID)}
				if n.SubnetID != "" {
					g.vpc = subnetVPC[n.SubnetID]
				}
				gws[n.ID] = g
			}
		}
		for _, e := range t.Edges {
			if e.To == "" || e.ToKind == "" {
				continue
			}
			g, ok := gws[e.To]
			if !ok {
				g = &gw{}
				gws[e.To] = g
			}
			if g.kind == "" || g.kind == "instance" || g.kind == "vm" {
				g.kind = e.ToKind
			}
			if g.name == "" {
				g.name = firstNonEmpty(nodeName[e.To], e.To)
			}
			if g.vpc == "" {
				g.vpc = subnetVPC[e.FromSubnet]
			}
		}
		// Emit gateway nodes in a stable order.
		gwIDs := make([]string, 0, len(gws))
		for id := range gws {
			gwIDs = append(gwIDs, id)
		}
		sort.Strings(gwIDs)
		for _, id := range gwIDs {
			g := gws[id]
			prefix := gatewayLabelPrefix[g.kind]
			if prefix == "" {
				prefix = strings.ReplaceAll(g.kind, "_", " ")
			}
			label := fmt.Sprintf("%s · %s", prefix, g.name)
			view.Nodes = append(view.Nodes, cloudNode(id, label, provider, g.kind, g.vpc,
				map[string]string{}, fmt.Sprintf("%s %s", g.kind, id)))
			if g.vpc != "" {
				groups[g.vpc].children = append(groups[g.vpc].children, id)
			}
		}

		// Route-table edges: subnet --(destination CIDR)--> egress target.
		for _, e := range t.Edges {
			if e.To == "" || e.ToKind == "" || e.FromSubnet == "" {
				continue
			}
			status := topology.StatusUp
			if strings.EqualFold(e.State, "blackhole") {
				status = topology.StatusDown
			}
			rt := firstNonEmpty(e.RouteTableName, e.ViaRouteTable)
			detail := fmt.Sprintf("route table %s: %s → %s", rt, e.Destination, e.To)
			view.Edges = append(view.Edges, topology.Edge{
				ID:           routeEdgeID(e.FromSubnet, e.To, e.Destination),
				Source:       e.FromSubnet,
				Target:       e.To,
				SourcePort:   e.Destination, // the destination CIDR is the edge label
				Relationship: topology.RelRoutedAdjacency,
				Protocol:     "cloud_api",
				Status:       status,
				Confidence:   0.7,
				FirstSeen:    nowStr,
				LastSeen:     nowStr,
				ChangeState:  topology.ChangeUnchanged,
				Evidence: []topology.EvidenceRef{{
					Source:     "cloud_api",
					Confidence: 0.7,
					Detail:     detail,
					ObservedAt: nowStr,
				}},
			})
		}
	}

	// Emit groups in first-seen order with their accumulated children.
	ordered := make([]*groupAcc, 0, len(groups))
	idByAcc := map[*groupAcc]string{}
	for id, g := range groups {
		ordered = append(ordered, g)
		idByAcc[g] = id
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].order < ordered[j].order })
	for _, g := range ordered {
		view.Groups = append(view.Groups, topology.Group{
			ID:        idByAcc[g],
			Label:     g.label,
			GroupType: "vpc",
			Children:  g.children,
			Health:    topology.HealthUnknown,
			Collapsed: false,
		})
	}
	return view
}

// cloudNode builds one canonical cloud-resource node. Health is honestly
// "unknown" (API-discovered, not health-monitored); tags carry the provider (for
// the official mark) + role + any network context (CIDR).
func cloudNode(id, label, provider, role, groupID string, extra map[string]string, evidenceDetail string) topology.Node {
	tags := map[string]string{"provider": provider, "role": role}
	for k, v := range extra {
		if v != "" {
			tags[k] = v
		}
	}
	return topology.Node{
		ID:          id,
		Label:       label,
		Kind:        topology.KindCloud,
		Role:        role,
		Site:        provider,
		Health:      topology.HealthUnknown,
		Confidence:  0.9,
		FirstSeen:   "",
		ChangeState: topology.ChangeUnchanged,
		Resolved:    true,
		GroupID:     groupID,
		Tags:        tags,
		Evidence: []topology.EvidenceRef{{
			Source:     "cloud_api",
			Confidence: 0.9,
			Detail:     evidenceDetail,
		}},
	}
}

// routeEdgeID is a stable, filesystem/DOM-safe id for a route edge.
func routeEdgeID(source, target, destination string) string {
	raw := fmt.Sprintf("route-%s-%s-%s", source, target, destination)
	return strings.NewReplacer(".", "_", "/", "_", ":", "_", " ", "_").Replace(raw)
}
