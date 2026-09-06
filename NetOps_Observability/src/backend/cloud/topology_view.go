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
	return BuildTopologyViewWithStatus(topos, tenant, now, nil)
}

// BuildTopologyViewWithStatus is BuildTopologyView with LIVE per-resource state
// painted onto the nodes. Split rather than changed in place so every existing
// caller and test keeps the pure structural projection.
func BuildTopologyViewWithStatus(topos []Topology, tenant string, now time.Time, status StatusLookup) topology.View {
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
	// Group accumulation across all providers.
	//
	// TWO LEVELS: a REGION group per (provider, region), and a VPC/VNet group
	// nested inside it. That nesting is the whole readability fix — a flat set
	// of VPC boxes has nothing keeping one region's VPCs away from another's, so
	// the blocks interleave and overlap. With a parent, the layout engine can
	// pack each region's VPCs inside one boundary.
	type groupAcc struct {
		label     string
		groupType string
		parentID  string
		children  []string
		order     int // first-seen order for stable output
	}
	groups := map[string]*groupAcc{}
	groupOrder := 0
	ensureGroupTyped := func(id, label, groupType, parentID string) {
		if id == "" {
			return
		}
		if _, ok := groups[id]; !ok {
			groups[id] = &groupAcc{label: label, groupType: groupType, parentID: parentID, order: groupOrder}
			groupOrder++
			return
		}
		g := groups[id]
		if label != "" && g.label == "" {
			g.label = label
		}
		// A parent discovered later must still take effect: the first sighting of
		// a VPC may precede the region context that owns it.
		if parentID != "" && g.parentID == "" {
			g.parentID = parentID
		}
	}

	for _, t := range topos {
		provider := string(t.Provider)
		vpcContainer := "VPC"
		if t.Provider == Azure {
			vpcContainer = "VNet"
		}

		// The REGION container. Keyed by (provider, region) because "us-east-1"
		// in two providers is two different places, and drawing them as one
		// region would merge unrelated networks into a single block.
		regionID := regionGroupID(provider, t.Region)
		if regionID != "" {
			ensureGroupTyped(regionID, regionLabel(provider, t.Region), "region", "")
		}
		// VPC groups nest inside the region they were discovered in.
		ensureVPCGroup := func(id, label string) { ensureGroupTyped(id, label, "vpc", regionID) }
		_ = ensureVPCGroup

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
			ensureVPCGroup(v.ID, label)
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
			view.Nodes = append(view.Nodes, cloudNode(s.ID, label, provider, "subnet", vpc, t.Region,
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
			view.Nodes = append(view.Nodes, cloudNode(id, label, provider, g.kind, g.vpc, t.Region,
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

	// Paint LIVE state onto every node in one pass, so no construction site can
	// be forgotten. Absent status stays HealthUnknown — the honest vocabulary's
	// "not measured". Unknown is never promoted to healthy.
	if status != nil {
		for i := range view.Nodes {
			st, ok := status(view.Nodes[i].ID)
			if !ok {
				continue
			}
			if h := healthFromCloudStatus(st.Status); h != "" {
				view.Nodes[i].Health = h
			}
			if view.Nodes[i].Tags == nil {
				view.Nodes[i].Tags = map[string]string{}
			}
			if st.Reason != "" {
				view.Nodes[i].Tags["status_reason"] = st.Reason
			}
			if st.Metric != "" {
				view.Nodes[i].Tags["key_metric"] = st.Metric
			}
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
		gt := g.groupType
		if gt == "" {
			gt = "vpc"
		}
		// `children` is a REQUIRED array in the view contract, and a REGION group
		// holds no member nodes directly (it parents VPC groups via parent_id), so
		// its accumulator stays nil — which encoding/json writes as `"children":null`.
		// Every consumer of the contract iterates that field; the SPA crashed on the
		// first region group and blanked the whole Cloud tab. A required array is
		// emitted as `[]`, never null.
		children := g.children
		if children == nil {
			children = []string{}
		}
		view.Groups = append(view.Groups, topology.Group{
			ID:        idByAcc[g],
			Label:     g.label,
			GroupType: gt,
			ParentID:  g.parentID,
			Children:  children,
			Health:    topology.HealthUnknown,
			Collapsed: false,
		})
	}
	return view
}

// cloudNode builds one canonical cloud-resource node. Health is honestly
// "unknown" (API-discovered, not health-monitored); tags carry the provider (for
// the mark) + role + the NETWORK CONTEXT the resource was discovered in
// (region, vpc, CIDR).
//
// region/vpc are on the node — not only on the containing groups — because the
// unified canvas classifies and re-groups by FACT (#131d). The alternative,
// widening the hostname regex in `domainOfNode`, is the one genuinely weak piece
// of that classifier and must not spread to cloud: a VPC is not a naming
// convention, it is a discovered field.
func cloudNode(id, label, provider, role, groupID, region string, extra map[string]string, evidenceDetail string) topology.Node {
	tags := map[string]string{"provider": provider, "role": role}
	if r := strings.TrimSpace(region); r != "" {
		tags["region"] = r
	}
	if groupID != "" {
		tags["vpc"] = groupID
	}
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

// regionGroupID keys a region container by PROVIDER and region.
//
// "us-east-1" exists in more than one provider's vocabulary, and an operator
// running AWS and a private cloud with overlapping region names must not see
// their networks merged into one block. Provider-qualifying costs nothing and
// removes a whole class of wrong-looking topology.
// NodeStatus is the LIVE per-resource signal the projection paints onto a node.
//
// It is deliberately a narrow injected lookup rather than a store dependency:
// BuildTopologyView stays a pure function of its inputs (which is why it is
// testable without a database), and the caller decides where status comes from.
type NodeStatus struct {
	Status string // healthy | degraded | down | not_measured (kinds.go vocabulary)
	Reason string // the SIGNAL that produced it ("targets 2/3 healthy")
	Metric string // one headline number, pre-rendered ("2/3 targets")
}

// StatusLookup answers "what is this cloud resource's live state?" for a
// resource id. A nil lookup, or an id it does not know, yields no status —
// which renders as NOT MEASURED, never as healthy. Unknown is not green.
type StatusLookup func(resourceID string) (NodeStatus, bool)

func regionGroupID(provider, region string) string {
	provider, region = strings.TrimSpace(provider), strings.TrimSpace(region)
	if provider == "" || region == "" {
		return ""
	}
	return "region:" + strings.ToLower(provider) + ":" + strings.ToLower(region)
}

// regionLabel renders the region container's caption.
func regionLabel(provider, region string) string {
	provider, region = strings.TrimSpace(provider), strings.TrimSpace(region)
	switch {
	case provider == "" && region == "":
		return ""
	case provider == "":
		return region
	case region == "":
		return provider
	}
	return provider + " · " + region
}

// healthFromCloudStatus maps the cloud component vocabulary (kinds.go) onto the
// topology contract's health.
//
// "" and not_measured deliberately return "" — the caller then leaves the node
// at HealthUnknown. Mapping an unmeasured component to healthy would be the
// exact lie the status vocabulary was designed to prevent: an operator reading
// green from a signal nobody ever collected.
func healthFromCloudStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case StatusHealthy:
		return topology.HealthOK
	case StatusDegraded:
		return topology.HealthWarning
	case StatusDown:
		return topology.HealthCritical
	default:
		return ""
	}
}

// StatusLookupFor builds the live-state lookup for a resource inventory.
//
// PURE, and in this package on purpose: the projection, the seam links and the
// path graph all need the same join, and three copies of "index by resource id
// AND by any interface id" would eventually disagree. A nil/empty inventory
// yields a nil lookup, which renders every node as NOT MEASURED — the honest
// rendering of "we could not ask", never a green map from no data at all.
func StatusLookupFor(res []CloudResource) StatusLookup {
	if len(res) == 0 {
		return nil
	}
	byID := make(map[string]NodeStatus, len(res))
	for _, c := range res {
		st := NodeStatus{Status: c.Status, Reason: c.StatusReason}
		if c.KeyMetricValue != nil && c.KeyMetricName != "" {
			st.Metric = fmt.Sprintf("%s %g%s", c.KeyMetricName, *c.KeyMetricValue, c.KeyMetricUnit)
		}
		// Index by resource id AND by any interface id, because the egress
		// topology names NVAs by their instance id while the inventory may only
		// carry the ENI that address belongs to.
		if c.ResourceID != "" {
			byID[c.ResourceID] = st
		}
		for _, nic := range c.NetworkInterfaceIDs {
			if nic != "" {
				if _, taken := byID[nic]; !taken {
					byID[nic] = st
				}
			}
		}
	}
	if len(byID) == 0 {
		return nil
	}
	return func(id string) (NodeStatus, bool) {
		st, ok := byID[id]
		return st, ok
	}
}
