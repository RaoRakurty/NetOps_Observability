// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// seam_links.go — the LATERAL seam links (#131c): the edges that say "these two
// cloud gateways are two ends of ONE link".
//
// THE MODELLING DECISION (coordinator, final). The Attached* facts on a seam
// endpoint (`model.go`) name the VPCs/regions a link joins, and `seamGroupID`
// (rollup.go) already groups the endpoints that declare the SAME attachment set
// into one seam. A VPC is a GROUP in the view contract and `topology.Edge` joins
// NODES, so the link is expressed as SEAM-DEVICE ↔ SEAM-DEVICE within one
// `seamGroupID` — never as an edge on a group, and never through an invented
// anchor node standing in for the VPC. The seam id travels on the edge
// (`tags.seam_group_id`) so the canvas and the rollup name the same seam.
//
// OBSERVED, NOT INFERRED. A route edge is control-plane data at 0.7 confidence
// ("the subnet's default route points at the NVA"); an attachment is the cloud
// inventory stating what the device IS attached to. That is an observed
// adjacency, so the relationship is `connected_to` — the contract's observed
// class — never `inferred`. The distinction is load-bearing downstream:
// `edgeBundling.ts` keys its bundle on the relationship, so an observed seam
// link can never be collapsed into a route bundle, and refuses to bundle
// anything degraded — a seam with a tunnel down is drawn on its own.
//
// NO NODE, NO EDGE. An endpoint is only joined when BOTH devices are nodes on
// the projected view. A seam device the egress topology never discovered gets no
// edge and no placeholder node: "no seam link discovered" is an honest state,
// and a link to a node that is not there is a lie the renderer would drop anyway.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/topology"
)

// maxSeamLinkDevices bounds the pairwise expansion inside ONE seam. A seam is a
// handful of traversed devices in practice (a VPN pair, a TGW and its
// attachments); pairing is O(n²), so the count is capped the same way
// `buildSeams` caps `MaxSeamDevices` — deterministically, lowest ids first —
// rather than letting a pathological inventory draw thousands of curves.
const maxSeamLinkDevices = 8

// seamEndpointNode resolves a seam resource to the id of the node it is drawn as
// on the view, or ("", false) when the egress topology never discovered it.
//
// The resource id is authoritative; a network-interface id is the documented
// fallback because the egress topology names an NVA by its instance while the
// inventory may only carry the ENI — the same join `cloudStatusLookup` makes.
func seamEndpointNode(r CloudResource, nodes map[string]bool) (string, bool) {
	if r.ResourceID != "" && nodes[r.ResourceID] {
		return r.ResourceID, true
	}
	for _, nic := range r.NetworkInterfaceIDs {
		if nic != "" && nodes[nic] {
			return nic, true
		}
	}
	return "", false
}

// seamAttachTargets is the human list of what a seam joins — the VPCs and
// regions its endpoints declare. Used as edge evidence, so the operator reads
// WHY two gateways are drawn as one link.
func seamAttachTargets(rs []CloudResource) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range rs {
		for _, v := range r.AttachedVpcIDs {
			if v = strings.TrimSpace(v); v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		for _, rg := range r.AttachedRegions {
			if rg = strings.TrimSpace(rg); rg != "" && !seen[rg] {
				seen[rg] = true
				out = append(out, rg)
			}
		}
	}
	sort.Strings(out)
	return out
}

// seamEdgeStatus maps the worst of the two endpoints' component status onto the
// edge status vocabulary. An unmeasured endpoint leaves the link UNKNOWN — a
// seam nobody measured is never drawn as up (kinds.go's whole point).
func seamEdgeStatus(a, b string) string {
	worst := StatusNotMeasured
	for _, s := range []string{NormalizeComponentStatus(a), NormalizeComponentStatus(b)} {
		switch {
		case s == StatusDown:
			return topology.StatusDown
		case s == StatusDegraded:
			worst = StatusDegraded
		case s == StatusHealthy && worst != StatusDegraded:
			worst = StatusHealthy
		}
	}
	switch worst {
	case StatusDegraded:
		return topology.StatusDegraded
	case StatusHealthy:
		return topology.StatusUp
	default:
		return topology.StatusUnknown
	}
}

// seamEdgeID is a stable, DOM-safe id for a lateral seam edge.
func seamEdgeID(a, b string) string {
	return strings.NewReplacer(".", "_", "/", "_", ":", "_", " ", "_", "|", "_").
		Replace(fmt.Sprintf("seam-%s-%s", a, b))
}

// BuildSeamLinks returns the lateral seam edges for a projected cloud view.
//
// `nodes` are the view's nodes (an endpoint with no node gets no edge) and `inv`
// is the caller's ALREADY TENANT-SCOPED inventory. Grouping is keyed by
// (tenant, seamGroupID) so two tenants that happen to name the same VPC are
// never joined into one link — a cross-tenant edge would be a §3a leak drawn as
// a plausible line. Pure and deterministic (sorted output).
func BuildSeamLinks(nodes []topology.Node, inv []CloudResource, now time.Time) []topology.Edge {
	nodeIDs := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeIDs[n.ID] = true
	}

	type acc struct {
		seamID  string
		devices []string          // resolved node ids, deduped
		res     []CloudResource   // the resources behind them (for evidence)
		status  map[string]string // node id → component status
	}
	groups := map[string]*acc{}
	order := []string{}
	for _, r := range inv {
		if ComponentFamily(r.ResourceType) != FamilySeam {
			continue
		}
		id, ok := seamEndpointNode(r, nodeIDs)
		if !ok {
			continue // discovered as inventory, never drawn — no edge to hang
		}
		seamID := seamGroupID(r)
		// TENANT FIRST (§3a): the key is scoped so a cross-tenant principal's
		// wider inventory can never pair one tenant's gateway with another's.
		key := r.TenantID + "\x00" + seamID
		g := groups[key]
		if g == nil {
			g = &acc{seamID: seamID, status: map[string]string{}}
			groups[key] = g
			order = append(order, key)
		}
		g.res = append(g.res, r)
		if _, dup := g.status[id]; !dup {
			g.devices = append(g.devices, id)
		}
		// Worst status wins if two resources resolve to the same node.
		if cur, ok := g.status[id]; !ok || displaySeverity(NormalizeComponentStatus(r.Status)) > displaySeverity(cur) {
			g.status[id] = NormalizeComponentStatus(r.Status)
		}
	}

	nowStr := now.UTC().Format(time.RFC3339)
	out := []topology.Edge{}
	sort.Strings(order)
	for _, key := range order {
		g := groups[key]
		sort.Strings(g.devices)
		devices := g.devices
		if len(devices) > maxSeamLinkDevices {
			devices = devices[:maxSeamLinkDevices]
		}
		targets := seamAttachTargets(g.res)
		detail := "seam attachment"
		if len(targets) > 0 {
			detail = "seam attachment joins " + strings.Join(targets, ", ")
		}
		for i := 0; i < len(devices); i++ {
			for j := i + 1; j < len(devices); j++ {
				a, b := devices[i], devices[j]
				out = append(out, topology.Edge{
					ID:           seamEdgeID(a, b),
					Source:       a,
					Target:       b,
					Relationship: topology.RelConnectedTo,
					Protocol:     "cloud_api",
					Status:       seamEdgeStatus(g.status[a], g.status[b]),
					Confidence:   0.9,
					FirstSeen:    nowStr,
					LastSeen:     nowStr,
					ChangeState:  topology.ChangeUnchanged,
					Tags:         map[string]string{"seam_group_id": g.seamID},
					Evidence: []topology.EvidenceRef{{
						Source:     "cloud_api",
						Confidence: 0.9,
						Detail:     detail,
						ObservedAt: nowStr,
					}},
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// BuildTopologyViewWithInventory is BuildTopologyViewWithStatus plus the LATERAL
// seam links the inventory's Attached* facts establish (#131c).
//
// Split from its two siblings for the same reason they were split from each
// other: every existing caller and test keeps the projection it asked for, and
// the pure structural version stays free of the inventory entirely.
func BuildTopologyViewWithInventory(topos []Topology, tenant string, now time.Time, inv []CloudResource) topology.View {
	view := BuildTopologyViewWithStatus(topos, tenant, now, StatusLookupFor(inv))
	view.Edges = append(view.Edges, BuildSeamLinks(view.Nodes, inv, now)...)
	return view
}

// ── the ON-PREM seam (#130b) ─────────────────────────────────────────────────

// onPremPeerAttrs is the CLOSED set of inventory attrs that name the on-premises
// end of a seam. Each is a fact a provider API actually returns — the address
// the tunnel or circuit terminates on outside the cloud:
//
//	peer_ip             — GCP VPN tunnel peerIp (gcp_components.py)
//	peer_address        — GCP router BGP peerIpAddress
//	customer_gateway_ip — the AWS CGW / Azure local-network-gateway address
//
// A closed set is the point. The Attached* facts name VPCs and regions and NEVER
// an on-prem device, so there is nothing there to join on; matching a hostname,
// a tag or a name substring instead would manufacture the adjacency rather than
// discover it. Where the provider returned no peer address there is NO seam
// edge, and the trace says so (topology.PathStateNoSeam).
var onPremPeerAttrs = []string{"peer_ip", "peer_address", "customer_gateway_ip"}

// DeviceResolver answers "which managed device owns this address, for this
// resource's tenant?" — ("", false) when none does.
//
// The TENANT is a parameter, not an assumption: a cross-tenant principal reads a
// wider inventory AND a wider device list, and joining one tenant's cloud
// gateway to another tenant's WAN edge on a shared address would draw a
// perfectly plausible wrong line across an ownership border (§3a). The caller
// owns the rule because only it knows each device's tenant.
type DeviceResolver func(tenantID, addr string) (string, bool)

// BuildOnPremSeamEdges returns the DISCOVERED on-prem ↔ cloud seam edges: a
// cloud seam endpoint joined to the managed device its peer address resolves to.
//
// This is the adjacency Dijkstra crosses to trace from a branch router to a
// cloud subnet. It is data, never an assumption — where the provider named no
// peer, or the address matches no device we manage, no edge is produced.
// Pure and deterministic (sorted output).
func BuildOnPremSeamEdges(nodes []topology.Node, inv []CloudResource, resolve DeviceResolver, now time.Time) []topology.Edge {
	if resolve == nil {
		return []topology.Edge{}
	}
	nodeIDs := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeIDs[n.ID] = true
	}
	nowStr := now.UTC().Format(time.RFC3339)
	seen := map[string]bool{}
	out := []topology.Edge{}
	for _, r := range inv {
		if ComponentFamily(r.ResourceType) != FamilySeam {
			continue
		}
		cloudID, ok := seamEndpointNode(r, nodeIDs)
		if !ok {
			continue
		}
		for _, key := range onPremPeerAttrs {
			addr := strings.TrimSpace(r.Attrs[key])
			if addr == "" {
				continue
			}
			dev, ok := resolve(r.TenantID, addr)
			if !ok || dev == "" || dev == cloudID {
				continue
			}
			id := seamEdgeID(cloudID, dev)
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, topology.Edge{
				ID:           id,
				Source:       cloudID,
				Target:       dev,
				Relationship: topology.RelConnectedTo,
				Protocol:     "cloud_api",
				Status:       seamEdgeStatus(r.Status, r.Status),
				Confidence:   0.9,
				FirstSeen:    nowStr,
				LastSeen:     nowStr,
				ChangeState:  topology.ChangeUnchanged,
				Tags:         map[string]string{"seam_group_id": seamGroupID(r), "peer_address": addr},
				Evidence: []topology.EvidenceRef{{
					Source:     "cloud_api",
					Confidence: 0.9,
					Detail:     fmt.Sprintf("%s terminates on %s", r.ResourceType, addr),
					ObservedAt: nowStr,
				}},
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
