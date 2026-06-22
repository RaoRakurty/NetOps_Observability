package main

// dependency_view.go — the REAL service/app dependency projection for the topology
// canvas's "dependency" mode (P2). It is a SEPARATE projection from the physical
// graph: nodes are the endpoints that actually exchange traffic and edges are the
// OBSERVED "talks-to / depends-on" relationships, derived from NetFlow/IPFIX flow
// records in netops.flows — directional client→server, volume-weighted, top-N.
//
// Honesty + safety:
//   - Tenant-scoped through the SAME flowTenantClause used by /api/flows (operator
//     visibility + tenant isolation), so a tenant only ever sees its own dependencies.
//   - Flow-derived edges are evidence class "flow" at modest confidence (0.6) and
//     render dashed/inferred on the canvas — never as hard topology.
//   - An empty result (no flows / collectors off) returns a well-formed EMPTY view
//     so the frontend degrades to the labeled sample, same contract as geo.

import (
	"net/http"
	"strconv"
	"time"

	"netops/backend/models"
	"netops/backend/topology"
)

// dependency edge evidence class + confidence (flow is observational, not topology).
const depFlowConfidence = 0.6

// projectDependencyView builds the dependency View from observed flows. Reuses the
// inventory to resolve flow endpoints to managed devices; unresolved endpoints
// become muted "host" nodes (the same treatment as an unresolved LLDP neighbour).
func (s *server) projectDependencyView(r *http.Request, claims jwtClaims, tenant string, devs []models.Device) topology.View {
	now := time.Now()
	tenantClause, none := s.flowTenantClause(r)
	if none {
		return emptyDependencyView(tenant, now)
	}

	// address → managed device, for endpoint resolution.
	byAddr := make(map[string]models.Device, len(devs))
	for _, d := range devs {
		if d.Address != "" {
			byAddr[d.Address] = d
		}
	}

	// Top directed conversations by volume in the last hour. Injection-safe: only the
	// server-built tenant clause + a fixed window/limit are interpolated.
	sql := `
SELECT src_addr AS src,
       dst_addr AS dst,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate)) AS bytes_total,
       count() AS flows,
       any(dst_port) AS dport
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 3600 SECOND` + tenantClause + `
   AND src_addr != '' AND dst_addr != '' AND src_addr != dst_addr
 GROUP BY src, dst
 ORDER BY bytes_total DESC
 LIMIT 60
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		return emptyDependencyView(tenant, now)
	}
	return buildDependencyView(tenant, now, byAddr, rows)
}

// emptyDependencyView is the well-formed empty result (non-nil slices) the frontend
// degrades to a labeled sample on. Pure.
func emptyDependencyView(tenant string, now time.Time) topology.View {
	return topology.View{
		ViewID:      "topo:dep:" + tenant,
		Mode:        topology.ModeDependency,
		Scope:       topology.Scope{TenantID: tenant},
		LayoutType:  "dependency",
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Nodes:       []topology.Node{},
		Edges:       []topology.Edge{},
		Groups:      []topology.Group{},
		Overlays:    []string{"health", "flow"},
	}
}

// buildDependencyView is the PURE projection: flow rows ({src,dst,bytes_total,flows})
// + an address→device map → a dependency View. Unit-testable; no I/O. Tenant scoping
// is the caller's job (flowTenantClause), so the rows here are already tenant-bounded.
func buildDependencyView(tenant string, now time.Time, byAddr map[string]models.Device, rows []map[string]any) topology.View {
	if len(rows) == 0 {
		return emptyDependencyView(tenant, now)
	}
	nodes := map[string]*topology.Node{}
	linkCount := map[string]int{}
	ensure := func(addr string) string {
		if d, ok := byAddr[addr]; ok {
			id := d.ID
			if _, seen := nodes[id]; !seen {
				nodes[id] = &topology.Node{
					ID: id, Label: displayDevName(d, addr), Kind: inferDeviceType(d),
					Vendor: d.Vendor, Model: d.Model, MgmtIP: d.Address,
					Health: topology.HealthOK, Confidence: 1.0, Resolved: true,
					Metrics:  map[string]float64{},
					Evidence: []topology.EvidenceRef{{Source: "flow", Confidence: depFlowConfidence, Detail: "Observed exchanging traffic", ObservedAt: now.UTC().Format(time.RFC3339)}},
				}
			}
			return id
		}
		id := "host:" + addr
		if _, seen := nodes[id]; !seen {
			nodes[id] = &topology.Node{
				ID: id, Label: addr, Kind: topology.KindServer,
				Health: topology.HealthUnknown, Confidence: 0.5, Resolved: false,
				Metrics:  map[string]float64{},
				Evidence: []topology.EvidenceRef{{Source: "flow", Confidence: 0.5, Detail: "Endpoint seen in flows; not in inventory", ObservedAt: now.UTC().Format(time.RFC3339)}},
			}
		}
		return id
	}

	edges := make([]topology.Edge, 0, len(rows))
	for _, row := range rows {
		src, _ := row["src"].(string)
		dst, _ := row["dst"].(string)
		if src == "" || dst == "" {
			continue
		}
		sID, dID := ensure(src), ensure(dst)
		if sID == dID {
			continue
		}
		bytes := asFloat(row["bytes_total"])
		flows := asFloat(row["flows"])
		edges = append(edges, topology.Edge{
			ID:           "dep:" + sID + "--" + dID,
			Source:       sID,
			Target:       dID,
			Relationship: "dependency",
			Protocol:     "flow",
			Status:       "up",
			Confidence:   depFlowConfidence,
			LastSeen:     now.UTC().Format(time.RFC3339),
			Evidence: []topology.EvidenceRef{{
				Source: "flow", Confidence: depFlowConfidence,
				Detail:     flowEdgeDetail(flows, bytes),
				ObservedAt: now.UTC().Format(time.RFC3339),
			}},
		})
		linkCount[sID]++
		linkCount[dID]++
	}

	out := emptyDependencyView(tenant, now)
	out.Nodes = make([]topology.Node, 0, len(nodes))
	for id, n := range nodes {
		n.Metrics["dependency_count"] = float64(linkCount[id])
		out.Nodes = append(out.Nodes, *n)
	}
	out.Edges = edges
	return out
}

func displayDevName(d models.Device, fallback string) string {
	if d.Name != "" {
		return d.Name
	}
	if d.Address != "" {
		return d.Address
	}
	return fallback
}

// flowEdgeDetail is a compact human one-liner for a dependency edge's evidence.
func flowEdgeDetail(flows, bytes float64) string {
	return intToString(int(flows)) + " flows · " + humanBytes(bytes) + " observed (1h)"
}

// humanBytes renders a byte count in B/KB/MB/GB (decimal), one decimal place.
func humanBytes(b float64) string {
	f1 := func(x float64) string { return strconv.FormatFloat(x, 'f', 1, 64) }
	switch {
	case b >= 1e9:
		return f1(b/1e9) + " GB"
	case b >= 1e6:
		return f1(b/1e6) + " MB"
	case b >= 1e3:
		return f1(b/1e3) + " KB"
	default:
		return intToString(int(b)) + " B"
	}
}
