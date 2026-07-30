package backend

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
	"fmt"
	"net"
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
func (s *server) projectDependencyView(r *http.Request, claims jwtClaims, tenant string, devs []models.Device) (topology.View, error) {
	now := time.Now()
	tenantClause, none := s.flowTenantClause(r)
	if none {
		// Genuinely nothing visible to this principal — an honest empty, not a failure.
		return emptyDependencyView(tenant, now), nil
	}

	// address → managed device, for endpoint resolution.
	byAddr := make(map[string]models.Device, len(devs))
	for _, d := range devs {
		if d.Address != "" {
			byAddr[d.Address] = d
		}
	}

	// Top directed conversations by volume in the last hour. A SERVICE dependency is
	// unicast TCP/UDP to a real port — so we exclude the network plumbing that would
	// otherwise pollute the map: routing/control protocols (OSPF/PIM/IGMP/VRRP/ICMP
	// all have proto ∉ {6,17}), counter/control samples (dst_port 0), and multicast /
	// broadcast / link-local destinations. Injection-safe: only the server-built
	// tenant clause + fixed window/limit are interpolated.
	sql := `
SELECT src_addr AS src,
       dst_addr AS dst,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate)) AS bytes_total,
       count() AS flows,
       any(dst_port) AS dport
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 3600 SECOND` + tenantClause + `
   AND proto IN (6, 17) AND dst_port != 0
   AND src_addr != '' AND dst_addr != '' AND src_addr != dst_addr
   AND NOT (toIPv4OrDefault(dst_addr) BETWEEN toIPv4('224.0.0.0') AND toIPv4('239.255.255.255'))
   AND NOT (toIPv4OrDefault(dst_addr) BETWEEN toIPv4('169.254.0.0') AND toIPv4('169.254.255.255'))
   AND dst_addr != '255.255.255.255'
 GROUP BY src, dst
 ORDER BY bytes_total DESC
 LIMIT 60
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		// A flow-store failure is NOT "this tenant has no dependencies". The
		// frontend degrades an empty view to a labeled sample, so returning
		// empty here puts DEMO topology on screen during an outage while the
		// operator is trying to work out their blast radius. Say we could not
		// answer; the caller turns it into a 502 rather than a confident empty.
		logError("topology", "dependency view unavailable — flow store did not answer",
			map[string]any{"tenant": tenant, "err": err.Error()})
		return topology.View{}, fmt.Errorf("dependency view unavailable: %w", err)
	}
	return buildDependencyView(tenant, now, byAddr, rows), nil
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
		dport := int(asFloat(row["dport"]))
		// Defense-in-depth: drop network plumbing (multicast/broadcast/link-local,
		// no real port, self-talk) even if the SQL filter is ever weakened or the rows
		// come from a non-ClickHouse source. A service dependency is unicast to a real
		// port — see isDependencyNoise.
		if isDependencyNoise(src, dst, dport) {
			continue
		}
		sID, dID := ensure(src), ensure(dst)
		if sID == dID {
			continue // distinct addresses resolving to the same managed device
		}
		bytes := asFloat(row["bytes_total"])
		flows := asFloat(row["flows"])
		svc := serviceForPort(dport)
		edges = append(edges, topology.Edge{
			ID:           "dep:" + sID + "--" + dID,
			Source:       sID,
			Target:       dID,
			TargetPort:   svc, // the dependency's service (e.g. "https (443)"), not a raw port
			Relationship: "dependency",
			Protocol:     "flow",
			Status:       "up",
			Confidence:   depFlowConfidence,
			LastSeen:     now.UTC().Format(time.RFC3339),
			Evidence: []topology.EvidenceRef{{
				Source: "flow", Confidence: depFlowConfidence,
				Detail:     "depends on " + svc + " · " + flowEdgeDetail(flows, bytes),
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

// isDependencyNoise reports whether a flow conversation is network plumbing rather
// than a real service dependency, and must therefore never appear on the dependency
// map. NON-NEGOTIABLE invariant (see CLAUDE.md §3 zero-trust, dependency-map honesty):
// control/counter samples (no real destination port), self-talk, and multicast /
// broadcast / link-local destinations (OSPF/PIM/IGMP/VRRP, DHCP discovery, mDNS, etc.)
// are NOT dependencies. The SQL in projectDependencyView is the primary filter; this is
// the unit-testable guard on the PURE projection so the invariant holds regardless of
// the row source. Unparseable / hostname destinations are left to the resolver.
func isDependencyNoise(src, dst string, dport int) bool {
	if src == "" || dst == "" || src == dst {
		return true
	}
	if dport <= 0 {
		return true
	}
	ip := net.ParseIP(dst)
	if ip == nil {
		return false
	}
	if ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// IPv4 limited broadcast (255.255.255.255) is not flagged by IsMulticast.
	if v4 := ip.To4(); v4 != nil && v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
		return true
	}
	return false
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

// wellKnownService maps a well-known server port to a customer-facing service name.
// Keeps the dependency map readable ("depends on PostgreSQL") instead of a raw port.
var wellKnownService = map[int]string{
	80: "HTTP", 8080: "HTTP", 443: "HTTPS", 8443: "HTTPS", 53: "DNS",
	22: "SSH", 25: "SMTP", 587: "SMTP", 465: "SMTP", 110: "POP3", 143: "IMAP",
	5432: "PostgreSQL", 3306: "MySQL", 1433: "SQL Server", 1521: "Oracle DB",
	6379: "Redis", 11211: "Memcached", 27017: "MongoDB", 9200: "Search", 9300: "Search",
	5672: "AMQP", 9092: "Kafka", 2181: "ZooKeeper", 389: "LDAP", 636: "LDAPS",
	123: "NTP", 161: "SNMP", 514: "Syslog", 179: "BGP", 3389: "RDP", 445: "SMB",
	8086: "Metrics", 9090: "Metrics", 6443: "Kubernetes API", 2049: "NFS",
}

// serviceForPort returns "<Service> (<port>)" for a known port, else "port <n>".
func serviceForPort(port int) string {
	if port <= 0 {
		return "service"
	}
	if name, ok := wellKnownService[port]; ok {
		return name + " (" + intToString(port) + ")"
	}
	return "port " + intToString(port)
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
