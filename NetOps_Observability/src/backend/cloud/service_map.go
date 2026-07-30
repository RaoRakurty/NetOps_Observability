package cloud

// service_map.go — the observed service dependency graph (cloud-platform-backlog
// #9, extracted P2 W4.19). Derived from OBSERVED cloud flow telemetry: the
// cloud_flow_pair rollups (top-K (src,dst) ACCEPT pairs per scan, emitted by all
// three cloud flow lanes) become volume-weighted talks_to edges, and
// cloud_flow_log REJECT rollups mark an edge as blocked by security rules.
//
// Endpoints resolve to services through the caller-supplied resolver in trust
// order (identity map first, then declared inventory — both principalTenant-
// scoped by the caller). An address the resolver doesn't claim stays honestly
// UNATTRIBUTED: the top-N unresolved endpoints (by observed bytes) render as
// their own bounded nodes; anything beyond the bound is dropped AND counted in
// Meta — never silently, never unbounded, never guessed.
//
// Honesty rules:
//   - Every edge is observed traffic (bytes summed from the pair signals) or an
//     observed REJECT — nothing is inferred from co-location or timing.
//   - Blocked evidence never inflates volume: REJECT magnitudes are provider-
//     specific (bytes on AWS, counts on Azure/GCP), so a blocked edge carries a
//     blocked observation count, not fabricated bytes.
//   - Meta reports what the window actually held (pair signals, resolved /
//     unresolved endpoints, truncation) so the UI can label the map truthfully.
//
// Tenant isolation (§3a): both SQL builders carry the caller's tenant_scope
// SETTINGS literal (the corr_signals FORCE row policy enforces it in the
// database). Bounded by construction: clamped window, GROUP BY with LIMIT,
// named columns.

import (
	"fmt"
	"net"
	"sort"
)

const (
	// Bounded read budgets (#100 contract): at most this many aggregated pair /
	// reject rows per request. The producers already cap pairs per scan cycle;
	// this bounds the window-wide aggregation regardless.
	ServiceMapMaxPairRows   = 500
	ServiceMapMaxRejectRows = 200
	// At most this many UNRESOLVED endpoints become nodes (top by bytes).
	ServiceMapMaxUnattributed = 10
)

// ── wire types ───────────────────────────────────────────────────────────────

type ServiceMapNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// "service" (resolved to a declared service/workload) or "endpoint"
	// (an observed address no inventory claims — honestly unattributed).
	Kind      string   `json:"kind"`
	Resolved  bool     `json:"resolved"`
	Bytes     float64  `json:"bytes"`
	Providers []string `json:"providers"`
}

type ServiceMapEdge struct {
	SourceService string   `json:"source_service"`
	DestService   string   `json:"dest_service"`
	Relationship  string   `json:"relationship"` // always "talks_to" — observed traffic
	Bytes         float64  `json:"bytes"`        // accepted volume only (never REJECT-derived)
	PairCount     int      `json:"pair_count"`   // distinct (src,dst) address pairs behind the edge
	Blocked       bool     `json:"blocked"`      // security rules rejected traffic on this edge
	BlockedCount  int      `json:"blocked_count"`
	Providers     []string `json:"providers"`
}

type ServiceMapMeta struct {
	WindowHours         int    `json:"window_hours"`
	PairSignals         int    `json:"pair_signals"`         // pair observations aggregated
	ResolvedEndpoints   int    `json:"resolved_endpoints"`   // distinct addresses resolved to a service
	UnresolvedEndpoints int    `json:"unresolved_endpoints"` // distinct addresses nothing claims
	UnattributedShown   int    `json:"unattributed_shown"`   // unresolved endpoints kept as nodes (top-N)
	UnattributedDropped int    `json:"unattributed_dropped"` // unresolved endpoints beyond the bound
	GeneratedAt         string `json:"generated_at"`
}

type ServiceMapGraph struct {
	Nodes []ServiceMapNode
	Edges []ServiceMapEdge
	Meta  ServiceMapMeta
}

// FlowPairRow is one aggregated (src,dst) row off corr_signals (JSONEachRow).
type FlowPairRow struct {
	Src       string   `json:"src"`
	Dst       string   `json:"dst"`
	Bytes     float64  `json:"bytes"`
	Obs       int      `json:"obs"`
	Providers []string `json:"providers"`
}

// ── SQL builders (pure — every one carries the caller's tenant_scope) ─────────

// ServiceMapPairSQL aggregates the window's cloud_flow_pair signals per
// (src,dst). Each pair signal is one scan cycle's NEW flow records
// (offset-tracked producers), so summing across rows sums disjoint observation
// windows.
func ServiceMapPairSQL(windowHours, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT JSONExtractString(attrs,'srcaddr') AS src,
       JSONExtractString(attrs,'dstaddr') AS dst,
       sum(value)                         AS bytes,
       count()                            AS obs,
       groupUniqArray(JSONExtractString(attrs,'provider')) AS providers
  FROM netops.corr_signals
 WHERE source = 'cloud'
   AND kind = 'cloud_flow_pair'
   AND ts > now() - INTERVAL %d HOUR
   AND JSONExtractString(attrs,'srcaddr') != ''
   AND JSONExtractString(attrs,'dstaddr') != ''
 GROUP BY src, dst
 ORDER BY bytes DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, limit, scope)
}

// ServiceMapRejectSQL aggregates the window's REJECT evidence per (src,dst) —
// the "blocked by security rules" layer. Only rows that carry BOTH peers can
// mark an edge (Azure/GCP deny rollups keep a sample tuple; AWS keeps every
// rejected pair's addresses). value semantics differ per provider, so only the
// observation COUNT is reported, never value-derived "bytes".
func ServiceMapRejectSQL(windowHours, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT JSONExtractString(attrs,'srcaddr') AS src,
       JSONExtractString(attrs,'dstaddr') AS dst,
       0                                  AS bytes,
       count()                            AS obs,
       groupUniqArray(JSONExtractString(attrs,'provider')) AS providers
  FROM netops.corr_signals
 WHERE source = 'cloud'
   AND kind = 'cloud_flow_log'
   AND JSONExtractString(attrs,'action') = 'REJECT'
   AND ts > now() - INTERVAL %d HOUR
   AND JSONExtractString(attrs,'srcaddr') != ''
   AND JSONExtractString(attrs,'dstaddr') != ''
 GROUP BY src, dst
 ORDER BY obs DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, windowHours, limit, scope)
}

// ── pure graph builder ────────────────────────────────────────────────────────

// serviceMapNoise reports whether an observed pair is network plumbing rather
// than service traffic (the dependency-map honesty invariant, mirror of
// isDependencyNoise): self-talk, empty peers, and multicast / broadcast /
// link-local / unspecified destinations never appear on the map.
func serviceMapNoise(src, dst string) bool {
	if src == "" || dst == "" || src == dst {
		return true
	}
	ip := net.ParseIP(dst)
	if ip == nil {
		return false // hostname-shaped peers are left to the resolver
	}
	if ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
		return true
	}
	return false
}

// BuildServiceMap folds aggregated pair + reject rows into the dependency
// graph. Pure: the resolver closes over the caller's tenant-scoped identity
// map + inventory; rows are already tenant-bounded by the SQL scope.
func BuildServiceMap(pairs, rejects []FlowPairRow, resolve func(string) (string, bool), maxUnattributed int) ServiceMapGraph {
	if resolve == nil {
		resolve = func(string) (string, bool) { return "", false }
	}

	// Pass 1 — resolve every distinct address once; rank unresolved by bytes so
	// the unattributed node budget keeps the loudest endpoints.
	type endpoint struct {
		service  string
		resolved bool
		bytes    float64
	}
	eps := map[string]*endpoint{}
	see := func(addr string, bytes float64) {
		e, ok := eps[addr]
		if !ok {
			svc, res := resolve(addr)
			e = &endpoint{service: svc, resolved: res}
			eps[addr] = e
		}
		e.bytes += bytes
	}
	for _, p := range pairs {
		if serviceMapNoise(p.Src, p.Dst) {
			continue
		}
		see(p.Src, p.Bytes)
		see(p.Dst, p.Bytes)
	}
	for _, p := range rejects {
		if serviceMapNoise(p.Src, p.Dst) {
			continue
		}
		see(p.Src, 0)
		see(p.Dst, 0)
	}

	resolvedCount, unresolved := 0, make([]string, 0, len(eps))
	for addr, e := range eps {
		if e.resolved {
			resolvedCount++
		} else {
			unresolved = append(unresolved, addr)
		}
	}
	sort.Slice(unresolved, func(i, j int) bool {
		if eps[unresolved[i]].bytes != eps[unresolved[j]].bytes {
			return eps[unresolved[i]].bytes > eps[unresolved[j]].bytes
		}
		return unresolved[i] < unresolved[j]
	})
	if maxUnattributed < 0 {
		maxUnattributed = 0
	}
	kept := unresolved
	if len(kept) > maxUnattributed {
		kept = kept[:maxUnattributed]
	}
	keptUnresolved := make(map[string]bool, len(kept))
	for _, a := range kept {
		keptUnresolved[a] = true
	}

	// nodeID maps an address onto its graph node id ("" = beyond the
	// unattributed budget → its pairs are dropped and counted in Meta).
	nodeID := func(addr string) string {
		e := eps[addr]
		if e.resolved {
			return "svc:" + e.service
		}
		if keptUnresolved[addr] {
			return "ip:" + addr
		}
		return ""
	}

	// Pass 2 — fold pairs into nodes + edges.
	nodes := map[string]*ServiceMapNode{}
	ensureNode := func(addr string) *ServiceMapNode {
		id := nodeID(addr)
		if id == "" {
			return nil
		}
		n, ok := nodes[id]
		if !ok {
			e := eps[addr]
			label := e.service
			kind := "service"
			if !e.resolved {
				label, kind = addr, "endpoint"
			}
			n = &ServiceMapNode{ID: id, Label: label, Kind: kind, Resolved: e.resolved, Providers: []string{}}
			nodes[id] = n
		}
		return n
	}
	addProviders := func(dst *[]string, provs []string) {
		for _, p := range provs {
			if p == "" {
				continue
			}
			found := false
			for _, have := range *dst {
				if have == p {
					found = true
					break
				}
			}
			if !found {
				*dst = append(*dst, p)
			}
		}
		sort.Strings(*dst)
	}

	type edgeKey struct{ src, dst string }
	edges := map[edgeKey]*ServiceMapEdge{}
	pairSignals := 0
	fold := func(p FlowPairRow, blocked bool) {
		if serviceMapNoise(p.Src, p.Dst) {
			return
		}
		sn, dn := ensureNode(p.Src), ensureNode(p.Dst)
		if sn == nil || dn == nil || sn.ID == dn.ID {
			return // beyond the unattributed budget, or intra-service traffic
		}
		if !blocked {
			pairSignals += p.Obs
			sn.Bytes += p.Bytes
			dn.Bytes += p.Bytes
		}
		addProviders(&sn.Providers, p.Providers)
		addProviders(&dn.Providers, p.Providers)
		k := edgeKey{sn.ID, dn.ID}
		e, ok := edges[k]
		if !ok {
			e = &ServiceMapEdge{SourceService: sn.ID, DestService: dn.ID, Relationship: "talks_to", Providers: []string{}}
			edges[k] = e
		}
		if blocked {
			e.Blocked = true
			e.BlockedCount += p.Obs
		} else {
			e.Bytes += p.Bytes
			e.PairCount++
		}
		addProviders(&e.Providers, p.Providers)
	}
	for _, p := range pairs {
		fold(p, false)
	}
	for _, p := range rejects {
		fold(p, true)
	}

	outNodes := make([]ServiceMapNode, 0, len(nodes))
	for _, n := range nodes {
		outNodes = append(outNodes, *n)
	}
	sort.Slice(outNodes, func(i, j int) bool {
		if outNodes[i].Bytes != outNodes[j].Bytes {
			return outNodes[i].Bytes > outNodes[j].Bytes
		}
		return outNodes[i].ID < outNodes[j].ID
	})
	outEdges := make([]ServiceMapEdge, 0, len(edges))
	for _, e := range edges {
		outEdges = append(outEdges, *e)
	}
	sort.Slice(outEdges, func(i, j int) bool {
		if outEdges[i].Bytes != outEdges[j].Bytes {
			return outEdges[i].Bytes > outEdges[j].Bytes
		}
		if outEdges[i].SourceService != outEdges[j].SourceService {
			return outEdges[i].SourceService < outEdges[j].SourceService
		}
		return outEdges[i].DestService < outEdges[j].DestService
	})

	return ServiceMapGraph{
		Nodes: outNodes,
		Edges: outEdges,
		Meta: ServiceMapMeta{
			PairSignals:         pairSignals,
			ResolvedEndpoints:   resolvedCount,
			UnresolvedEndpoints: len(unresolved),
			UnattributedShown:   len(kept),
			UnattributedDropped: len(unresolved) - len(kept),
		},
	}
}
