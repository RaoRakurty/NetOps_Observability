package main

import (
	"context"
	"encoding/json"
	"fmt"
	"netops/backend/internal/seam"
	"os"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/collectors"
	"netops/backend/internal/chschema"
	"netops/backend/pathgraph"
)

// path_ingest.go — the prober's traceroute output → PathObservation + ordered
// PathHops (frozen contract §2.3/§2.4), with every hop resolved through the §3
// RANKED resolver, stamped with seam membership, and carrying the explicit
// transformation (tunnel_ingress/egress) at the seam.
//
// Invariants this file exists to hold:
//   - ONE NEW IMMUTABLE OBSERVATION PER RUN. Nothing is ever updated in place; a
//     route change is a new observation and the history stays queryable (§8).
//   - A NON-RESPONDING HOP IS PRESERVED. The prober delivers it with an empty IP;
//     it is stored as state=missing with no address. It is never dropped and the
//     gap is never bridged (§2.4) — which is the difference between "we don't know"
//     and a fabricated adjacency.
//   - NO TOKEN EVER BECOMES AN EDGE. Hop identity comes from the resolver; the
//     rDNS name we happen to have is passed as rank-7 CANDIDATE material and lands
//     in candidate_ref, which no edge builder reads.

// pathIngestCfg is the ingester's provenance + vantage configuration (§1). It is
// operator-supplied, never inferred from the data.
// The ingest derivation core moved to pathgraph/ingest.go (Phase-2 W2.3).
type (
	pathIngestCfg = pathgraph.IngestConfig
	netContext    = pathgraph.NetContext
	seamIndex     = pathgraph.SeamIndex
	pathRecords   = pathgraph.Records
)

// pathIngestConfigFromEnv reads the ingester's provenance block. Defaults are the
// honest ones: platform tenant, live class, prod environment.
func pathIngestConfigFromEnv(now time.Time) pathIngestCfg {
	dc := envOr("PATH_GRAPH_DATA_CLASS", pathgraph.DataClassLive)
	if !pathgraph.ValidDataClass(dc) {
		dc = pathgraph.DataClassLive
	}
	cfg := pathIngestCfg{
		Tenant:         normTenant(os.Getenv("PATH_GRAPH_TENANT")),
		DataClass:      dc,
		Environment:    envOr("PATH_GRAPH_ENVIRONMENT", "prod"),
		ScenarioID:     os.Getenv("PATH_GRAPH_SCENARIO_ID"),
		ProducerID:     envOr("PATH_GRAPH_PRODUCER_ID", "prober"),
		VantageID:      envOr("PATH_GRAPH_VANTAGE_ID", "prober"),
		VantageAddress: os.Getenv("PATH_GRAPH_VANTAGE_ADDRESS"),
		Now:            now,

		DefaultVantageID: envOr("PATH_GRAPH_VANTAGE_ID", "prober"),
		VantageAddrFor:   vantageAddressFor,
	}
	if cfg.VantageAddress == "" {
		// The per-vantage map (PATH_GRAPH_VANTAGE_ADDRESSES) is the single source of
		// truth: the default vantage's own address comes from its entry there, so the
		// operator declares each vantage exactly once. The singular env stays as an
		// explicit override.
		cfg.VantageAddress = vantageAddressFor(cfg.VantageID)
	}
	return cfg
}

func vantageAddressFor(vantage string) string {
	for _, part := range strings.Split(os.Getenv("PATH_GRAPH_VANTAGE_ADDRESSES"), ",") {
		part = strings.TrimSpace(part)
		name, addr, ok := strings.Cut(part, "=")
		if !ok {
			name, addr, ok = strings.Cut(part, ":")
		}
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), vantage) {
			return strings.TrimSpace(addr)
		}
	}
	return ""
}

// ── fact assembly from the live inventories ──────────────────────────────────

// pathFactSource is the DI seam (§5 "interfaces for all external dependencies"):
// the resolver's fact base, per tenant. The default implementation reads the real
// inventories; tests inject a fixture.
type pathFactSource interface {
	Facts(ctx context.Context, tenant string, at time.Time) (pathgraph.PathFacts, netContext, error)
}

// serverPathFacts assembles the §3 fact base from what the platform actually
// discovers today:
//
//	rank 2  ← the cloud NIC/ENI inventory (private_ips + network_interface_ids per
//	          resource) — this is what binds 10.60.10.10 to the AWS app host.
//	rank 3  ← the device interface registry (SNMP/gNMI-discovered ip → device/ifName).
//	rank 4  ← application telemetry that names its own service + host
//	          (netops.app_identities: dst_ip → canonical app).
//	rank 5  ← NOT WIRED. There is no flow/NAT session source in the platform yet, so
//	          SessionSourceAvailable=false and the API reports the blind spot instead
//	          of pretending the path has no translation. We do not fake a source.
//	rank 6  ← the discovered cloud route tables / Azure UDRs (INFERRED, supporting).
//	rank 7  ← rDNS/hostnames, carried as candidates only.
type serverPathFacts struct{ s *server }

func (f serverPathFacts) Facts(ctx context.Context, tenant string, at time.Time) (pathgraph.PathFacts, netContext, error) {
	s := f.s
	topos, err := cloud.LoadTopologiesLayered(os.Getenv("CLOUD_FIXTURES_DIR"), os.Getenv("CLOUD_RUNTIME_DIR"))
	if err != nil {
		logWarn("pathgraph", "cloud topology load failed", map[string]any{"err": err.Error()})
	}
	nc := pathgraph.NewNetContext(topos, os.Getenv("PATH_GRAPH_LOCAL_CONTEXTS"), envOr("PATH_GRAPH_DEFAULT_CONTEXT", "default"))
	facts := pathgraph.PathFacts{SessionSourceAvailable: false}
	dataClass := envOr("PATH_GRAPH_DATA_CLASS", pathgraph.DataClassLive)
	if !pathgraph.ValidDataClass(dataClass) {
		dataClass = pathgraph.DataClassLive
	}

	// rank 2 — cloud NIC/ENI inventory.
	if s.cloud != nil {
		res, err := s.cloud.ListResources(ctx, tenant, false)
		if err != nil {
			return facts, nc, err
		}
		for _, r := range res {
			eni := ""
			if len(r.NetworkInterfaceIDs) > 0 {
				eni = r.NetworkInterfaceIDs[0]
			}
			for _, ip := range r.PrivateIPs {
				kind := cloudEndpointKind(r, topos, ip)
				facts.NICBindings = append(facts.NICBindings, pathgraph.NICBinding{
					TenantID: tenant, Address: ip, NetworkContext: nc.Of(ip), ResourceID: r.ResourceID,
					InterfaceID: eni, Kind: kind, Service: r.AppName,
					Window:      pathgraph.Window{From: r.DiscoveredAt},
					EvidenceRef: "cloud_inventory:" + r.ResourceID, DataClass: dataClass, ObservedAt: r.LastSeenAt,
				})
			}
		}
	}

	// rank 3 — device interface registry (tenant-scoped through the device inventory).
	fetchIfAddr := s.wanIfAddr
	if fetchIfAddr == nil {
		fetchIfAddr = collectors.FetchIfAddrMap
	}
	ifaddr, _ := fetchIfAddr(ctx) // empty when the collector is off — degrade, never fail
	if len(ifaddr) > 0 && s.discovery != nil {
		visible := map[string]bool{}
		for _, d := range s.discovery.Devices() {
			if d.ID != "" && deviceTenant(d) == tenant {
				visible[d.ID] = true
			}
		}
		for devID, byIP := range ifaddr {
			if !visible[devID] {
				continue // another tenant's device is not even a candidate (§6.1)
			}
			for ip, ifName := range byIP {
				facts.InterfaceBindings = append(facts.InterfaceBindings, pathgraph.InterfaceBinding{
					TenantID: tenant, Address: ip, NetworkContext: nc.Of(ip), DeviceID: devID,
					InterfaceID: ifName, EvidenceRef: "if_inventory:" + devID + ":" + ifName,
					DataClass: dataClass, ObservedAt: at,
				})
			}
		}
	}

	// rank 4 — application telemetry that names its own service + host.
	facts.AppBindings = append(facts.AppBindings, s.appEndpointBindings(ctx, tenant, nc, dataClass, at)...)

	// rank 6 — the INFERRED cloud route relations (supporting only, never an edge).
	for _, t := range topos {
		for _, e := range t.Edges {
			facts.Routes = append(facts.Routes, pathgraph.RouteRelation{
				TenantID: tenant, NetworkContext: nc.Of(nextHopAddr(t, e)), FromSubnet: e.FromSubnet,
				FromSubnetName: e.FromSubnetName, Destination: e.Destination, ToRef: e.To, ToKind: e.ToKind,
				RouteTable:  firstNonEmptyStr(e.RouteTableName, e.ViaRouteTable),
				EvidenceRef: "cloud_route:" + e.ViaRouteTable + ":" + e.Destination,
				DataClass:   dataClass, ObservedAt: at,
			})
		}
	}
	return facts, nc, nil
}

// nextHopAddr resolves a route's next hop to an address when the topology knows one
// (AWS points at a resource id; Azure UDRs point straight at an IP).
func nextHopAddr(t cloud.Topology, e cloud.TopoEdge) string {
	for _, n := range t.Nodes {
		if n.ID == e.To {
			return n.PrivateIP
		}
	}
	return e.To
}

// cloudEndpointKind labels a cloud resource's endpoint. The route table's declared
// next-hop kind (nva / nat_gateway / …) wins, because that is the cloud's OWN
// statement about the resource's role; otherwise an instance is an app endpoint.
func cloudEndpointKind(r cloud.CloudResource, topos []cloud.Topology, ip string) string {
	for _, t := range topos {
		switch t.NodeKindOf(r.ResourceID) {
		case "nva":
			return pathgraph.KindNVA
		case "nat_gateway", "internet_gateway", "vpn_gateway", "vpc_endpoint":
			return pathgraph.KindCloudEdge
		}
		switch t.NodeKindOf(ip) {
		case "nva":
			return pathgraph.KindNVA
		case "nat_gateway", "internet_gateway", "vpn_gateway", "vpc_endpoint":
			return pathgraph.KindCloudEdge
		}
	}
	if strings.Contains(r.ResourceType, "instance") || strings.Contains(r.ResourceType, "vm") {
		return pathgraph.KindAppEndpoint
	}
	return pathgraph.KindServiceEndpoint
}

// appEndpointBindings reads the rank-4 facts: application telemetry that declares
// its own listen endpoint. netops.app_identities is the platform's fused identity
// table (dst_ip → canonical app) — the application naming ITSELF at an address.
// Best-effort: no ClickHouse (dev/file backend) → no rank-4 facts, and the API
// honestly reports an unresolved service rather than guessing one.
func (s *server) appEndpointBindings(ctx context.Context, tenant string, nc netContext, dataClass string, at time.Time) []pathgraph.AppBinding {
	if envOr("CLICKHOUSE_URL", "") == "" {
		return nil
	}
	sql := `SELECT dst_ip, app, ` + chschema.ISO("max(fused_at)") + ` AS last_seen
  FROM netops.app_identities
 WHERE app != 'unknown' AND app != '' AND dst_ip != ''
 GROUP BY dst_ip, app
 ORDER BY last_seen DESC
 LIMIT 500
 FORMAT JSON`
	rows, err := chSelect(ctx, pathgraph.ScopeFor(tenant, false), sql, "worker:pathgraph-facts")
	if err != nil {
		logWarn("pathgraph", "app-identity facts unavailable", map[string]any{"err": err.Error()})
		return nil
	}
	out := make([]pathgraph.AppBinding, 0, len(rows))
	for _, r := range rows {
		ip, app := str(r["dst_ip"]), str(r["app"])
		if ip == "" || app == "" {
			continue
		}
		out = append(out, pathgraph.AppBinding{
			TenantID: tenant, Service: app, Address: ip, NetworkContext: nc.Of(ip),
			Window:      pathgraph.Window{From: at.Add(-24 * time.Hour)},
			EvidenceRef: "app_identity:" + app + "@" + ip, DataClass: dataClass, ObservedAt: at,
		})
	}
	return out
}

// ── the ingest loop ──────────────────────────────────────────────────────────

// startPathGraphIngest converts the prober's traceroutes into contract objects on a
// timer. Opt-in (FEATURE_PATH_GRAPH=true) and dormant otherwise, like every other
// collector-facing feature.
func (s *server) startPathGraphIngest(ctx context.Context) {
	if !envBool("FEATURE_PATH_GRAPH") || s.pathGraph == nil {
		return
	}
	every := 60 * time.Second
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			if err := s.ingestPathsOnce(ctx); err != nil {
				logWarn("pathgraph", "path ingest cycle failed", map[string]any{"err": err.Error()})
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// ingestPathsOnce reads the current prober output and writes ONE new immutable
// observation per path. Idempotence is by construction: a new run is a new row, and
// re-reading the same prober snapshot writes a new observation of the same shape —
// which is exactly what "every measurement run produces a new PathObservation"
// means. (The prober only republishes on a completed run.)
func (s *server) ingestPathsOnce(ctx context.Context) error {
	paths, err := s.currentProbePaths(ctx)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}
	cfg := pathIngestConfigFromEnv(time.Now().UTC())
	src := s.pathFacts
	if src == nil {
		src = serverPathFacts{s}
	}
	facts, nc, err := src.Facts(ctx, cfg.Tenant, cfg.Now)
	if err != nil {
		return err
	}
	var seams []seam.Seam
	if s.seams != nil {
		seams, err = s.seams.List(ctx, cfg.Tenant, false, "active", "")
		if err != nil {
			// ABORT the cycle — do not ingest unstamped. Path observations are
			// IMMUTABLE: proceeding with an empty seam index stamps SeamID="" on
			// every hop of this window, and those rows are never rewritten. Days
			// later the RCA spine reports "no seam ownership" as a durable,
			// evidence-backed-looking fact, and the history-based repair path
			// cannot fix it because the "prior complete observation" it consults
			// is itself unstamped. A skipped window is recoverable (the next
			// cycle re-reads the same probe paths); a falsely-stamped one is not.
			// A NIL store is different and still fine: seams are optional, and
			// "not configured" genuinely means no seam crossings to record.
			return fmt.Errorf("seam inventory unavailable — refusing to ingest "+
				"unstamped path observations (they are immutable): %w", err)
		}
	}
	si := pathgraph.BuildSeamIndex(seams)

	written := 0
	for _, p := range paths {
		recs, err := pathgraph.BuildRecords(cfg, facts, si, nc, p)
		if err != nil {
			logWarn("pathgraph", "skipping unusable probe path", map[string]any{"err": err.Error()})
			continue
		}
		if err := s.persistPathRecords(ctx, recs); err != nil {
			logWarn("pathgraph", "path persist failed", map[string]any{"err": err.Error(), "dst": p.Dst})
			continue
		}
		written++
	}
	logInfo("pathgraph", "path observations written", map[string]any{"observations": written, "paths": len(paths)})
	return nil
}

// persistPathRecords writes the registries then the immutable run, in that order:
// an observation whose endpoints are not yet registered would render as unresolved.
func (s *server) persistPathRecords(ctx context.Context, r pathRecords) error {
	if r.SrcEndpoint.Address != "" {
		if err := s.pathGraph.UpsertEndpoint(ctx, r.SrcEndpoint); err != nil {
			return err
		}
	}
	if err := s.pathGraph.UpsertEndpoint(ctx, r.DstEndpoint); err != nil {
		return err
	}
	if err := s.pathGraph.UpsertPathDefinition(ctx, r.Definition); err != nil {
		return err
	}
	return s.pathGraph.AppendObservation(ctx, r.Definition, r.Observation, r.Hops)
}

// currentProbePaths reads the prober's latest traceroutes from whichever transport
// is wired (the sidecar's shared file, the key-value publish, or the in-process
// collector) — the same precedence handleProbePaths uses.
func (s *server) currentProbePaths(ctx context.Context) ([]collectors.PathResult, error) {
	if collectors.RedisAddr() != "" {
		// MERGED across vantages: the LAN vantage's client-anchored trace and the WAN
		// prober's edge-anchored trace are BOTH ingested, as distinct paths.
		if paths, err := collectors.FetchProbePathsAll(ctx); err == nil && len(paths) > 0 {
			return s.mergedProbePaths(paths), nil
		}
	}
	if path := os.Getenv("PROBE_PATHS_FILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-configured path
			var out []collectors.PathResult
			if err := json.Unmarshal(data, &out); err == nil {
				return s.mergedProbePaths(out), nil
			}
		}
	}
	return s.mergedProbePaths(collectors.Paths.All()), nil
}
