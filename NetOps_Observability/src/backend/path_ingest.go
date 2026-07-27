package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/collectors"
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
type pathIngestCfg struct {
	Tenant         string
	DataClass      string // live | synthetic | replay | lab
	Environment    string
	ScenarioID     string
	RunID          string
	ProducerID     string
	VantageID      string
	VantageAddress string // the client/vantage the measurement starts at
	Now            time.Time
}

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

// ── network context (§2.1: an address is meaningless without one) ────────────

// netContext maps an address to its network context (VPC / VNet / VRF / LAN
// segment). Cloud prefixes come from the DISCOVERED cloud topology (route-table
// export); on-prem prefixes are operator-declared via PATH_GRAPH_LOCAL_CONTEXTS
// ("lab-lan:172.40.40.0/24,lab-wan:10.70.245.0/24"). Anything unmapped falls back
// to a single named default — an honest "we don't segment this space", never a
// silent cross-context join (the tenant wall still holds either way).
type netContext struct {
	topos    []cloud.Topology
	local    []localContext
	fallback string
}

type localContext struct {
	name   string
	prefix netip.Prefix
}

func newNetContext(topos []cloud.Topology, spec string) netContext {
	nc := netContext{topos: topos, fallback: envOr("PATH_GRAPH_DEFAULT_CONTEXT", "default")}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Canonical form "cidr=name" ("=" is IPv6-safe); legacy "name:cidr" still
		// parses when the entry has no "=".
		var name, cidr string
		var ok bool
		if cidr, name, ok = strings.Cut(part, "="); !ok {
			name, cidr, ok = strings.Cut(part, ":")
		}
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			logWarn("pathgraph", "ignoring bad PATH_GRAPH_LOCAL_CONTEXTS entry", map[string]any{"entry": part})
			continue
		}
		nc.local = append(nc.local, localContext{name: strings.TrimSpace(name), prefix: p})
	}
	return nc
}

// Of resolves an address to its network context.
func (n netContext) Of(addr string) string {
	if addr == "" {
		return n.fallback
	}
	for _, t := range n.topos {
		if c := t.NetworkContextOf(addr); c != "" {
			return c
		}
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(addr)); err == nil {
		for _, lc := range n.local {
			if lc.prefix.Contains(ip) {
				return lc.name
			}
		}
	}
	return n.fallback
}

// ── seam membership ──────────────────────────────────────────────────────────

// seamSide names which side of an ownership seam an endpoint sits on. The seam
// inventory already carries the endpoints (on_prem / provider_edge / local /
// remote / dst); we do not re-derive them from addresses.
type seamSide struct {
	SeamID   string
	SeamType string
	Near     bool     // true = the enterprise-owned side (on_prem/local/a_ip)
	FarSide  []string // the OTHER side's addresses — the disambiguator when one address terminates several seams
}

// seamIndex is address → the seam sides that address terminates, built from the
// ACTIVE seam inventory. An address may terminate SEVERAL seams (the lab edge
// 10.70.245.122 is the near end of both the AWS and the Azure VPN) — the index
// keeps every candidate and the stamper disambiguates per path.
type seamIndex map[string][]seamSide

// seamEndpointSide classifies a seam endpoint KEY. Only known endpoint-address
// keys are indexed; anything else (names, interfaces, probe_target, …) is skipped —
// indexing a non-endpoint value would fabricate seam membership (§5).
var seamNearKeys = map[string]bool{"on_prem": true, "local": true, "a_ip": true}
var seamFarKeys = map[string]bool{"remote": true, "b_ip": true, "b_public_ip": true, "cloud": true}

func buildSeamIndex(seams []Seam) seamIndex {
	idx := seamIndex{}
	for _, s := range seams {
		var near, far []string
		for key, addr := range s.Endpoints {
			addr = strings.ToLower(strings.TrimSpace(addr))
			if addr == "" {
				continue
			}
			if _, err := netip.ParseAddr(addr); err != nil {
				continue // endpoint metadata (names, hosts) is not an address
			}
			switch {
			case seamNearKeys[key]:
				near = append(near, addr)
			case seamFarKeys[key]:
				far = append(far, addr)
			}
		}
		for _, a := range near {
			idx[a] = append(idx[a], seamSide{SeamID: s.SeamID, SeamType: s.SeamType, Near: true, FarSide: far})
		}
		for _, a := range far {
			idx[a] = append(idx[a], seamSide{SeamID: s.SeamID, SeamType: s.SeamType, Near: false, FarSide: near})
		}
	}
	return idx
}

// tunnelSeamTypes are the seam types where crossing the seam IS a tunnel
// transformation (the packet is encapsulated). DIA and CLOUD_BACKBONE are not
// tunnels — claiming one there would be a fabricated transformation.
var tunnelSeamTypes = map[string]bool{"VPN": true, "SDWAN": true, "DX": true}

// transformAt returns the explicit transformation recorded on a hop that sits on a
// seam: ingress on the near side, egress on the far side. Nothing else is inferred.
//
// When the address terminates SEVERAL seams (a shared enterprise edge), the path
// itself disambiguates: the seam actually crossed is the one whose far side also
// appears among this path's hops. If that still leaves zero or several candidates,
// NO seam is stamped — an edge that cannot state its evidence is not emitted (§5);
// a wrong seam id would send the NOC to the wrong tunnel.
func (si seamIndex) transformAt(addr string, hopAddrs map[string]bool) (seamID, transformation string) {
	cands := si[strings.ToLower(strings.TrimSpace(addr))]
	if len(cands) > 1 {
		var onPath []seamSide
		for _, c := range cands {
			for _, far := range c.FarSide {
				if hopAddrs[far] {
					onPath = append(onPath, c)
					break
				}
			}
		}
		cands = onPath
	}
	if len(cands) != 1 {
		return "", pathgraph.TransformNone
	}
	s := cands[0]
	if !tunnelSeamTypes[s.SeamType] {
		return s.SeamID, pathgraph.TransformNone
	}
	if s.Near {
		return s.SeamID, pathgraph.TransformTunnelIngress
	}
	return s.SeamID, pathgraph.TransformTunnelEgress
}

// ── probe → contract records (PURE: no I/O, fully unit-tested) ───────────────

// pathRecords is one measurement run, fully modelled.
type pathRecords struct {
	Definition  pathgraph.PathDefinition
	Observation pathgraph.PathObservation
	Hops        []pathgraph.PathHop
	SrcEndpoint pathgraph.Endpoint
	DstEndpoint pathgraph.Endpoint
	Service     *pathgraph.ServiceTail
	Supporting  map[int][]pathgraph.SupportingRel
}

// buildPathRecords converts ONE prober traceroute into the contract's objects.
// Deterministic given (cfg, facts, seams, contexts, probe) except for the freshly
// minted ids — which is exactly what an immutable per-run record needs.
func buildPathRecords(cfg pathIngestCfg, facts pathgraph.PathFacts, si seamIndex, nc netContext, p collectors.PathResult) (pathRecords, error) {
	if strings.TrimSpace(p.Dst) == "" {
		return pathRecords{}, errors.New("probe path has no destination")
	}
	// MULTI-VANTAGE (§2.2/§8): the path's identity carries the vantage that measured
	// it. When the prober attributed the path (PROBER_ID), that attribution WINS over
	// the ingester's default — otherwise every vantage's traces would collapse into
	// one path_id again, which is precisely the bug the per-vantage publish fixed.
	if v := strings.TrimSpace(p.VantageID); v != "" {
		cfg.VantageID = v
		// A remote vantage measures from ITS OWN address. Only trust an operator-declared
		// source address for the vantage the operator declared it for; otherwise the
		// client end of the spine stays unresolved (honest) rather than borrowed from
		// another prober's vantage.
		if cfg.VantageAddress != "" && v != envOr("PATH_GRAPH_VANTAGE_ID", "prober") {
			cfg.VantageAddress = vantageAddressFor(v)
		}
	}
	observedAt := p.TS
	if observedAt.IsZero() {
		observedAt = cfg.Now
	}
	protocol := "icmp"
	method := pathgraph.MethodTracerouteICMP
	if strings.EqualFold(p.Method, "tcp") {
		protocol = "tcp"
		method = pathgraph.MethodTracerouteTCP
	}
	runID := cfg.RunID
	if runID == "" {
		runID = "run-" + randHex(8) // §2.3: run_id is REQUIRED on an observation
	}
	prov := func() pathgraph.Provenance {
		return pathgraph.Provenance{
			TenantID: cfg.Tenant, DataClass: cfg.DataClass, Environment: cfg.Environment,
			ScenarioID: cfg.ScenarioID, RunID: runID, ProducerID: cfg.ProducerID,
			ProvenanceID: "pv-" + randHex(12),
		}
	}

	srcCtx := nc.Of(cfg.VantageAddress)
	dstCtx := nc.Of(p.Dst)

	// Endpoints: src (the vantage/client) and dst. Both are BINDINGS — resolved by
	// the ranked resolver, never assumed.
	srcRes := facts.Resolve(pathgraph.Query{
		TenantID: cfg.Tenant, Address: cfg.VantageAddress, NetworkContext: srcCtx, At: observedAt,
		IncludeNonLive: cfg.DataClass != pathgraph.DataClassLive,
	})
	dstRes := facts.Resolve(pathgraph.Query{
		TenantID: cfg.Tenant, Address: p.Dst, NetworkContext: dstCtx, At: observedAt,
		IncludeNonLive: cfg.DataClass != pathgraph.DataClassLive,
	})

	srcEP := pathgraph.Endpoint{
		EndpointID: pathgraph.EndpointID(cfg.Tenant, cfg.VantageAddress, srcCtx), Address: cfg.VantageAddress,
		AddressFamily: addressFamily(cfg.VantageAddress), NetworkContext: srcCtx, Kind: pathgraph.KindClient,
		ResolvedEntityRef: srcRes.EntityRef, ResolutionMethod: srcRes.Method, Confidence: srcRes.Confidence,
		ValidFrom: observedAt, EvidenceRef: firstNonEmptyStr(srcRes.EvidenceRef, "probe:"+cfg.VantageID),
		Provenance: prov(),
	}
	dstKind := pathgraph.KindUnknown
	if dstRes.Authoritative {
		dstKind = firstNonEmptyStr(dstRes.Kind, pathgraph.KindAppEndpoint)
	}
	dstEP := pathgraph.Endpoint{
		EndpointID: pathgraph.EndpointID(cfg.Tenant, p.Dst, dstCtx), Address: p.Dst,
		AddressFamily: addressFamily(p.Dst), NetworkContext: dstCtx, Kind: dstKind,
		ResolvedEntityRef: dstRes.EntityRef, ResolutionMethod: dstRes.Method, Confidence: dstRes.Confidence,
		ValidFrom: observedAt, EvidenceRef: firstNonEmptyStr(dstRes.EvidenceRef, "probe:"+cfg.VantageID),
		Provenance: prov(),
	}

	// §2.2 — path identity. Any difference in ANY identity field is a different path.
	pathID := pathgraph.PathID(cfg.Tenant, srcEP.EndpointID, dstEP.EndpointID, "forward", protocol, 0, cfg.VantageID, srcCtx)
	def := pathgraph.PathDefinition{
		PathID: pathID, SrcEndpointRef: srcEP.EndpointID, DstEndpointRef: dstEP.EndpointID,
		SrcAddress: cfg.VantageAddress, DstAddress: p.Dst, Direction: "forward", Protocol: protocol,
		VantageID: cfg.VantageID, NetworkContext: srcCtx, Provenance: prov(),
	}

	obsProv := prov()
	obs := pathgraph.PathObservation{
		ObservationID: "ob-" + randHex(12), PathID: pathID, ObservedAt: observedAt, Method: method,
		VantageID: cfg.VantageID, HopCount: len(p.Hops), ContractVersion: pathgraph.ContractVersion,
		Provenance: obsProv,
	}
	obs.Status = pathgraph.StatusPartial
	switch {
	case len(p.Hops) == 0:
		obs.Status = pathgraph.StatusFailed
	case p.Reached:
		obs.Status = pathgraph.StatusComplete
	}

	recs := pathRecords{Definition: def, Observation: obs, SrcEndpoint: srcEP, DstEndpoint: dstEP,
		Supporting: map[int][]pathgraph.SupportingRel{}}

	// The path's own address set (hops + destination) — the seam disambiguator.
	hopAddrs := map[string]bool{strings.ToLower(strings.TrimSpace(p.Dst)): true}
	for _, h := range p.Hops {
		if ip := strings.ToLower(strings.TrimSpace(h.IP)); ip != "" {
			hopAddrs[ip] = true
		}
	}

	firstResponding := true
	for i, h := range p.Hops {
		idx := h.TTL
		if idx <= 0 {
			idx = i + 1
		}
		hop := pathgraph.PathHop{
			ObservationID: obs.ObservationID, HopIndex: idx, ObservedAt: observedAt,
			TenantID: cfg.Tenant, DataClass: cfg.DataClass, Transformation: pathgraph.TransformNone,
			ResolutionMethod: pathgraph.MethodUnresolved, Confidence: pathgraph.ConfUnknown,
			Kind: pathgraph.KindUnknown, EvidenceRef: "pv-" + randHex(12),
		}
		if strings.TrimSpace(h.IP) == "" {
			// A NON-RESPONDING HOP. It is a FACT about the path: preserved, addressless,
			// explicitly unknown. Never dropped, never bridged.
			hop.State = pathgraph.HopMissing
			hop.NetworkContext = ""
			recs.Hops = append(recs.Hops, hop)
			continue
		}
		hop.State = pathgraph.HopResponding
		hop.ObservedAddress = h.IP
		hop.RTTms = h.RTTms
		hop.LossPct = h.Loss
		hop.NetworkContext = nc.Of(h.IP)

		res := facts.Resolve(pathgraph.Query{
			TenantID: cfg.Tenant, Address: h.IP, NetworkContext: hop.NetworkContext, At: observedAt,
			// The rDNS name is rank-7 material ONLY. Passing it here is how the resolver
			// can offer it as a candidate lead — and structurally cannot make it an edge.
			Hostname:       h.Host,
			IncludeNonLive: cfg.DataClass != pathgraph.DataClassLive,
		})
		hop.ResolutionMethod = res.Method
		hop.Confidence = res.Confidence
		hop.CandidateRef = res.CandidateRef
		if res.Authoritative {
			hop.ResolvedEntityRef = res.EntityRef // ranks 1–5 ONLY
		}
		if len(res.Supporting) > 0 {
			recs.Supporting[hop.HopIndex] = res.Supporting
		}

		// seam membership + the explicit transformation at the seam. The path's own
		// hop set disambiguates a shared seam endpoint (the far side must be on-path).
		seamID, transform := si.transformAt(h.IP, hopAddrs)
		hop.SeamID = seamID
		hop.Transformation = transform
		if res.Transformation != "" && res.Transformation != pathgraph.TransformNone {
			hop.Transformation = res.Transformation // a rank-5 session stitch is more specific
		}

		hop.Kind = hopKindFor(res, seamID, transform, h.IP, hop.NetworkContext, srcCtx, p.Dst, firstResponding)
		firstResponding = false
		recs.Hops = append(recs.Hops, hop)
	}

	// The service tail — ONLY from rank 4 (the app declares its endpoint) or rank 2
	// (the cloud inventory attributes the resource that owns the IP). There is NO
	// name-similarity path to this node: that is the §10 acceptance requirement.
	if tail := facts.ServiceOf(pathgraph.Query{
		TenantID: cfg.Tenant, Address: p.Dst, NetworkContext: dstCtx, At: observedAt,
		IncludeNonLive: cfg.DataClass != pathgraph.DataClassLive,
	}); tail != nil {
		recs.Service = tail
	}
	return recs, nil
}

// hopKindFor labels a hop. IDENTITY comes from the resolver; the LABEL may also come
// from the seam inventory (which side of the ownership boundary this address sits on)
// and from position (the first responding hop inside the client's own context is the
// LAN gateway). A label never creates an edge, so an inferred label is safe where an
// inferred identity would not be.
func hopKindFor(res pathgraph.Resolution, seamID, transform string, addr, hopCtx, srcCtx, dst string, firstResponding bool) string {
	if res.Kind != "" && res.Authoritative {
		return res.Kind
	}
	if seamID != "" {
		// The stamped transformation already encodes the side: ingress = the
		// enterprise-owned near end (WAN edge), egress = the far end (cloud edge).
		if transform == pathgraph.TransformTunnelIngress {
			return pathgraph.KindWANEdge
		}
		return pathgraph.KindCloudEdge
	}
	if strings.EqualFold(addr, dst) && res.Authoritative {
		return pathgraph.KindAppEndpoint
	}
	if firstResponding && hopCtx == srcCtx {
		return pathgraph.KindLANGateway
	}
	if !res.Authoritative {
		return pathgraph.KindUnknown // unresolved stays unknown (§8)
	}
	return pathgraph.KindTransit
}

// vantageAddressFor resolves a vantage's own source address from the operator's
// declaration: PATH_GRAPH_VANTAGE_ADDRESSES="lan-vantage-1=172.40.40.200,prober=10.70.245.122".
// "=" is the canonical separator (an IPv6 address contains ":"); the legacy
// "vantage:addr" form still parses when the entry has no "=". An undeclared
// vantage returns "" — its client node then renders as an unresolved endpoint
// (honest) instead of inheriting somebody else's address.
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

func addressFamily(addr string) string {
	if strings.Contains(addr, ":") {
		return "ipv6"
	}
	return "ipv4"
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
	nc := newNetContext(topos, os.Getenv("PATH_GRAPH_LOCAL_CONTEXTS"))
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
	sql := `SELECT dst_ip, app, ` + chISO("max(fused_at)") + ` AS last_seen
  FROM netops.app_identities
 WHERE app != 'unknown' AND app != '' AND dst_ip != ''
 GROUP BY dst_ip, app
 ORDER BY last_seen DESC
 LIMIT 500
 FORMAT JSON`
	rows, err := chSelect(ctx, chScopeFor(tenant, false), sql, "worker:pathgraph-facts")
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
	var seams []Seam
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
	si := buildSeamIndex(seams)

	written := 0
	for _, p := range paths {
		recs, err := buildPathRecords(cfg, facts, si, nc, p)
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
