package pathgraph

// ingest.go — the prober-path → immutable observation/hop derivation
// (Phase-2 W2.3, extracted from package main's path_ingest.go): the ingest
// provenance config, the network-context mapper (§2.1: an address is
// meaningless without one), the seam index with its multi-seam disambiguation
// rule, BuildRecords (the contract's pure heart) and the hop-kind
// classification. The env constructor, fact assembly from live inventories,
// the ingest loop and persistence stay in main.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/collectors"
	"netops/backend/internal/applog"
	"netops/backend/internal/seam"
)

type IngestConfig struct {
	Tenant         string
	DataClass      string // live | synthetic | replay | lab
	Environment    string
	ScenarioID     string
	RunID          string
	ProducerID     string
	VantageID      string
	VantageAddress string // the client/vantage the measurement starts at
	Now            time.Time

	// DefaultVantageID is the ingester's own vantage (env-resolved by main);
	// VantageAddrFor resolves an operator-declared source address for a named
	// remote vantage. Injected so this package reads no environment.
	DefaultVantageID string
	VantageAddrFor   func(vantage string) string
}

// firstNonEmptyStr returns the first non-blank value (duplicated).
func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// randHex mints a fresh id (main's helper, duplicated at the boundary).
func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "t" + time.Now().UTC().Format("150405.000000000")
	}
	return hex.EncodeToString(b)
}

// ── network context (§2.1: an address is meaningless without one) ────────────

// NetContext maps an address to its network context (VPC / VNet / VRF / LAN
// segment). Cloud prefixes come from the DISCOVERED cloud topology (route-table
// export); on-prem prefixes are operator-declared via PATH_GRAPH_LOCAL_CONTEXTS
// ("lab-lan:172.40.40.0/24,lab-wan:10.70.245.0/24"). Anything unmapped falls back
// to a single named default — an honest "we don't segment this space", never a
// silent cross-context join (the tenant wall still holds either way).
type NetContext struct {
	topos    []cloud.Topology
	local    []localContext
	fallback string
}

type localContext struct {
	name   string
	prefix netip.Prefix
}

func NewNetContext(topos []cloud.Topology, spec, fallback string) NetContext {
	if strings.TrimSpace(fallback) == "" {
		fallback = "default"
	}
	nc := NetContext{topos: topos, fallback: fallback}
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
			applog.Warn("pathgraph", "ignoring bad PATH_GRAPH_LOCAL_CONTEXTS entry", map[string]any{"entry": part})
			continue
		}
		nc.local = append(nc.local, localContext{name: strings.TrimSpace(name), prefix: p})
	}
	return nc
}

// Of resolves an address to its network context.
func (n NetContext) Of(addr string) string {
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

// SeamSide names which side of an ownership seam an endpoint sits on. The seam
// inventory already carries the endpoints (on_prem / provider_edge / local /
// remote / dst); we do not re-derive them from addresses.
type SeamSide struct {
	SeamID   string
	SeamType string
	Near     bool     // true = the enterprise-owned side (on_prem/local/a_ip)
	FarSide  []string // the OTHER side's addresses — the disambiguator when one address terminates several seams
}

// SeamIndex is address → the seam sides that address terminates, built from the
// ACTIVE seam inventory. An address may terminate SEVERAL seams (the lab edge
// 10.70.245.122 is the near end of both the AWS and the Azure VPN) — the index
// keeps every candidate and the stamper disambiguates per path.
type SeamIndex map[string][]SeamSide

// seamEndpointSide classifies a seam endpoint KEY. Only known endpoint-address
// keys are indexed; anything else (names, interfaces, probe_target, …) is skipped —
// indexing a non-endpoint value would fabricate seam membership (§5).
var seamNearKeys = map[string]bool{"on_prem": true, "local": true, "a_ip": true}
var seamFarKeys = map[string]bool{"remote": true, "b_ip": true, "b_public_ip": true, "cloud": true}

func BuildSeamIndex(seams []seam.Seam) SeamIndex {
	idx := SeamIndex{}
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
			idx[a] = append(idx[a], SeamSide{SeamID: s.SeamID, SeamType: s.SeamType, Near: true, FarSide: far})
		}
		for _, a := range far {
			idx[a] = append(idx[a], SeamSide{SeamID: s.SeamID, SeamType: s.SeamType, Near: false, FarSide: near})
		}
	}
	return idx
}

// TunnelSeamTypes are the seam types where crossing the seam IS a tunnel
// transformation (the packet is encapsulated). DIA and CLOUD_BACKBONE are not
// tunnels — claiming one there would be a fabricated transformation.
var TunnelSeamTypes = map[string]bool{"VPN": true, "SDWAN": true, "DX": true}

// transformAt returns the explicit transformation recorded on a hop that sits on a
// seam: ingress on the near side, egress on the far side. Nothing else is inferred.
//
// When the address terminates SEVERAL seams (a shared enterprise edge), the path
// itself disambiguates: the seam actually crossed is the one whose far side also
// appears among this path's hops. If that still leaves zero or several candidates,
// NO seam is stamped — an edge that cannot state its evidence is not emitted (§5);
// a wrong seam id would send the NOC to the wrong tunnel.
func (si SeamIndex) TransformAt(addr string, hopAddrs map[string]bool) (seamID, transformation string) {
	cands := si[strings.ToLower(strings.TrimSpace(addr))]
	if len(cands) > 1 {
		var onPath []SeamSide
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
		return "", TransformNone
	}
	s := cands[0]
	if !TunnelSeamTypes[s.SeamType] {
		return s.SeamID, TransformNone
	}
	if s.Near {
		return s.SeamID, TransformTunnelIngress
	}
	return s.SeamID, TransformTunnelEgress
}

// ── probe → contract records (PURE: no I/O, fully unit-tested) ───────────────

// Records is one measurement run, fully modelled.
type Records struct {
	Definition  PathDefinition
	Observation PathObservation
	Hops        []PathHop
	SrcEndpoint Endpoint
	DstEndpoint Endpoint
	Service     *ServiceTail
	Supporting  map[int][]SupportingRel
}

// BuildRecords converts ONE prober traceroute into the contract's objects.
// Deterministic given (cfg, facts, seams, contexts, probe) except for the freshly
// minted ids — which is exactly what an immutable per-run record needs.
func BuildRecords(cfg IngestConfig, facts PathFacts, si SeamIndex, nc NetContext, p collectors.PathResult) (Records, error) {
	if strings.TrimSpace(p.Dst) == "" {
		return Records{}, errors.New("probe path has no destination")
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
		if cfg.VantageAddress != "" && v != cfg.DefaultVantageID {
			cfg.VantageAddress = ""
			if cfg.VantageAddrFor != nil {
				cfg.VantageAddress = cfg.VantageAddrFor(v)
			}
		}
	}
	observedAt := p.TS
	if observedAt.IsZero() {
		observedAt = cfg.Now
	}
	protocol := "icmp"
	method := MethodTracerouteICMP
	if strings.EqualFold(p.Method, "tcp") {
		protocol = "tcp"
		method = MethodTracerouteTCP
	}
	runID := cfg.RunID
	if runID == "" {
		runID = "run-" + randHex(8) // §2.3: run_id is REQUIRED on an observation
	}
	prov := func() Provenance {
		return Provenance{
			TenantID: cfg.Tenant, DataClass: cfg.DataClass, Environment: cfg.Environment,
			ScenarioID: cfg.ScenarioID, RunID: runID, ProducerID: cfg.ProducerID,
			ProvenanceID: "pv-" + randHex(12),
		}
	}

	srcCtx := nc.Of(cfg.VantageAddress)
	dstCtx := nc.Of(p.Dst)

	// Endpoints: src (the vantage/client) and dst. Both are BINDINGS — resolved by
	// the ranked resolver, never assumed.
	srcRes := facts.Resolve(Query{
		TenantID: cfg.Tenant, Address: cfg.VantageAddress, NetworkContext: srcCtx, At: observedAt,
		IncludeNonLive: cfg.DataClass != DataClassLive,
	})
	dstRes := facts.Resolve(Query{
		TenantID: cfg.Tenant, Address: p.Dst, NetworkContext: dstCtx, At: observedAt,
		IncludeNonLive: cfg.DataClass != DataClassLive,
	})

	srcEP := Endpoint{
		EndpointID: EndpointID(cfg.Tenant, cfg.VantageAddress, srcCtx), Address: cfg.VantageAddress,
		AddressFamily: AddressFamily(cfg.VantageAddress), NetworkContext: srcCtx, Kind: KindClient,
		ResolvedEntityRef: srcRes.EntityRef, ResolutionMethod: srcRes.Method, Confidence: srcRes.Confidence,
		ValidFrom: observedAt, EvidenceRef: firstNonEmptyStr(srcRes.EvidenceRef, "probe:"+cfg.VantageID),
		Provenance: prov(),
	}
	dstKind := KindUnknown
	if dstRes.Authoritative {
		dstKind = firstNonEmptyStr(dstRes.Kind, KindAppEndpoint)
	}
	dstEP := Endpoint{
		EndpointID: EndpointID(cfg.Tenant, p.Dst, dstCtx), Address: p.Dst,
		AddressFamily: AddressFamily(p.Dst), NetworkContext: dstCtx, Kind: dstKind,
		ResolvedEntityRef: dstRes.EntityRef, ResolutionMethod: dstRes.Method, Confidence: dstRes.Confidence,
		ValidFrom: observedAt, EvidenceRef: firstNonEmptyStr(dstRes.EvidenceRef, "probe:"+cfg.VantageID),
		Provenance: prov(),
	}

	// §2.2 — path identity. Any difference in ANY identity field is a different path.
	pathID := PathID(cfg.Tenant, srcEP.EndpointID, dstEP.EndpointID, "forward", protocol, 0, cfg.VantageID, srcCtx)
	def := PathDefinition{
		PathID: pathID, SrcEndpointRef: srcEP.EndpointID, DstEndpointRef: dstEP.EndpointID,
		SrcAddress: cfg.VantageAddress, DstAddress: p.Dst, Direction: "forward", Protocol: protocol,
		VantageID: cfg.VantageID, NetworkContext: srcCtx, Provenance: prov(),
	}

	obsProv := prov()
	obs := PathObservation{
		ObservationID: "ob-" + randHex(12), PathID: pathID, ObservedAt: observedAt, Method: method,
		VantageID: cfg.VantageID, HopCount: len(p.Hops), ContractVersion: ContractVersion,
		Provenance: obsProv,
	}
	obs.Status = StatusPartial
	switch {
	case len(p.Hops) == 0:
		obs.Status = StatusFailed
	case p.Reached:
		obs.Status = StatusComplete
	}

	recs := Records{Definition: def, Observation: obs, SrcEndpoint: srcEP, DstEndpoint: dstEP,
		Supporting: map[int][]SupportingRel{}}

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
		hop := PathHop{
			ObservationID: obs.ObservationID, HopIndex: idx, ObservedAt: observedAt,
			TenantID: cfg.Tenant, DataClass: cfg.DataClass, Transformation: TransformNone,
			ResolutionMethod: MethodUnresolved, Confidence: ConfUnknown,
			Kind: KindUnknown, EvidenceRef: "pv-" + randHex(12),
		}
		if strings.TrimSpace(h.IP) == "" {
			// A NON-RESPONDING HOP. It is a FACT about the path: preserved, addressless,
			// explicitly unknown. Never dropped, never bridged.
			hop.State = HopMissing
			hop.NetworkContext = ""
			recs.Hops = append(recs.Hops, hop)
			continue
		}
		hop.State = HopResponding
		hop.ObservedAddress = h.IP
		hop.RTTms = h.RTTms
		hop.LossPct = h.Loss
		hop.NetworkContext = nc.Of(h.IP)

		res := facts.Resolve(Query{
			TenantID: cfg.Tenant, Address: h.IP, NetworkContext: hop.NetworkContext, At: observedAt,
			// The rDNS name is rank-7 material ONLY. Passing it here is how the resolver
			// can offer it as a candidate lead — and structurally cannot make it an edge.
			Hostname:       h.Host,
			IncludeNonLive: cfg.DataClass != DataClassLive,
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
		seamID, transform := si.TransformAt(h.IP, hopAddrs)
		hop.SeamID = seamID
		hop.Transformation = transform
		if res.Transformation != "" && res.Transformation != TransformNone {
			hop.Transformation = res.Transformation // a rank-5 session stitch is more specific
		}

		hop.Kind = HopKindFor(res, seamID, transform, h.IP, hop.NetworkContext, srcCtx, p.Dst, firstResponding)
		firstResponding = false
		recs.Hops = append(recs.Hops, hop)
	}

	// The service tail — ONLY from rank 4 (the app declares its endpoint) or rank 2
	// (the cloud inventory attributes the resource that owns the IP). There is NO
	// name-similarity path to this node: that is the §10 acceptance requirement.
	if tail := facts.ServiceOf(Query{
		TenantID: cfg.Tenant, Address: p.Dst, NetworkContext: dstCtx, At: observedAt,
		IncludeNonLive: cfg.DataClass != DataClassLive,
	}); tail != nil {
		recs.Service = tail
	}
	return recs, nil
}

// HopKindFor labels a hop. IDENTITY comes from the resolver; the LABEL may also come
// from the seam inventory (which side of the ownership boundary this address sits on)
// and from position (the first responding hop inside the client's own context is the
// LAN gateway). A label never creates an edge, so an inferred label is safe where an
// inferred identity would not be.
func HopKindFor(res Resolution, seamID, transform string, addr, hopCtx, srcCtx, dst string, firstResponding bool) string {
	if res.Kind != "" && res.Authoritative {
		return res.Kind
	}
	if seamID != "" {
		// The stamped transformation already encodes the side: ingress = the
		// enterprise-owned near end (WAN edge), egress = the far end (cloud edge).
		if transform == TransformTunnelIngress {
			return KindWANEdge
		}
		return KindCloudEdge
	}
	if strings.EqualFold(addr, dst) && res.Authoritative {
		return KindAppEndpoint
	}
	if firstResponding && hopCtx == srcCtx {
		return KindLANGateway
	}
	if !res.Authoritative {
		return KindUnknown // unresolved stays unknown (§8)
	}
	return KindTransit
}

// vantageAddressFor resolves a vantage's own source address from the operator's
// declaration: PATH_GRAPH_VANTAGE_ADDRESSES="lan-vantage-1=172.40.40.200,prober=10.70.245.122".
// "=" is the canonical separator (an IPv6 address contains ":"); the legacy
// "vantage:addr" form still parses when the entry has no "=". An undeclared
// vantage returns "" — its client node then renders as an unresolved endpoint
// (honest) instead of inheriting somebody else's address.
func AddressFamily(addr string) string {
	if strings.Contains(addr, ":") {
		return "ipv6"
	}
	return "ipv4"
}
