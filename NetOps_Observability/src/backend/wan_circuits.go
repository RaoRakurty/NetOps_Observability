package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// WAN interface metrics (WAN path-metrics program).
//
// NO hub/spoke. Every WAN interface gets path metrics on its own, measured to a
// TARGET that is DERIVED per interface — not paired by an operator "hub" intent.
// The old SD-WAN hub-and-spoke circuit mesh has been removed entirely.
//
// Which interfaces are measured:
//   - every interface on a WAN-pattern device (default name pattern below), AND
//   - every interface on ANY device that is directly connected (LLDP/CDP neighbor)
//     to a WAN-pattern device. This is what makes the lab work: the WAN router's
//     interfaces AND the Spine's interface toward the WAN router are both measured.
//
// How the measurement target is derived per interface (ranked, first wins):
//  1. operator NEXT-HOP override (policy.NextHops[device] or [device/ifName]) —
//     the prod ISP next-hop when you know it.
//  2. DIRECTLY-CONNECTED PEER (LLDP/CDP): the neighbor interface's IP. This is the
//     lab case (WAN router ⇄ Spine) and any internal point-to-point link.
//  3. REACHABILITY ANCHOR (public DNS 1.1.1.1 / 8.8.8.8 by default): the prod
//     internet-facing case where the far end is an ISP that speaks no LLDP — you
//     measure internet reachability to a well-known anchor instead.
//
// The per-field SLA (latency/jitter/loss/QoE/availability) is then resolved for
// that target host through the ONE source-agnostic resolver (path_metric_resolver.go,
// the 5-tier measurement-source ranking) — so provenance is identical everywhere.
//
// Endpoints/targets are DERIVED (projected on demand from the interface-IP table ×
// neighbors × policy). Only the policy (operator intent) is persisted (tenantKV).

// defaultWanPattern selects WAN devices by name.
const defaultWanPattern = "wan|edge|gw|dmz"

// mgmtIfPattern matches out-of-band MANAGEMENT interfaces, which are never WAN
// transport. Excluding them is essential: on a shared management segment every
// device is an LLDP/CDP neighbour of every other, so without this filter the WAN
// router's mgmt port pulls the whole fabric in and derives arbitrary "peers".
var mgmtIfPattern = regexp.MustCompile(`(?i)(^|[^a-z])(mgmt|management|oob)|^(ma|me|fxp|em)\d`)

func isMgmtInterface(ifn string) bool { return mgmtIfPattern.MatchString(ifn) }

// defaultAnchors are the reachability anchors used when an interface has no
// directly-connected peer and no configured next-hop (prod internet-facing case).
var defaultAnchors = []string{"1.1.1.1", "8.8.8.8"}

// WanTargetKind is how an interface's measurement target was derived (provenance).
type WanTargetKind string

const (
	WanTargetDirectPeer WanTargetKind = "direct_peer" // LLDP/CDP-connected neighbor (lab, internal P2P)
	WanTargetNextHop    WanTargetKind = "next_hop"     // operator-configured ISP next-hop
	WanTargetAnchor     WanTargetKind = "anchor"       // public-DNS / reachability anchor (prod default)
	WanTargetNone       WanTargetKind = ""             // no target could be derived
)

// Label is the customer-facing kind name (no raw tokens — customer-language rule).
func (k WanTargetKind) Label() string {
	switch k {
	case WanTargetDirectPeer:
		return "Directly-connected peer"
	case WanTargetNextHop:
		return "ISP next-hop"
	case WanTargetAnchor:
		return "Reachability anchor"
	default:
		return "—"
	}
}

// WanEndpoint is one WAN (or WAN-connected) transport interface, with its derived
// measurement target.
type WanEndpoint struct {
	TenantID   string `json:"tenant_id,omitempty"`
	Device     string `json:"device"`
	Interface  string `json:"interface"`       // ifName (Ethernet1)
	Address    string `json:"address"`         // interface IP
	Measurable string `json:"measurable_addr"` // address the OTHER end targets; default = Address
	Site       string `json:"site,omitempty"`
	// ConnectedToWAN marks an interface that was included because it is directly
	// connected to a WAN device (e.g. the lab Spine's link to the WAN router),
	// rather than living on a WAN device itself.
	ConnectedToWAN bool `json:"connected_to_wan,omitempty"`

	// Derived measurement target (no hub/spoke).
	Target      string        `json:"target,omitempty"`       // dst host we measure to
	TargetKind  WanTargetKind `json:"target_kind,omitempty"`  // how the target was derived
	TargetLabel string        `json:"target_label,omitempty"` // customer-facing target description
}

// WanCircuit is one interface → its measurement target (a 1:1 link, NOT a mesh).
// The name is retained for the /api/wan/circuits surface + the echo publisher;
// Remote is the target rendered as an endpoint (its device/if for a direct peer,
// or the anchor address for an anchor target).
type WanCircuit struct {
	TenantID string        `json:"tenant_id,omitempty"`
	ID       string        `json:"id"` // deterministic over (local interface, target)
	Local    WanEndpoint   `json:"local"`
	Remote   WanEndpoint   `json:"remote"`
	Kind     WanTargetKind `json:"kind"`
	Source   string        `json:"source"` // registry
	Enabled  bool          `json:"enabled"`
}

// WanMeasurementPolicy is the per-tenant measurement policy — one row per tenant.
// It replaces the old hub/spoke topology policy: no roles, no mesh mode. All
// operator intent for the WAN interface view lives here.
type WanMeasurementPolicy struct {
	TenantID   string            `json:"tenant_id,omitempty"`
	WanPattern string            `json:"wan_pattern,omitempty"`       // which devices are WAN devices
	Anchors    []string          `json:"anchors,omitempty"`           // reachability anchors (default 1.1.1.1/8.8.8.8)
	NextHops   map[string]string `json:"next_hops,omitempty"`         // device or device/ifName → explicit target (ISP next-hop)
	IncludeConnected *bool        `json:"include_connected,omitempty"` // include ifaces connected to a WAN device (default true)
	UpdatedBy  string            `json:"updated_by,omitempty"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// withDefaults fills empty fields with the safe baseline a tenant gets before it
// has ever saved a policy.
func (p WanMeasurementPolicy) withDefaults() WanMeasurementPolicy {
	if p.WanPattern == "" {
		p.WanPattern = defaultWanPattern
	}
	if len(p.Anchors) == 0 {
		p.Anchors = append([]string(nil), defaultAnchors...)
	}
	if p.IncludeConnected == nil {
		t := true
		p.IncludeConnected = &t
	}
	return p
}

func (p WanMeasurementPolicy) validate() error {
	if p.WanPattern != "" {
		if _, err := regexp.Compile("(?i)" + p.WanPattern); err != nil {
			return fmt.Errorf("wan_pattern is not a valid regex: %w", err)
		}
	}
	return nil
}

func (p WanMeasurementPolicy) includeConnected() bool {
	return p.IncludeConnected == nil || *p.IncludeConnected
}

// ---- policy store (operator intent) — tenantKV, one row per tenant ----

type wanPolicyStore struct {
	kv *tenantKV[WanMeasurementPolicy]
}

func newWanPolicyStore(path string) (*wanPolicyStore, error) {
	if path == "" {
		path = "/data/wan_policy.json"
	}
	kv, err := newTenantKV[WanMeasurementPolicy](path,
		func(p WanMeasurementPolicy) string { return p.TenantID },
		func(p WanMeasurementPolicy) string { return "policy" }) // single row per tenant
	if err != nil {
		return nil, err
	}
	return &wanPolicyStore{kv: kv}, nil
}

// Get returns the tenant's policy (with defaults applied) — never fails closed to
// "no view": an unconfigured tenant gets the measurement baseline.
func (s *wanPolicyStore) Get(tenant string, cross bool) WanMeasurementPolicy {
	if p, ok := s.kv.Get(tenant, cross, "policy"); ok {
		return p.withDefaults()
	}
	return WanMeasurementPolicy{TenantID: tenant}.withDefaults()
}

func (s *wanPolicyStore) Put(p WanMeasurementPolicy) error { return s.kv.Upsert(p) }

// ---- projector: interface-IP table × neighbors × policy → endpoints + targets ----

// wanNeighborIndex indexes directly-connected neighbours by the LOCAL interface
// (deviceID, ifName) → the peer (device id, ifName, measurable IP). Built from the
// merged LLDP/CDP/BGP-LS topology links, joined to the interface-IP table so we
// know the peer's probe-able address.
type wanPeer struct {
	device string // peer device name
	iface  string // peer ifName
	addr   string // peer interface IP (probe target)
}

// wanProject builds the WAN endpoint set (every WAN interface + every interface
// directly connected to a WAN device) with each interface's derived measurement
// target, plus the 1:1 interface→target links. Tenant-scoped: a principal only
// ever sees its own devices' interfaces (the isolation guarantee).
func (s *server) wanProject(ctx context.Context, tenant string, cross bool) ([]WanEndpoint, []WanCircuit) {
	pol := s.wanPolicy.Get(tenant, cross)
	pat := regexp.MustCompile("(?i)" + pol.WanPattern)

	// All devices visible to this principal, id→device and name→id.
	visible := map[string]models.Device{}
	nameToID := map[string]string{}
	wanDev := map[string]bool{} // device id → is a WAN-pattern device
	for _, d := range s.discovery.Devices() {
		if d.ID == "" {
			continue
		}
		if !cross && deviceTenant(d) != tenant {
			continue
		}
		visible[d.ID] = d
		nameToID[strings.ToLower(d.Name)] = d.ID
		if pat.MatchString(d.Name) {
			wanDev[d.ID] = true
		}
	}
	if len(wanDev) == 0 {
		return nil, nil
	}

	fetchIfAddr := s.wanIfAddr
	if fetchIfAddr == nil {
		fetchIfAddr = collectors.FetchIfAddrMap
	}
	ifaddr, _ := fetchIfAddr(ctx) // device → ip → ifName (empty if collector off)

	// ifName → ip, per device (inverse of ifaddr) — for peer-IP resolution.
	ipByDevIf := map[string]map[string]string{}
	for dev, m := range ifaddr {
		inv := map[string]string{}
		for ip, ifn := range m {
			inv[ifn] = ip
		}
		ipByDevIf[dev] = inv
	}

	// Directly-connected neighbours, joined to the peer's interface IP.
	neighbors := s.wanNeighborIndex(ctx, visible, nameToID, ipByDevIf)

	// Which (device, ifName) interfaces are IN SCOPE:
	//   - every interface on a WAN device, PLUS
	//   - (if enabled) every interface directly connected to a WAN device.
	type ifRef struct{ dev, ifn, ip string }
	inScope := map[string]ifRef{} // key = wanIfKey(devID, ifName)
	addIf := func(devID, ifn, ip string) {
		if isMgmtInterface(ifn) {
			return // management ports are never WAN transport
		}
		k := wanIfKey(devID, ifn)
		if _, ok := inScope[k]; !ok {
			inScope[k] = ifRef{devID, ifn, ip}
		}
	}
	for devID := range wanDev {
		for ip, ifn := range ifaddr[devID] {
			addIf(devID, ifn, ip)
		}
	}
	if pol.includeConnected() {
		for k, peer := range neighbors {
			devID, ifn := splitIfKey(k)
			if devID == "" {
				continue
			}
			// Only pull in a NON-WAN device's interface when its peer is a WAN device.
			if wanDev[devID] {
				continue // already covered above
			}
			if id := nameToID[strings.ToLower(peer.device)]; id != "" && wanDev[id] {
				addIf(devID, ifn, ipByDevIf[devID][ifn])
			}
		}
	}

	// Build endpoints with a derived target each.
	var endpoints []WanEndpoint
	for _, ref := range inScope {
		d := visible[ref.dev]
		site := ""
		if b, ok := s.deviceSites.Get(tenant, cross, ref.dev); ok {
			site = b.Site
		}
		ep := WanEndpoint{
			TenantID: deviceTenant(d), Device: d.Name, Interface: ref.ifn,
			Address: ref.ip, Measurable: ref.ip, Site: site,
			ConnectedToWAN: !wanDev[ref.dev],
		}
		ep.Target, ep.TargetKind, ep.TargetLabel = wanDeriveTarget(ref.dev, ref.ifn, neighbors, pol)
		endpoints = append(endpoints, ep)
	}
	sort.Slice(endpoints, func(a, b int) bool {
		if endpoints[a].Device != endpoints[b].Device {
			return endpoints[a].Device < endpoints[b].Device
		}
		return endpoints[a].Interface < endpoints[b].Interface
	})

	// 1:1 interface → target links.
	var circuits []WanCircuit
	for _, ep := range endpoints {
		if ep.Target == "" {
			continue
		}
		remote := WanEndpoint{
			TenantID: ep.TenantID, Measurable: ep.Target, Address: ep.Target,
		}
		switch ep.TargetKind {
		case WanTargetDirectPeer:
			// Fill the peer device/if for display.
			if peer, ok := neighbors[wanIfKey(deviceIDForName(ep.Device, nameToID), ep.Interface)]; ok {
				remote.Device, remote.Interface = peer.device, peer.iface
			}
		case WanTargetAnchor:
			remote.Device = "Internet"
		case WanTargetNextHop:
			remote.Device = "Next-hop"
		}
		circuits = append(circuits, WanCircuit{
			TenantID: ep.TenantID, ID: wanCircuitID(ep, remote), Local: ep, Remote: remote,
			Kind: ep.TargetKind, Source: "registry", Enabled: true,
		})
	}
	return endpoints, circuits
}

// wanNeighborIndex builds (localDevID, localIfName) → peer, from the merged
// topology links, restricted to devices visible to the principal and joined to
// the peer's interface IP. LLDP/CDP carry LocalDevice (id) + RemSysName (name);
// we resolve the peer name to a visible device id and look up its interface IP.
func (s *server) wanNeighborIndex(ctx context.Context, visible map[string]models.Device, nameToID map[string]string, ipByDevIf map[string]map[string]string) map[string]wanPeer {
	fetch := s.wanNeighbors
	if fetch == nil {
		fetch = collectors.FetchTopologyLinks
	}
	links, _ := fetch(ctx)
	out := map[string]wanPeer{}
	for _, l := range links {
		if l.Proto == "bgp_ls" { // BGP-LS is a control-plane view, not a directly-probeable L2 peer
			continue
		}
		if l.LocalDevice == "" || l.LocalPort == "" {
			continue
		}
		if _, ok := visible[l.LocalDevice]; !ok {
			continue // not this principal's device
		}
		peerID := nameToID[strings.ToLower(l.RemSysName)]
		if peerID == "" {
			continue // unknown / cross-tenant peer — skip (never leak another tenant)
		}
		peerAddr := ipByDevIf[peerID][l.RemPort]
		peerName := visible[peerID].Name
		k := wanIfKey(l.LocalDevice, l.LocalPort)
		if _, seen := out[k]; !seen {
			out[k] = wanPeer{device: peerName, iface: l.RemPort, addr: peerAddr}
		}
	}
	return out
}

// wanDeriveTarget picks an interface's measurement target by the ranked strategy:
// operator next-hop override → directly-connected peer → reachability anchor.
func wanDeriveTarget(devID, ifn string, neighbors map[string]wanPeer, pol WanMeasurementPolicy) (string, WanTargetKind, string) {
	// 1. operator next-hop override, keyed by "device/ifName" then "device".
	if pol.NextHops != nil {
		if t := pol.NextHops[devID+"/"+ifn]; t != "" {
			return t, WanTargetNextHop, "Configured next-hop " + t
		}
		if t := pol.NextHops[devID]; t != "" {
			return t, WanTargetNextHop, "Configured next-hop " + t
		}
	}
	// 2. directly-connected peer (LLDP/CDP) with a resolvable IP.
	if peer, ok := neighbors[wanIfKey(devID, ifn)]; ok && peer.addr != "" {
		return peer.addr, WanTargetDirectPeer, "Directly-connected peer " + peer.device + " " + peer.iface
	}
	// 3. reachability anchor (prod internet-facing default).
	anchors := pol.Anchors
	if len(anchors) == 0 {
		anchors = defaultAnchors
	}
	if len(anchors) > 0 && anchors[0] != "" {
		return anchors[0], WanTargetAnchor, "Reachability anchor " + anchors[0]
	}
	return "", WanTargetNone, ""
}

// deviceIDForName resolves a device NAME back to its id (endpoints store the name).
func deviceIDForName(name string, nameToID map[string]string) string {
	return nameToID[strings.ToLower(name)]
}

func wanCircuitID(local, remote WanEndpoint) string {
	h := sha1.Sum([]byte(local.Device + "|" + local.Interface + "|" + remote.Measurable))
	return "wan-" + hex.EncodeToString(h[:6])
}

// ---- interface-target publisher (→ Redis, for the wan-echo collector) ----

// startWANCircuitPublish periodically projects every tenant's interface→target
// links and publishes them to Redis as the wan-echo collector's target list, so
// the prober measures the DERIVED targets. Gated by FEATURE_WAN_ECHO; a no-op
// without it (or without Redis). The prober is platform infrastructure, so it
// probes across tenants; each target carries its tenant label so the metric stays
// scoped.
func (s *server) startWANCircuitPublish(ctx context.Context) {
	if os.Getenv("FEATURE_WAN_ECHO") != "true" || collectors.RedisAddr() == "" {
		return
	}
	interval := envDuration("WAN_ECHO_PUBLISH_INTERVAL", 60*time.Second)
	publish := func() {
		_, circuits := s.wanProject(ctx, TenantGlobal, true)
		targets := make([]collectors.EchoTarget, 0, len(circuits))
		for _, c := range circuits {
			if !c.Enabled || c.Remote.Measurable == "" {
				continue
			}
			targets = append(targets, collectors.EchoTarget{
				CircuitID:    c.ID,
				Tenant:       c.Local.TenantID,
				LocalDevice:  c.Local.Device,
				LocalIf:      c.Local.Interface,
				LocalAddr:    c.Local.Measurable,
				RemoteDevice: c.Remote.Device,
				RemoteIf:     c.Remote.Interface,
				RemoteAddr:   c.Remote.Measurable,
			})
		}
		if err := collectors.PublishWANCircuits(ctx, targets, int(3*interval/time.Second)); err != nil {
			log.Printf("wan-echo: publish targets: %v", err)
			return
		}
		log.Printf("wan-echo: published %d interface target(s)", len(targets))
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		publish()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				publish()
			}
		}
	}()
}

// ---- per-WAN-interface rows: interface × target × resolved SLA × util ----

// WanInterfaceRow is one WAN (or WAN-connected) interface enriched for the table:
// live utilization/status (device_if_*), the derived measurement target + how it
// was derived, and the SLA resolved through the 5-tier source ranking with
// provenance. Every in-scope interface appears; SLA/target fields stay zero/empty
// ("—") where no target or no measurement exists yet.
type WanInterfaceRow struct {
	Device         string `json:"device"`
	Interface      string `json:"interface"`
	Address        string `json:"address"`
	Site           string `json:"site,omitempty"`
	ConnectedToWAN bool   `json:"connected_to_wan,omitempty"` // Spine-style: connected to a WAN device, not on one

	// live interface load/state (VictoriaMetrics device_if_*)
	InBps   float64 `json:"in_bps"`
	OutBps  float64 `json:"out_bps"`
	Util    float64 `json:"util_pct"`
	HasUtil bool    `json:"has_util"`
	OperUp  bool    `json:"oper_up"`
	HasOper bool    `json:"has_oper"`

	// derived measurement target (no hub/spoke)
	Target      string        `json:"target,omitempty"`       // dst host measured to
	TargetKind  WanTargetKind `json:"target_kind,omitempty"`  // direct_peer | next_hop | anchor
	TargetLabel string        `json:"target_label,omitempty"` // customer-facing target description
	RemoteDevice string       `json:"remote_device,omitempty"`
	RemoteIf     string       `json:"remote_if,omitempty"`
	HasTarget    bool         `json:"has_target"`

	// live throughput sparkline (bits/sec, oldest→newest) for the in-row moving
	// graph. Refetched each poll so the line advances (live). Empty when no series.
	Spark []float64 `json:"spark,omitempty"`

	// resolved SLA + provenance (5-tier measurement-source ranking)
	Latency         float64    `json:"latency_ms"`
	Jitter          float64    `json:"jitter_ms"`
	Loss            float64    `json:"loss_pct"`
	QoE             float64    `json:"qoe"`
	Availability    float64    `json:"availability_pct"`
	HasLatency      bool       `json:"has_latency"`
	HasJitter       bool       `json:"has_jitter"`
	HasLoss         bool       `json:"has_loss"`
	HasQoE          bool       `json:"has_qoe"`
	HasAvailability bool       `json:"has_availability"`
	Source          PathSource `json:"source,omitempty"`       // headline measurement method
	SourceLabel     string     `json:"source_label,omitempty"` // customer-facing method name
	Tier            int        `json:"tier,omitempty"`         // 1..5 (1 = closest to user experience)
	TierLabel       string     `json:"tier_label,omitempty"`   // e.g. "Active path probe"
}

// wanIfKey indexes a device_if_* sample / endpoint by device + interface name.
func wanIfKey(device, iface string) string { return device + "\x00" + iface }

// wanSparkSeries fetches a short throughput history (bits/sec) per interface for
// the in-row live sparkline: one VictoriaMetrics range query over the last
// `windowSec` at `stepSec`, keyed by device+ifName. Throughput = (in+out) octet
// rate ×8. Best-effort — a query error or a metrics-off environment yields an
// empty map and the rows simply carry no sparkline. `nowUnix` is passed in so the
// caller controls the clock (testable, no hidden time.Now here).
func (s *server) wanSparkSeries(ctx context.Context, nowUnix, windowSec, stepSec int64) map[string][]float64 {
	if s.vmRangeRaw == nil && s.metricsBase() == "" {
		return nil
	}
	query := `(rate(device_if_in_octets[1m]) + rate(device_if_out_octets[1m])) * 8`
	series, err := s.vmQueryRangeByIf(ctx, query, nowUnix-windowSec, nowUnix, stepSec)
	if err != nil {
		return nil
	}
	return series
}

// metricsBase returns the configured VM base URL (or "" when unset).
func (s *server) metricsBase() string {
	return envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
}

// vmQueryRangeByIf runs a range query and returns per (device,ifName) value series
// (oldest→newest), keyed by wanIfKey. A DI seam (s.vmRangeRaw) lets tests inject.
func (s *server) vmQueryRangeByIf(ctx context.Context, query string, start, end, step int64) (map[string][]float64, error) {
	if s.vmRangeRaw != nil {
		return s.vmRangeRaw(ctx, query, start, end, step)
	}
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start, 10))
	q.Set("end", strconv.FormatInt(end, 10))
	q.Set("step", strconv.FormatInt(step, 10))
	endpoint := strings.TrimRight(s.metricsBase(), "/") + "/api/v1/query_range?" + q.Encode()
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := backendHTTPClient(15 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	series := map[string][]float64{}
	for _, r := range out.Data.Result {
		dev, ifn := r.Metric["device"], r.Metric["ifName"]
		if dev == "" || ifn == "" {
			continue
		}
		vals := make([]float64, 0, len(r.Values))
		for _, v := range r.Values {
			f := 0.0
			if str, ok := v[1].(string); ok {
				f, _ = strconv.ParseFloat(str, 64)
			}
			if f < 0 {
				f = 0
			}
			vals = append(vals, f)
		}
		series[wanIfKey(dev, ifn)] = vals
	}
	return series, nil
}

// splitIfKey reverses wanIfKey.
func splitIfKey(k string) (string, string) {
	if i := strings.IndexByte(k, 0); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "", ""
}

// wanInterfaceRows builds the per-interface table: every in-scope WAN interface
// for the principal, joined with its derived target, the resolved SLA, and live
// util. Target metrics are keyed by target HOST (the resolver's identity).
func (s *server) wanInterfaceRows(ctx context.Context, tenant string, cross bool) []WanInterfaceRow {
	endpoints, circuits := s.wanProject(ctx, tenant, cross)
	if len(endpoints) == 0 {
		return nil
	}

	// local (device,if) → target link, so each interface finds its target.
	linkByLocal := map[string]WanCircuit{}
	for _, c := range circuits {
		k := wanIfKey(c.Local.Device, c.Local.Interface)
		if _, seen := linkByLocal[k]; !seen {
			linkByLocal[k] = c
		}
	}

	resolved := s.resolveCurrentByDst(ctx)

	// live interface load/state from VM, keyed by device+ifName.
	type util struct {
		in, out, speedMbps float64
		hasIn, hasOut      bool
		oper               float64
		hasOper            bool
	}
	uMap := map[string]*util{}
	getU := func(k string) *util {
		u := uMap[k]
		if u == nil {
			u = &util{}
			uMap[k] = u
		}
		return u
	}
	foldUtil := func(query string, set func(u *util, v float64)) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			dev, ifn := sm.Labels["device"], sm.Labels["ifName"]
			if dev == "" || ifn == "" {
				continue
			}
			set(getU(wanIfKey(dev, ifn)), sm.Value)
		}
	}
	foldUtil(`rate(device_if_in_octets[2m])*8`, func(u *util, v float64) { u.in, u.hasIn = v, true })
	foldUtil(`rate(device_if_out_octets[2m])*8`, func(u *util, v float64) { u.out, u.hasOut = v, true })
	foldUtil(`device_if_speed`, func(u *util, v float64) { u.speedMbps = v })
	foldUtil(`device_if_oper_status`, func(u *util, v float64) { u.oper, u.hasOper = v, true })

	// Live throughput history for the in-row moving sparkline (last 10m @ 30s step).
	spark := s.wanSparkSeries(ctx, time.Now().Unix(), 600, 30)

	rows := make([]WanInterfaceRow, 0, len(endpoints))
	for _, e := range endpoints {
		row := WanInterfaceRow{
			Device: e.Device, Interface: e.Interface, Address: e.Address,
			Site: e.Site, ConnectedToWAN: e.ConnectedToWAN,
			Target: e.Target, TargetKind: e.TargetKind, TargetLabel: e.TargetLabel,
		}
		if u, ok := uMap[wanIfKey(e.Device, e.Interface)]; ok {
			row.InBps, row.OutBps = u.in, u.out
			row.HasUtil = u.hasIn || u.hasOut
			if sp := u.speedMbps * 1e6; sp > 0 {
				mx := u.in
				if u.out > mx {
					mx = u.out
				}
				row.Util = mx / sp * 100
			}
			if u.hasOper {
				row.OperUp, row.HasOper = u.oper == 1, true
			}
		}
		if sp := spark[wanIfKey(e.Device, e.Interface)]; len(sp) > 0 {
			row.Spark = sp
		}
		if c, ok := linkByLocal[wanIfKey(e.Device, e.Interface)]; ok {
			row.HasTarget = true
			row.RemoteDevice, row.RemoteIf = c.Remote.Device, c.Remote.Interface
			if m, ok := resolved[hostOnly(e.Target)]; ok {
				row.Latency, row.HasLatency = m.Latency, m.HasLatency
				row.Jitter, row.HasJitter = m.Jitter, m.HasJitter
				row.Loss, row.HasLoss = m.Loss, m.HasLoss
				row.QoE, row.HasQoE = m.QoE, m.HasQoE
				row.Availability, row.HasAvailability = m.Availability, m.HasAvailability
				row.Source = m.Source()
				row.SourceLabel = row.Source.Label()
				row.Tier = int(row.Source.Tier())
				row.TierLabel = row.Source.TierLabel()
			}
		}
		rows = append(rows, row)
	}
	// busiest first, then by name for stability.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Util != rows[j].Util {
			return rows[i].Util > rows[j].Util
		}
		if rows[i].Device != rows[j].Device {
			return rows[i].Device < rows[j].Device
		}
		return rows[i].Interface < rows[j].Interface
	})
	return rows
}

// ---- HTTP handlers ----

// handleWanInterfaces: GET /api/wan/interfaces — the per-WAN-interface table.
func (s *server) handleWanInterfaces(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": s.wanInterfaceRows(r.Context(), tenant, cross)})
}

// handleWanEndpoints: GET /api/wan/endpoints — the derived WAN endpoint registry.
func (s *server) handleWanEndpoints(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	eps, _ := s.wanProject(r.Context(), tenant, cross)
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps})
}

// handleWanCircuits: GET /api/wan/circuits — the derived interface→target links.
func (s *server) handleWanCircuits(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	_, circuits := s.wanProject(r.Context(), tenant, cross)
	writeJSON(w, http.StatusOK, map[string]any{"circuits": circuits})
}

// handleWanPolicy: GET|PUT /api/wan/policy — the per-tenant measurement policy.
func (s *server) handleWanPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		writeJSON(w, http.StatusOK, s.wanPolicy.Get(tenant, cross))
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var req WanMeasurementPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad body: " + err.Error()})
			return
		}
		tenant, _ := principalTenant(claims)
		req.TenantID = tenant // owner from the token, never the body
		req.UpdatedBy = claims.Sub
		req.UpdatedAt = time.Now().UTC()
		req = req.withDefaults()
		if err := req.validate(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.wanPolicy.Put(req); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, req)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}
