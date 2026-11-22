// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/ifbridge"
	"netops/backend/internal/metricval"
	"netops/backend/models"
	"netops/backend/wan"
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

// The WAN projection core moved to the wan package (Phase-2 W1.6). Aliases
// keep the policy store, projector, publisher, rows and handlers below (plus
// the isolation test) source-compatible.
type (
	WanEndpoint          = wan.Endpoint
	WanCircuit           = wan.Circuit
	WanMeasurementPolicy = wan.MeasurementPolicy
	WanTargetKind        = wan.TargetKind
)

const (
	WanTargetDirectPeer = wan.TargetDirectPeer
	WanTargetNextHop    = wan.TargetNextHop
	WanTargetAnchor     = wan.TargetAnchor
	WanTargetNone       = wan.TargetNone
)

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
//
// A server built without the store answers the same way. main.go builds it or
// aborts the boot, so this is a partially-built server and nothing else, but a
// missing guard is not an error path: without it the nil dereference came out
// of /api/wan/interfaces as a recovered panic and a 500, which is a failure
// reported in the wrong way (§10). The baseline is the honest answer, and it is
// the answer every unconfigured tenant already gets.
func (s *wanPolicyStore) Get(tenant string, cross bool) WanMeasurementPolicy {
	if s == nil || s.kv == nil {
		return wan.MeasurementPolicy{TenantID: tenant}.WithDefaults()
	}
	// EVERY tenant's row carries the same id ("policy"), because this collection
	// is one row per tenant. A cross-tenant read therefore misses on the platform
	// key and falls through to Collection.Get's "the id may live under any tenant"
	// scan, which returns whichever tenant's row the map happened to yield first:
	// a nondeterministic answer that hands the platform operator another tenant's
	// WAN pattern and its configured ISP next-hops (keyed by that tenant's device
	// and interface names) — a restricted tenant's included. The Global view reads
	// the PLATFORM's own row or the baseline; a tenant's policy is only ever read
	// inside that tenant's scope.
	lookup := tenant
	if cross {
		lookup = TenantGlobal
	}
	if p, ok := s.kv.Get(lookup, false, "policy"); ok {
		return p.WithDefaults()
	}
	return wan.MeasurementPolicy{TenantID: tenant}.WithDefaults()
}

// Put persists operator intent. With no store there is nowhere to persist it,
// and a write that cannot be written down must SAY so rather than panic: the
// read side can fall back to the baseline, the write side has no such fallback.
func (s *wanPolicyStore) Put(p WanMeasurementPolicy) error {
	if s == nil || s.kv == nil {
		return errors.New("wan measurement policy store is not configured")
	}
	return s.kv.Upsert(p)
}

// wanPolicyFor is the READ side of the measurement policy, resolved for a
// principal: the tenant scope plus the per-tenant operator-visibility
// restriction. A policy is not telemetry, but it is still the tenant's: its
// next-hop overrides are keyed by that tenant's device and interface names and
// valued with its ISP addresses. So an operator scoped INTO a restricted tenant
// gets the measurement BASELINE — the same answer an unconfigured tenant gets,
// which discloses nothing — rather than that tenant's row. The tenant's own
// users are never affected, and this is a no-op when no tenant is restricted.
func (s *server) wanPolicyFor(claims jwtClaims) WanMeasurementPolicy {
	tenant, cross := principalTenant(claims)
	if _, deny := s.operatorTelemetryRestriction(claims, tenant, cross); deny {
		return wan.MeasurementPolicy{TenantID: tenant}.WithDefaults()
	}
	return s.wanPolicy.Get(tenant, cross)
}

// ---- projector: interface-IP table × neighbors × policy → endpoints + targets ----

// wanProjection is one principal's WAN view. Endpoints are the CONFIRMED WAN
// interfaces (measured, each with a derived target, each a circuit);
// Candidates are the POSSIBLE ones (listed apart, never probed, until an
// operator marks them). Both carry why (wan_basis / wan_reason / wan_evidence).
type wanProjection struct {
	Endpoints  []WanEndpoint
	Candidates []WanEndpoint
	Circuits   []WanCircuit
}

// wanProject is the confirmed half of wanProjectAll: the endpoints and circuits
// every measuring and listing consumer reads (the echo publisher, Iris).
func (s *server) wanProject(ctx context.Context, vis deviceVisibility) ([]WanEndpoint, []WanCircuit, error) {
	p, err := s.wanProjectAll(ctx, vis)
	return p.Endpoints, p.Circuits, err
}

// wanProjectAll builds the WAN view per INTERFACE from evidence (wan.Classify):
// the controller's VPN, port role and interface kind (interface bridge), the
// SD-WAN overlay's transport locators, a next-hop declared for exactly that
// port, and the operator's marks. Until 2026-11-22 it took every addressed port
// of any device whose NAME matched the WAN pattern, so an SD-WAN edge listed its
// LAN, loopback and system ports as WAN circuits (owner report). The name
// pattern now only makes a device a candidate, which widens what is offered as
// possible and never confirms a port.
//
// vis is the RESOLVED device-registry visibility for the caller (tenancy.go): the
// ordinary tenant rule AND the per-tenant operator-visibility restriction. It is
// taken as a parameter rather than re-derived here because this projection is
// also driven by platform infrastructure (the wan-echo publisher), which measures
// on every tenant's behalf and must NOT be narrowed — see startWANCircuitPublish.
//
// WHY THE WHOLE PROJECTION HANGS OFF THE DEVICE SLICE: `visible` and `nameToID`
// are the resolution universe for the neighbour index, and wan.NeighborIndex
// drops any link whose local device is not in `visible` or whose remote sysName
// does not resolve through `nameToID`. So a device removed here cannot come back
// as a peer's NAME, its interface IP, or a "Directly-connected peer <name>"
// target label — the interface facing it falls through to the reachability
// anchor instead, which names nothing. The evidence bundle is read for every
// device, but only visible devices are ever classified, so another tenant's
// controller rows or overlay facts never decide a caller's interface.
//
// The error is whether the directly-connected-peer evidence was actually read
// (tracker 290): with no neighbour index every interface falls through to the
// reachability anchor, which is safe and invisible, so callers surface it.
func (s *server) wanProjectAll(ctx context.Context, vis deviceVisibility) (wanProjection, error) {
	if vis.deny {
		// The operator scoped INTO a restricted tenant: no devices, and no read of
		// that tenant's measurement policy either.
		return wanProjection{}, nil
	}
	tenant, cross := vis.tenant, vis.cross
	pol := s.wanPolicy.Get(tenant, cross)
	pat := regexp.MustCompile("(?i)" + pol.WanPattern)

	// All devices visible to this principal, id→device and name→id.
	visible := map[string]models.Device{}
	nameToID := map[string]string{}
	for _, d := range vis.filter(s.discovery.Devices()) {
		if d.ID == "" {
			continue
		}
		visible[d.ID] = d
		nameToID[strings.ToLower(d.Name)] = d.ID
	}
	if len(visible) == 0 {
		return wanProjection{}, nil
	}

	// The evidence bundle: the merged bridge (address → port, and each device's
	// controller rows). An unread bridge empties the view, so it is reported
	// rather than answered as "this tenant has no WAN interfaces" (tracker 307).
	ev, evErr := s.wanEvidence(ctx)
	reportIfRegistryUnread("wan", "the interface table for this projection is EMPTY — no WAN interface or circuit can be derived, which is indistinguishable from a tenant that has none", evErr,
		map[string]any{"tenant": tenant, "cross": cross, "devices": len(visible)})
	ifaddr := ev.Addr

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
	neighbors, neighborsErr := s.wanNeighborIndex(ctx, visible, nameToID, ipByDevIf)

	// SD-WAN overlay facts: the transport locators each device lists.
	var overlay map[string]collectors.OverlayDeviceFacts
	if snap := s.sdwanOverlay.Load(); snap != nil {
		overlay = snap.devFacts
	}

	// A candidate device: its name matches the pattern, or it is an SD-WAN edge.
	candidate := map[string]bool{}
	for id, d := range visible {
		_, ov := overlay[id]
		candidate[id] = pat.MatchString(d.Name) || ov || len(ev.NMS[id].Rows) > 0
	}
	// Ports directly connected to a candidate device (usually its LAN side).
	linked := map[string]map[string]string{}
	if pol.IncludeConnectedOn() {
		for k, peer := range neighbors {
			devID, ifn := wan.SplitIfKey(k)
			if devID == "" || candidate[devID] {
				continue
			}
			if id := nameToID[strings.ToLower(peer.Device)]; id != "" && candidate[id] {
				if linked[devID] == nil {
					linked[devID] = map[string]string{}
				}
				linked[devID][ifn] = peer.Device
			}
		}
	}

	var proj wanProjection
	ids := make([]string, 0, len(visible))
	for id := range visible {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := visible[id]
		rows := ev.NMS[id].Rows
		if len(ifaddr[id]) == 0 && len(rows) == 0 {
			continue
		}
		in := wan.DeviceInputs{
			DeviceID: id, Name: d.Name, Candidate: candidate[id],
			AddrIf: ifaddr[id], NextHops: pol.NextHops, Linked: linked[id],
		}
		for _, r := range rows {
			in.Rows = append(in.Rows, wan.IfRow{Name: r.IfName, VRF: r.VRF, Role: r.Role, Kind: r.Kind, Alias: r.Alias, Addrs: r.Addrs})
		}
		if f, ok := overlay[id]; ok {
			for _, t := range f.TLOCs {
				in.TLOCIfaces = append(in.TLOCIfaces, t.Interface)
			}
			in.TLOCAddrs = f.LocalTLOCAddrs
		}
		facts := wan.BuildFacts(in, canonIface)
		addrOf := map[string]string{}
		for _, f := range facts.Ifaces {
			addrOf[f.Name] = preferIPv4(f.Addrs)
		}
		site := ""
		if b, ok := s.deviceSites.Get(tenant, cross, id); ok {
			site = b.Site
		}
		for _, v := range wan.Classify(facts) {
			ip := addrOf[v.Interface]
			if v.Confidence == "" || ip == "" {
				continue // not WAN, or nothing to measure from
			}
			ep := WanEndpoint{
				TenantID: deviceTenant(d), DeviceID: id, Device: d.Name, Interface: v.Interface,
				Address: ip, Measurable: ip, Site: site,
				ConnectedToWAN: v.Basis == wan.BasisLinked,
				WanConfidence:  v.Confidence, WanBasis: v.Basis, WanReason: v.Reason, WanEvidence: v.Evidence,
			}
			if v.Confidence != wan.Confirmed {
				proj.Candidates = append(proj.Candidates, ep)
				continue
			}
			ep.Target, ep.TargetKind, ep.TargetLabel = wan.DeriveTarget(id, v.Interface, neighbors, pol)
			proj.Endpoints = append(proj.Endpoints, ep)
		}
	}
	byName := func(eps []WanEndpoint) {
		sort.Slice(eps, func(a, b int) bool {
			if eps[a].Device != eps[b].Device {
				return eps[a].Device < eps[b].Device
			}
			return eps[a].Interface < eps[b].Interface
		})
	}
	byName(proj.Endpoints)
	byName(proj.Candidates)

	// 1:1 interface → target links, confirmed interfaces only.
	for _, ep := range proj.Endpoints {
		if ep.Target == "" {
			continue
		}
		remote := WanEndpoint{
			TenantID: ep.TenantID, Measurable: ep.Target, Address: ep.Target,
		}
		switch ep.TargetKind {
		case WanTargetDirectPeer:
			// Fill the peer device/if for display.
			if peer, ok := neighbors[wan.IfKey(ep.DeviceID, ep.Interface)]; ok {
				remote.Device, remote.Interface = peer.Device, peer.Iface
			}
		case WanTargetAnchor:
			remote.Device = "Internet"
		case WanTargetNextHop:
			remote.Device = "Next-hop"
		}
		proj.Circuits = append(proj.Circuits, WanCircuit{
			TenantID: ep.TenantID, ID: wan.CircuitID(ep, remote), Local: ep, Remote: remote,
			Kind: ep.TargetKind, Source: "registry", Enabled: true,
		})
	}
	return proj, neighborsErr
}

// preferIPv4 picks the address an interface is measured from: its first IPv4
// address, else its first address ("" when it has none).
func preferIPv4(addrs []string) string {
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

// wanEvidenceTTL is how long the default evidence read is reused.
const wanEvidenceTTL = 30 * time.Second

// wanEvidenceCache memoizes the merged-bridge read the WAN projection uses. The
// bundle is the same for every principal — visibility is applied after, per
// request — so caching it never mixes one caller's output into another's. A
// failed read is never cached.
type wanEvidenceCache struct {
	mu  sync.Mutex
	at  time.Time
	val ifbridge.Merged
}

func (c *wanEvidenceCache) get(ctx context.Context, now time.Time, fetch func(context.Context) (ifbridge.Merged, error)) (ifbridge.Merged, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && now.Sub(c.at) >= 0 && now.Sub(c.at) < wanEvidenceTTL {
		return c.val, nil
	}
	m, err := fetch(ctx)
	if err != nil {
		return m, err
	}
	c.val, c.at = m, now
	return m, nil
}

// wanEvidence is the projection's evidence bundle: the wanIfEvidence seam, else
// the older wanIfAddr seam (an address map, no controller rows), else the cached
// merged bridge. Callers must not mutate what it returns.
func (s *server) wanEvidence(ctx context.Context) (ifbridge.Merged, error) {
	if s.wanIfEvidence != nil {
		return s.wanIfEvidence(ctx)
	}
	if s.wanIfAddr != nil {
		m, err := s.wanIfAddr(ctx)
		return ifbridge.Merged{Addr: m}, err
	}
	return s.wanEvidenceCache.get(ctx, time.Now(), fetchIfBridge)
}

// wanNeighborIndex fetches the merged topology links via the DI seam and
// builds the pure wan.NeighborIndex over them.
//
// It REPORTS a failed fetch rather than folding it into an empty index
// (tracker 290). An empty index is a legitimate state — no discovery collector
// is deployed, or nothing is directly connected — and it is also exactly what a
// dead channel produces, so the two have to be told apart before the projection
// quietly downgrades every interface to a reachability anchor.
func (s *server) wanNeighborIndex(ctx context.Context, visible map[string]models.Device, nameToID map[string]string, ipByDevIf map[string]map[string]string) (map[string]wan.Peer, error) {
	fetch := s.wanNeighbors
	if fetch == nil {
		fetch = s.fetchTopoLinks // the shared adjacency-evidence resolver (seam, then collector)
	}
	links, err := fetch(ctx)
	idx := wan.NeighborIndex(links, visible, nameToID, ipByDevIf)
	if errTopoLinksUnread(err) {
		return idx, err
	}
	return idx, nil
}

// ---- interface-target publisher (→ Redis, for the wan-echo collector) ----

// echoTargetsFor renders the enabled, measurable circuits as the wan-echo
// collector's target list. Each target carries the local device's tenant AND
// inventory id: the collector stamps them as the circuit series' `tenant_id`
// and `device` labels, which is what lets the tenant metric scope admit a
// tenant's own circuit series and nobody else's (tracker 337 N-B5).
func echoTargetsFor(circuits []WanCircuit) []collectors.EchoTarget {
	targets := make([]collectors.EchoTarget, 0, len(circuits))
	for _, c := range circuits {
		if !c.Enabled || c.Remote.Measurable == "" {
			continue
		}
		targets = append(targets, collectors.EchoTarget{
			CircuitID:     c.ID,
			Tenant:        c.Local.TenantID,
			LocalDevice:   c.Local.Device,
			LocalDeviceID: c.Local.DeviceID,
			LocalIf:       c.Local.Interface,
			LocalAddr:     c.Local.Measurable,
			RemoteDevice:  c.Remote.Device,
			RemoteIf:      c.Remote.Interface,
			RemoteAddr:    c.Remote.Measurable,
		})
	}
	return targets
}

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
		// PLATFORM INFRASTRUCTURE, not an operator read: the prober measures on
		// every tenant's behalf and each target carries its tenant label, so the
		// restricted tenant's own users keep getting their own measurements. The
		// operator-visibility rule governs operator READS (the request handlers
		// below); narrowing the prober here would take a restricted tenant's
		// measurements away from the tenant itself.
		_, circuits, err := s.wanProject(ctx, platformInfraDeviceVisibility())
		if err != nil {
			// REFUSAL (tracker 290). Publishing now would REPLACE the prober's
			// target list with one derived from no adjacency evidence at all —
			// every direct-peer target downgraded to a reachability anchor — and
			// the prober would then measure the wrong thing for as long as the
			// list lived. Skipping leaves the last good list in place (it carries
			// a 3-interval TTL), and the next cycle is 60s away. The publish
			// channel is the same channel the read just failed on, so there is
			// almost nothing to lose and a whole measurement programme to protect.
			logError("wan", "adjacency evidence unread — the wan-echo target list is NOT being republished, so the prober keeps its last targets",
				map[string]any{"error": err.Error()})
			return
		}
		targets := echoTargetsFor(circuits)
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

	// Why this interface is WAN (wan.Classify). The table lists confirmed rows;
	// possible ones travel in the response's `candidates`.
	WanConfidence string         `json:"wan_confidence,omitempty"`
	WanBasis      wan.Basis      `json:"wan_basis,omitempty"`
	WanReason     string         `json:"wan_reason,omitempty"`
	WanEvidence   []wan.Evidence `json:"wan_evidence,omitempty"`

	// live interface load/state (VictoriaMetrics device_if_*)
	InBps   float64 `json:"in_bps"`
	OutBps  float64 `json:"out_bps"`
	Util    float64 `json:"util_pct"`
	HasUtil bool    `json:"has_util"`
	OperUp  bool    `json:"oper_up"`
	HasOper bool    `json:"has_oper"`

	// derived measurement target (no hub/spoke)
	Target       string        `json:"target,omitempty"`       // dst host measured to
	TargetKind   WanTargetKind `json:"target_kind,omitempty"`  // direct_peer | next_hop | anchor
	TargetLabel  string        `json:"target_label,omitempty"` // customer-facing target description
	RemoteDevice string        `json:"remote_device,omitempty"`
	RemoteIf     string        `json:"remote_if,omitempty"`
	HasTarget    bool          `json:"has_target"`

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

// wanSparkSeries fetches a short throughput history (bits/sec) per interface for
// the in-row live sparkline: one VictoriaMetrics range query over the last
// `windowSec` at `stepSec`, keyed by device+ifName. Throughput = (in+out) octet
// rate ×8. Best-effort — a query error or a metrics-off environment yields an
// empty map and the rows simply carry no sparkline. `nowUnix` is passed in so the
// caller controls the clock (testable, no hidden time.Now here).
func (s *server) wanSparkSeries(ctx context.Context, nowUnix, windowSec, stepSec int64, f []string) map[string][]float64 {
	if s.vmRangeRaw == nil && s.metricsBase() == "" {
		return nil
	}
	query := `(rate(device_if_in_octets[1m]) + rate(device_if_out_octets[1m])) * 8`
	series, err := s.vmQueryRangeByIf(ctx, query, nowUnix-windowSec, nowUnix, stepSec, f)
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
func (s *server) vmQueryRangeByIf(ctx context.Context, query string, start, end, step int64, filters []string) (map[string][]float64, error) {
	if s.vmRangeRaw != nil {
		return s.vmRangeRaw(ctx, query, start, end, step)
	}
	q := url.Values{}
	q.Set("query", query)
	// SEC (2026-08-04): this builds its own request rather than going through
	// vmInstantScoped, so the caller's device boundary must be applied HERE —
	// it is the sparkline behind every WAN row and was previously fleet-wide.
	for _, f := range filters {
		q.Add("extra_filters[]", f)
	}
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
				// F-21: NaN/±Inf are missing data, not utilisation — and they
				// cannot be JSON-encoded, so one of them emptied the response.
				f = metricval.FiniteOrZero(str)
			}
			if f < 0 {
				f = 0
			}
			vals = append(vals, f)
		}
		series[wan.IfKey(dev, ifn)] = vals
	}
	return series, nil
}

// splitIfKey reverses wanIfKey.

// wanInterfaceRows builds the per-interface table: every in-scope WAN interface
// for the principal, joined with its derived target, the resolved SLA, and live
// util. Target metrics are keyed by target HOST (the resolver's identity).
// f carries the caller's device boundary for every VictoriaMetrics read below
// (SEC 2026-08-04): the util/sparkline/resolver maps are joined onto rows by
// device+ifName NAME, so an unscoped read surfaces another tenant's link load,
// speed and oper-state whenever a device name collides across tenants — the
// defect topology_view.go:86-91 documents.
func (s *server) wanInterfaceRows(ctx context.Context, vis deviceVisibility, f []string) ([]WanInterfaceRow, error) {
	rows, _, err := s.wanInterfaceView(ctx, vis, f)
	return rows, err
}

// wanSeriesKey is the join key between a device_if_* series and a WAN row: the
// series' `device` label is the INVENTORY ID, and its ifName may be spelled
// either way ("Gi1" from SNMP, "GigabitEthernet1" from the controller). Until
// 2026-11-22 rows looked the series up by device NAME, so on any inventory whose
// ids differ from their names (the lab: "cedge-40-fdf7b64f") utilisation,
// oper-state and the sparkline never joined.
func wanSeriesKey(device, ifn string) string { return wan.IfKey(device, canonIface(ifn)) }

// wanInterfaceView is the table rows (confirmed WAN interfaces) and the
// possible ones the page lists apart.
func (s *server) wanInterfaceView(ctx context.Context, vis deviceVisibility, f []string) ([]WanInterfaceRow, []WanEndpoint, error) {
	proj, projErr := s.wanProjectAll(ctx, vis)
	endpoints, circuits := proj.Endpoints, proj.Circuits
	if len(endpoints) == 0 {
		return nil, proj.Candidates, projErr
	}

	// local (device,if) → target link, so each interface finds its target.
	linkByLocal := map[string]WanCircuit{}
	for _, c := range circuits {
		k := wan.IfKey(c.Local.Device, c.Local.Interface)
		if _, seen := linkByLocal[k]; !seen {
			linkByLocal[k] = c
		}
	}

	resolved := s.resolveCurrentByDst(ctx, f)

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
		samples, err := s.vmInstantScoped(ctx, query, f)
		if err != nil {
			return
		}
		for _, sm := range samples {
			dev, ifn := sm.Labels["device"], sm.Labels["ifName"]
			if dev == "" || ifn == "" {
				continue
			}
			set(getU(wanSeriesKey(dev, ifn)), sm.Value)
		}
	}
	foldUtil(`rate(device_if_in_octets[2m])*8`, func(u *util, v float64) { u.in, u.hasIn = v, true })
	foldUtil(`rate(device_if_out_octets[2m])*8`, func(u *util, v float64) { u.out, u.hasOut = v, true })
	foldUtil(`device_if_speed`, func(u *util, v float64) { u.speedMbps = v })
	foldUtil(`device_if_oper_status`, func(u *util, v float64) { u.oper, u.hasOper = v, true })

	// Live throughput history for the in-row moving sparkline (last 10m @ 30s step).
	spark := map[string][]float64{}
	for k, v := range s.wanSparkSeries(ctx, time.Now().Unix(), 600, 30, f) {
		dev, ifn := wan.SplitIfKey(k)
		spark[wanSeriesKey(dev, ifn)] = v
	}
	// A series is labelled with the inventory id; a row knows both id and name.
	seriesKeys := func(e WanEndpoint) []string {
		keys := []string{}
		if e.DeviceID != "" {
			keys = append(keys, wanSeriesKey(e.DeviceID, e.Interface))
		}
		return append(keys, wanSeriesKey(e.Device, e.Interface))
	}

	rows := make([]WanInterfaceRow, 0, len(endpoints))
	for _, e := range endpoints {
		row := WanInterfaceRow{
			Device: e.Device, Interface: e.Interface, Address: e.Address,
			Site: e.Site, ConnectedToWAN: e.ConnectedToWAN,
			Target: e.Target, TargetKind: e.TargetKind, TargetLabel: e.TargetLabel,
			WanConfidence: e.WanConfidence, WanBasis: e.WanBasis, WanReason: e.WanReason, WanEvidence: e.WanEvidence,
		}
		var u *util
		var sp []float64
		for _, k := range seriesKeys(e) {
			if u == nil {
				u = uMap[k]
			}
			if sp == nil {
				sp = spark[k]
			}
		}
		if u != nil {
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
		if len(sp) > 0 {
			row.Spark = sp
		}
		if c, ok := linkByLocal[wan.IfKey(e.Device, e.Interface)]; ok {
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
	return rows, proj.Candidates, projErr
}

// ---- HTTP handlers ----

// wanTargetsUnreadNote is what an operator is told when the WAN projection had
// no adjacency evidence to derive targets from. It names the CONSEQUENCE, not
// the plumbing: the Target column is what the reader is looking at.
const wanTargetsUnreadNote = "Adjacency evidence could not be read, so directly-connected peers were not resolved — interfaces shown against a reachability anchor may in fact have a peer, and are not confirmed to be internet-facing."

// wanDegradedNotes turns a projection failure into the operator-facing notes the
// WAN payloads carry. nil on a healthy read, and nil when no discovery collector
// is deployed at all (errTopoLinksUnread already filtered that), so the banner
// never appears on a deployment where the anchor really is the right target.
func wanDegradedNotes(err error) []string {
	if err == nil {
		return nil
	}
	logWarn("wan", "adjacency evidence unread for a WAN projection — every interface fell back to its reachability anchor",
		map[string]any{"error": err.Error()})
	return []string{wanTargetsUnreadNote}
}

// handleWanInterfaces: GET /api/wan/interfaces — the per-WAN-interface table.
func (s *server) handleWanInterfaces(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	// RENDERABLE-WITH-A-BANNER (tracker 290). The row is mostly real without the
	// neighbour index — the interface, its utilisation, its oper-state and its
	// measured SLA all still arrive — so refusing the table would cost far more
	// than it saves. What the table cannot say for itself is that every "Reachability
	// anchor" in the Target column may be a fallback the projection took because
	// the peer was never looked for, so the payload says it instead.
	rows, candidates, err := s.wanInterfaceView(r.Context(), s.deviceVisibilityFor(claims), s.metricsScopeFiltersFor(claims))
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": rows, "candidates": nonNilEndpoints(candidates), "degraded": wanDegradedNotes(err)})
}

// nonNilEndpoints keeps an empty list on the wire as [] rather than null.
func nonNilEndpoints(eps []WanEndpoint) []WanEndpoint {
	if eps == nil {
		return []WanEndpoint{}
	}
	return eps
}

// handleWanEndpoints: GET /api/wan/endpoints — the derived WAN endpoint registry.
func (s *server) handleWanEndpoints(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	proj, err := s.wanProjectAll(r.Context(), s.deviceVisibilityFor(claims))
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": proj.Endpoints, "candidates": nonNilEndpoints(proj.Candidates), "degraded": wanDegradedNotes(err)})
}

// handleWanCircuits: GET /api/wan/circuits — the derived interface→target links.
func (s *server) handleWanCircuits(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	_, circuits, err := s.wanProject(r.Context(), s.deviceVisibilityFor(claims))
	writeJSON(w, http.StatusOK, map[string]any{"circuits": circuits, "degraded": wanDegradedNotes(err)})
}

// handleWanPolicy: GET|PUT /api/wan/policy — the per-tenant measurement policy.
func (s *server) handleWanPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, s.wanPolicyFor(claims))
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
		req = req.WithDefaults()
		if err := req.Validate(); err != nil {
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
