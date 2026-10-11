// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// bgp_vrf_peers.go — BGP sessions INSIDE routing instances (PE-CE, SD-WAN
// service-VPN BGP, VRF-lite), which BGP4-MIB cannot show: its bgpPeerTable
// covers the default instance only. Capability-first like vrf_instances.go:
// each source is probed in the device's vendor order and the first that
// answers is used.
//
// Sources (numeric OIDs compiled with snmptranslate):
//
//	cisco-bgp-peer3  CISCO-BGP4-MIB cbgpPeer3Table   9.9.187.1.2.9.1   VrfName .4, State .5, RemoteAs .13   {VrfId, Type, Addr}
//	cisco-bgp-peer2  CISCO-BGP4-MIB cbgpPeer2Table   9.9.187.1.2.5.1   State .3, RemoteAs .11 (default VRF, v4+v6; SONiC's only BGP table)
//	nokia-bgp        TIMETRA-BGP-MIB tBgpPeerNgTable 6527.3.1.2.14.4.7.1  ConnState .59, PeerAS4Byte .66  {vRtrID, Type, Addr} + vRtrName join
//	huawei-bgp       HUAWEI-BGP-VPN-MIB              2011.5.25.177.1.1  AddrFamily VrfName .6; hwBgpPeerTable RemoteAs .2, State .5
//	viptela-bgp      VIPTELA-OPER-BGP               41916.14.3.1      As .2, State .10 (ZERO-based)     {VpnId, PeerAddr}
//
// NOT read here, stated rather than guessed: Juniper jnxBgpM2 and Arista
// aristaBgp4V2 carry only a numeric instance index with no name table — those
// VRF peers come from gNMI (owner decision on index-only labelling, tracker).
// A device with gNMI is skipped entirely: gNMI owns BGP there.
//
// Dedupe against the generic poller's BGP4-MIB series: a vendor row in the
// default instance for an IPv4 peer BGP4-MIB already lists is dropped; every
// other row (VRF peers, IPv6 globals, devices whose BGP4-MIB is empty) is
// emitted with a `vrf` label — the label the gNMI lane already carries.
// Not forwarded to the correlation bus (its BGP identity is device:peer, which
// would merge one peer IP from two VRFs; tracker follow-up).

var bgp4PeerState = []int{1, 3, 6, 1, 2, 1, 15, 3, 1, 2}

// Source names (the `mib` label — never `source`, see metrics_query.go).
const (
	bgpSrcCiscoP3 = "cisco-bgp-peer3"
	bgpSrcCiscoP2 = "cisco-bgp-peer2"
	bgpSrcNokia   = "nokia-bgp"
	bgpSrcHuawei  = "huawei-bgp"
	bgpSrcViptela = "viptela-bgp"
)

// defaultVRF is the global instance's label, matching the gNMI lane.
const defaultVRF = "default"

// bgpVRFPeer is one session.
type bgpVRFPeer struct {
	VRF      string
	Peer     string
	State    int64 // 1 idle … 6 established
	RemoteAS int64 // 0 = unknown
}

type bgpVRFReading struct {
	Source    string
	Peers     map[string]*bgpVRFPeer // key vrf|peer
	Dropped   int
	Truncated bool
}

func newBGPReading(src string) *bgpVRFReading {
	return &bgpVRFReading{Source: src, Peers: map[string]*bgpVRFPeer{}}
}

func (r *bgpVRFReading) peer(vrf, addr string) *bgpVRFPeer {
	k := vrf + "|" + addr
	p := r.Peers[k]
	if p == nil {
		p = &bgpVRFPeer{VRF: vrf, Peer: addr}
		r.Peers[k] = p
	}
	return p
}

// inetFromArcs decodes an InetAddressType + InetAddress index pair that ENDS
// the index (true of every table read here): type (1 ipv4 / 2 ipv6), then the
// address with its SMI length octet, or bare (agents differ). The remaining
// arcs must be exactly one of those two shapes — a truncated or over-long
// index is refused, never guessed at.
func inetFromArcs(arcs []int) (string, int, bool) {
	if len(arcs) < 1 {
		return "", 0, false
	}
	var n int
	switch arcs[0] {
	case 1:
		n = 4
	case 2:
		n = 16
	default:
		return "", 0, false
	}
	rest := arcs[1:]
	switch {
	case len(rest) == n+1 && rest[0] == n:
		rest = rest[1:]
	case len(rest) == n:
	default:
		return "", 0, false
	}
	addr := arcsAddr(rest)
	return addr, len(arcs), addr != ""
}

func bgpStateOK(n int64) bool { return n >= 1 && n <= 6 }

type bgpEnv struct {
	walk walkFn
	addr string
	cr   snmpCreds
	max  int
}

type bgpSource struct {
	name string
	read func(ctx context.Context, e bgpEnv) (*bgpVRFReading, error)
}

// ── Cisco ───────────────────────────────────────────────────────────────────

var (
	cbgpPeer3Entry = []int{1, 3, 6, 1, 4, 1, 9, 9, 187, 1, 2, 9, 1}
	cbgpPeer2Entry = []int{1, 3, 6, 1, 4, 1, 9, 9, 187, 1, 2, 5, 1}
)

func readCiscoPeer3(ctx context.Context, e bgpEnv) (*bgpVRFReading, error) {
	states, trunc, err := e.walk(ctx, e.addr, e.cr, oidPlus(cbgpPeer3Entry, 5), e.max)
	if err != nil || len(states) == 0 {
		return nil, err
	}
	names, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(cbgpPeer3Entry, 4), e.max) // best-effort: unnamed → by id
	ases, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(cbgpPeer3Entry, 13), e.max)
	r := newBGPReading(bgpSrcCiscoP3)
	r.Truncated = trunc
	for idx, v := range states {
		a, ok := parseArcs(idx)
		if !ok || len(a) < 2 || !isIntegerTag(v.tag) || !bgpStateOK(v.int()) {
			r.Dropped++
			continue
		}
		peer, _, ok := inetFromArcs(a[1:])
		if !ok {
			r.Dropped++
			continue
		}
		vrf := defaultVRF
		if a[0] != 0 {
			vrf = "vrf-id " + strconv.Itoa(a[0])
		}
		if nv, has := names[idx]; has {
			if n, ok := vrfName(strings.TrimSpace(string(nv.raw))); ok {
				vrf = n
			}
		}
		p := r.peer(vrf, peer)
		p.State = v.int()
		if av, has := ases[idx]; has && isIntegerTag(av.tag) {
			p.RemoteAS = av.int()
		}
	}
	return r, nil
}

func readCiscoPeer2(ctx context.Context, e bgpEnv) (*bgpVRFReading, error) {
	states, trunc, err := e.walk(ctx, e.addr, e.cr, oidPlus(cbgpPeer2Entry, 3), e.max)
	if err != nil || len(states) == 0 {
		return nil, err
	}
	ases, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(cbgpPeer2Entry, 11), e.max)
	r := newBGPReading(bgpSrcCiscoP2)
	r.Truncated = trunc
	for idx, v := range states {
		a, ok := parseArcs(idx)
		peer := ""
		if ok {
			peer, _, ok = inetFromArcs(a)
		}
		if !ok || !isIntegerTag(v.tag) || !bgpStateOK(v.int()) {
			r.Dropped++
			continue
		}
		p := r.peer(defaultVRF, peer)
		p.State = v.int()
		if av, has := ases[idx]; has && isIntegerTag(av.tag) {
			p.RemoteAS = av.int()
		}
	}
	return r, nil
}

// ── Nokia SR OS ─────────────────────────────────────────────────────────────

var tBgpPeerNgEntry = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 14, 4, 7, 1}

func readNokiaBGP(ctx context.Context, e bgpEnv) (*bgpVRFReading, error) {
	states, trunc, err := e.walk(ctx, e.addr, e.cr, oidPlus(tBgpPeerNgEntry, 59), e.max)
	if err != nil || len(states) == 0 {
		return nil, err
	}
	types, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(vRtrConfEntry, 28), e.max)
	names, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(vRtrConfEntry, 4), e.max)
	ases, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(tBgpPeerNgEntry, 66), e.max)
	r := newBGPReading(bgpSrcNokia)
	r.Truncated = trunc
	for idx, v := range states {
		a, ok := parseArcs(idx)
		if !ok || len(a) < 2 || !isIntegerTag(v.tag) || !bgpStateOK(v.int()) {
			r.Dropped++
			continue
		}
		peer, _, ok := inetFromArcs(a[1:])
		if !ok {
			r.Dropped++
			continue
		}
		id := strconv.Itoa(a[0])
		vrf := ""
		if t, has := types[id]; has && t.int() == 1 { // baseRouter
			vrf = defaultVRF
		} else if nv, has := names[id]; has {
			vrf, _ = vrfName(strings.TrimSpace(string(nv.raw)))
		}
		if vrf == "" {
			r.Dropped++ // an instance we cannot name is not guessed at
			continue
		}
		p := r.peer(vrf, peer)
		p.State = v.int()
		if av, has := ases[idx]; has && isIntegerTag(av.tag) {
			p.RemoteAS = av.int()
		}
	}
	return r, nil
}

// ── Huawei ──────────────────────────────────────────────────────────────────

var (
	hwBgpPeerAFEntry = []int{1, 3, 6, 1, 4, 1, 2011, 5, 25, 177, 1, 1, 1, 1}
	hwBgpPeerEntry   = []int{1, 3, 6, 1, 4, 1, 2011, 5, 25, 177, 1, 1, 2, 1}
)

// readHuaweiBGP: one row per (instance, AFI, SAFI, peer); folded per (vrf, peer).
// INDEX {InstanceId, Afi, Safi, Type, IPAddr}.
func readHuaweiBGP(ctx context.Context, e bgpEnv) (*bgpVRFReading, error) {
	states, trunc, err := e.walk(ctx, e.addr, e.cr, oidPlus(hwBgpPeerEntry, 5), e.max)
	if err != nil || len(states) == 0 {
		return nil, err
	}
	names, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(hwBgpPeerAFEntry, 6), e.max)
	ases, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(hwBgpPeerEntry, 2), e.max)
	r := newBGPReading(bgpSrcHuawei)
	r.Truncated = trunc
	for idx, v := range states {
		a, ok := parseArcs(idx)
		if !ok || len(a) < 4 || !isIntegerTag(v.tag) || !bgpStateOK(v.int()) {
			r.Dropped++
			continue
		}
		peer, _, ok := inetFromArcs(a[3:])
		if !ok {
			r.Dropped++
			continue
		}
		vrf := defaultVRF
		if a[0] != 0 {
			vrf = ""
			if nv, has := names[idx]; has {
				vrf, _ = vrfName(strings.TrimSpace(string(nv.raw)))
			}
			if vrf == "" {
				r.Dropped++
				continue
			}
		}
		p := r.peer(vrf, peer)
		if v.int() > p.State {
			p.State = v.int() // best state across the peer's address families
		}
		if av, has := ases[idx]; has && isIntegerTag(av.tag) {
			p.RemoteAS = av.int()
		}
	}
	return r, nil
}

// ── Viptela vEdge ───────────────────────────────────────────────────────────

var viptelaBGPNbrEntry = []int{1, 3, 6, 1, 4, 1, 41916, 14, 3, 1}

// viptelaBGPState maps the ZERO-based vEdge enum (idle0 … established5,
// clearing6, deleted7) onto the standard 1..6. Without this a clearing session
// (raw 6) would read as established. deleted → dropped.
func viptelaBGPState(n int64) (int64, bool) {
	switch {
	case n >= 0 && n <= 5:
		return n + 1, true
	case n == 6:
		return 1, true
	}
	return 0, false
}

func readViptelaBGP(ctx context.Context, e bgpEnv) (*bgpVRFReading, error) {
	states, trunc, err := e.walk(ctx, e.addr, e.cr, oidPlus(viptelaBGPNbrEntry, 10), e.max)
	if err != nil || len(states) == 0 {
		return nil, err
	}
	ases, _, _ := e.walk(ctx, e.addr, e.cr, oidPlus(viptelaBGPNbrEntry, 2), e.max)
	r := newBGPReading(bgpSrcViptela)
	r.Truncated = trunc
	for idx, v := range states {
		a, ok := parseArcs(idx)
		if !ok || len(a) != 5 || a[0] > 65531 || !isIntegerTag(v.tag) {
			r.Dropped++
			continue
		}
		st, ok := viptelaBGPState(v.int())
		peer := arcsAddr(a[1:])
		if !ok || peer == "" {
			r.Dropped++
			continue
		}
		p := r.peer(strconv.Itoa(a[0]), peer) // the VPN id is the name, as in device_vrf_info
		p.State = st
		if av, has := ases[idx]; has && isIntegerTag(av.tag) {
			p.RemoteAS = av.int()
		}
	}
	return r, nil
}

// ── order, dedupe, emission ─────────────────────────────────────────────────

var (
	bgpP3      = bgpSource{bgpSrcCiscoP3, readCiscoPeer3}
	bgpP2      = bgpSource{bgpSrcCiscoP2, readCiscoPeer2}
	bgpNokia   = bgpSource{bgpSrcNokia, readNokiaBGP}
	bgpHuawei  = bgpSource{bgpSrcHuawei, readHuaweiBGP}
	bgpViptela = bgpSource{bgpSrcViptela, readViptelaBGP}
)

func bgpSourcesFor(enterprise int, known bool) []bgpSource {
	if !known {
		return []bgpSource{bgpP2} // SONiC (net-snmp enterprise) implements only cbgpPeer2
	}
	switch enterprise {
	case 9:
		return []bgpSource{bgpP3, bgpP2}
	case 6527:
		return []bgpSource{bgpNokia}
	case 2011:
		return []bgpSource{bgpHuawei}
	case 41916:
		return []bgpSource{bgpViptela}
	}
	return []bgpSource{bgpP2}
}

// dedupe drops default-instance IPv4 rows BGP4-MIB already publishes. A row
// whose instance could not be NAMED ("vrf-id N") and whose peer BGP4-MIB
// lists is treated the same way: which VrfId a release gives the global
// table is not documented, and publishing a global peer twice is worse than
// missing an unnamed VRF peer with an overlapping address.
func (r *bgpVRFReading) dedupe(bgp4 map[string]bool) {
	for k, p := range r.Peers {
		if p.VRF != defaultVRF && !strings.HasPrefix(p.VRF, "vrf-id ") {
			continue
		}
		if a, err := netip.ParseAddr(p.Peer); err == nil && a.Is4() && bgp4[p.Peer] {
			delete(r.Peers, k)
		}
	}
}

func bgpVRFLines(device string, r *bgpVRFReading, now int64) []string {
	keys := make([]string, 0, len(r.Peers))
	for k := range r.Peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		p := r.Peers[k]
		out = append(out, fmt.Sprintf(`device_bgp_peer_state{device=%q,peer=%q,vrf=%q,mib=%q} %d %d`,
			device, p.Peer, sanitizeLabel(p.VRF), r.Source, p.State, now))
		if p.RemoteAS > 0 {
			out = append(out, fmt.Sprintf(`device_bgp_peer_remote_as{device=%q,peer=%q,vrf=%q,mib=%q} %d %d`,
				device, p.Peer, sanitizeLabel(p.VRF), r.Source, p.RemoteAS, now))
		}
	}
	t := 0
	if r.Truncated {
		t = 1
	}
	return append(out,
		fmt.Sprintf(`collector_bgp_vrf_walk_truncated{device=%q} %d %d`, device, t, now),
		fmt.Sprintf(`collector_bgp_vrf_rows_dropped{device=%q} %d %d`, device, r.Dropped, now))
}

// ── the collector ───────────────────────────────────────────────────────────

type bgpVRFCollector struct {
	interval time.Duration
	workers  int
	maxRows  int
	targets  TargetFunc
	walk     walkFn
	get      getFn

	stMu   sync.Mutex
	source map[string]string

	mu     sync.RWMutex
	status Status
}

// NewBGPVRFPeers builds the routing-instance BGP peer collector.
func NewBGPVRFPeers(targets TargetFunc) Collector {
	return &bgpVRFCollector{
		interval: time.Minute, // BGP alerts fire after 2 m
		workers:  envIntBounded("BGP_VRF_WORKERS", 8, 1, 64),
		maxRows:  envIntBounded("BGP_VRF_MAX_PEERS", 4096, 16, 100000),
		targets:  targets,
		walk:     snmpWalkColumnBounded,
		get:      snmpGet,
		source:   map[string]string{},
		status:   Status{Name: "bgp_vrf_peers", Healthy: true, Kind: "metrics"},
	}
}

func (c *bgpVRFCollector) Name() string { return "bgp_vrf_peers" }

func (c *bgpVRFCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *bgpVRFCollector) Run(ctx context.Context) error {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	c.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.pollOnce(ctx)
		}
	}
}

type bgpVRFResult struct {
	id       string
	answered bool
	skipped  bool // gNMI owns BGP on this device
	reading  *bgpVRFReading
	err      string
}

func (r bgpVRFResult) capability() string {
	switch {
	case r.skipped:
		return "gnmi"
	case r.reading != nil:
		return r.reading.Source
	case r.answered && r.err == "":
		return "no_peers"
	case r.answered:
		return "walk_failed"
	}
	return "not_answering"
}

var bgpVRFFailLogAt atomic.Int64

func (c *bgpVRFCollector) pollOnce(ctx context.Context) {
	var targets []Target
	if c.targets != nil {
		targets = c.targets()
	}
	start := time.Now()
	jobs := make(chan Target)
	results := make(chan bgpVRFResult, len(targets))
	var wg sync.WaitGroup
	for w := 0; w < c.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tg := range jobs {
				results <- c.pollDevice(ctx, tg)
			}
		}()
	}
	for _, tg := range targets {
		select {
		case jobs <- tg:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	now := start.UnixMilli()
	var lines []string
	answered := 0
	var lastErr string
	for r := range results {
		if r.answered {
			answered++
		}
		if r.err != "" {
			lastErr = r.err
		}
		if r.reading != nil {
			lines = append(lines, bgpVRFLines(r.id, r.reading, now)...)
		}
		lines = append(lines, fmt.Sprintf(`device_bgp_vrf_capability{device=%q,mib=%q} 1 %d`, r.id, r.capability(), now))
	}
	healthy := cycleHealthy(len(targets), answered)
	lines = append(lines,
		collectorUpLine("bgp_vrf_peers", healthy, now),
		fmt.Sprintf(`collector_targets{collector="bgp_vrf_peers"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="bgp_vrf_peers"} %d %d`, answered, now),
	)
	emitMetrics(ctx, strings.Join(lines, "\n"))

	c.mu.Lock()
	c.status.LastTick = start.UTC()
	c.status.Targets = len(targets)
	c.status.Reachable = answered
	c.status.LastPollMillis = time.Since(start).Milliseconds()
	c.status.Healthy = healthy
	c.status.LastError = cycleError(len(targets), answered, lastErr)
	c.mu.Unlock()
}

func (c *bgpVRFCollector) pollDevice(ctx context.Context, tg Target) bgpVRFResult {
	res := bgpVRFResult{id: tg.ID}
	if tg.hasTransport("gnmi") {
		res.skipped = true // gNMI owns BGP here, VRF peers included
		return res
	}
	addr := withPort(tg.Address, 161)
	creds := tg.creds()
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	v, err := c.get(dctx, addr, creds, sysObjectIDOID)
	if err != nil {
		res.err = err.Error()
		return res
	}
	res.answered = true
	ent, known := 0, false
	if v.tag == 0x06 {
		ent, known = enterpriseOf(decodeOID(v.raw))
	}
	sources := bgpSourcesFor(ent, known)
	c.stMu.Lock()
	last := c.source[tg.ID]
	c.stMu.Unlock()
	for i, s := range sources {
		if s.name == last && i > 0 {
			sources = append([]bgpSource{s}, append(append([]bgpSource{}, sources[:i]...), sources[i+1:]...)...)
			break
		}
	}
	e := bgpEnv{walk: c.walk, addr: addr, cr: creds, max: c.maxRows}
	var reading *bgpVRFReading
	var lastErr error
	for _, s := range sources {
		r, err := s.read(dctx, e)
		if err != nil {
			lastErr = err
			continue
		}
		if r != nil {
			reading = r
			break
		}
	}
	if reading == nil {
		c.stMu.Lock()
		delete(c.source, tg.ID)
		c.stMu.Unlock()
		if lastErr != nil {
			res.err = lastErr.Error()
			if now := time.Now().Unix(); now-bgpVRFFailLogAt.Load() >= 60 {
				bgpVRFFailLogAt.Store(now)
				log.Printf("bgp_vrf_peers: walk FAILED device=%s: %v — VRF BGP peers are unknown this cycle, not absent", tg.ID, lastErr)
			}
		}
		return res
	}
	// The generic poller already publishes BGP4-MIB's default-instance peers.
	bgp4 := map[string]bool{}
	if rows, _, err := c.walk(dctx, addr, creds, bgp4PeerState, c.maxRows); err == nil {
		for idx := range rows {
			if a, ok := parseArcs(idx); ok && len(a) == 4 {
				if s := arcsAddr(a); s != "" {
					bgp4[s] = true
				}
			}
		}
	}
	reading.dedupe(bgp4)
	c.stMu.Lock()
	c.source[tg.ID] = reading.Source
	c.stMu.Unlock()
	res.reading = reading
	return res
}
