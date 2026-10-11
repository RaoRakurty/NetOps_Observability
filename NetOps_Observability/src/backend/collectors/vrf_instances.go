// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// vrf_instances.go — routing instances (VRF / VPN / routing-instance / VPRN)
// and which interfaces belong to each, read over SNMP from whichever MIB the
// device answers. Capability-first: each source is probed in the device's
// vendor order and the FIRST one that answers is used (and remembered), so a
// device is never double-counted from two MIBs. What answered is published
// with every series (`source`), and a device that answers none is reported as
// such — never as "no VRFs".
//
// Sources (numeric OIDs compiled with snmptranslate from the published MIBs):
//
//	mpls-l3vpn   MPLS-L3VPN-STD-MIB (RFC 4382)      1.3.6.1.2.1.10.166.11  Cisco IOS-XE/XR, NX-OS 7k, Huawei, Juniper (draft root), others
//	mpls-vpn     MPLS-VPN-MIB (draft, older Cisco)   1.3.6.1.3.118          IfConf columns differ from RFC 4382 (.3 not .2)
//	cisco-vrf    CISCO-VRF-MIB                       1.3.6.1.4.1.9.9.711    VRF-lite (no RD); probe-only fallback
//	juniper-vpn  JUNIPER-VPN-MIB (bgpIpVpn rows)     1.3.6.1.4.1.2636.3.26  Junos instance-type vrf
//	arista-vrf   ARISTA-VRF-MIB                      1.3.6.1.4.1.30065.3.18
//	nokia-vrtr   TIMETRA-VRTR-MIB (VPRN / VR)        1.3.6.1.4.1.6527.3.1.2.3  SR OS
//	viptela-vpn  VIPTELA-OPER-VPN interfaceTable     1.3.6.1.4.1.41916.12.2.1  vEdge VPNs
//
// Not over SNMP (stated, not guessed): SONiC (sonic-snmpagent implements no VRF
// MIB), Nokia SR Linux and Juniper virtual-router instances — those come from
// gNMI network-instance paths.

// VRF source names (the `source` label).
const (
	vrfSrcL3VPN   = "mpls-l3vpn"
	vrfSrcMPLSVPN = "mpls-vpn"
	vrfSrcCisco   = "cisco-vrf"
	vrfSrcJuniper = "juniper-vpn"
	vrfSrcArista  = "arista-vrf"
	vrfSrcNokia   = "nokia-vrtr"
	vrfSrcViptela = "viptela-vpn"
)

// vrfKind is the vendor's own word for the instance, carried as the `kind`
// label so the UI can say "VPN 10" on a vEdge and "VPRN" on SR OS.
var vrfKind = map[string]string{
	vrfSrcL3VPN: "vrf", vrfSrcMPLSVPN: "vrf", vrfSrcCisco: "vrf", vrfSrcJuniper: "routing-instance",
	vrfSrcArista: "vrf", vrfSrcNokia: "vprn", vrfSrcViptela: "vpn",
}

// vrfInstance is one routing instance read from a device.
type vrfInstance struct {
	Name string
	Kind string
	RD   string
	Oper int // 1 up, 2 down, 0 unknown (the source has no oper column)
}

// vrfReading is everything one source yielded for one device.
type vrfReading struct {
	Source    string
	Instances map[string]*vrfInstance
	Members   map[string]map[string]bool // vrf → set of ifName
	Dropped   int                        // rows refused by validation
	Truncated bool
}

func newVRFReading(src string) *vrfReading {
	return &vrfReading{Source: src, Instances: map[string]*vrfInstance{}, Members: map[string]map[string]bool{}}
}

func (r *vrfReading) instance(name string) *vrfInstance {
	in := r.Instances[name]
	if in == nil {
		in = &vrfInstance{Name: name, Kind: vrfKind[r.Source]}
		r.Instances[name] = in
	}
	return in
}

func (r *vrfReading) member(vrf, ifName string) {
	m := r.Members[vrf]
	if m == nil {
		m = map[string]bool{}
		r.Members[vrf] = m
	}
	m[ifName] = true
}

// vrfLimits bounds every walk (§9).
type vrfLimits struct {
	maxInstances int
	maxMembers   int
}

// vrfEnv is what a source reader needs: a bounded walk and the device's
// ifIndex → ifName map (walked lazily, once).
type vrfEnv struct {
	walk    walkFn
	addr    string
	creds   snmpCreds
	lim     vrfLimits
	ifNames func() map[string]string
}

type vrfSource struct {
	name string
	read func(ctx context.Context, e vrfEnv) (*vrfReading, error)
}

func oidPlus(base []int, more ...int) []int {
	return append(append([]int{}, base...), more...)
}

func arcsOf(idx string) []int {
	a, ok := parseArcs(idx)
	if !ok {
		return nil
	}
	return a
}

// ── RFC 4382 and its draft predecessor ──────────────────────────────────────

var (
	l3vpnVrfEntry   = []int{1, 3, 6, 1, 2, 1, 10, 166, 11, 1, 2, 2, 1}
	l3vpnIfConf     = []int{1, 3, 6, 1, 2, 1, 10, 166, 11, 1, 2, 1, 1}
	mplsVpnVrfEntry = []int{1, 3, 6, 1, 3, 118, 1, 2, 2, 1}
	mplsVpnIfConf   = []int{1, 3, 6, 1, 3, 118, 1, 2, 1, 1}
)

// readL3VPNFamily reads either MIB. They share the VrfTable layout (.4 RD,
// .6 OperStatus) and index encoding, but NOT the IfConf column numbers:
// Classification is .2 in RFC 4382 and .3 in the draft.
func readL3VPNFamily(src string, vrfEntry, ifConf []int, ifClassCol int) func(ctx context.Context, e vrfEnv) (*vrfReading, error) {
	return func(ctx context.Context, e vrfEnv) (*vrfReading, error) {
		oper, trunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(vrfEntry, 6), e.lim.maxInstances)
		if err != nil || len(oper) == 0 {
			return nil, err
		}
		r := newVRFReading(src)
		r.Truncated = trunc
		for idx, v := range oper {
			name, _, ok := splitLenString(arcsOf(idx), 0)
			if !ok || !isIntegerTag(v.tag) {
				r.Dropped++
				continue
			}
			in := r.instance(name)
			if n := v.int(); n == 1 || n == 2 {
				in.Oper = int(n)
			}
		}
		if rds, _, err := e.walk(ctx, e.addr, e.creds, oidPlus(vrfEntry, 4), e.lim.maxInstances); err == nil {
			for idx, v := range rds {
				if name, _, ok := splitLenString(arcsOf(idx), 0); ok && r.Instances[name] != nil {
					r.Instances[name].RD = renderRD(v.raw)
				}
			}
		}
		mem, mtrunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(ifConf, ifClassCol), e.lim.maxMembers)
		if err == nil {
			r.Truncated = r.Truncated || mtrunc
			names := e.ifNames()
			for idx := range mem {
				name, rest, ok := splitLenString(arcsOf(idx), 1)
				if !ok || r.Instances[name] == nil {
					r.Dropped++
					continue
				}
				ifName := names[strconv.Itoa(rest[0])]
				if ifName == "" {
					r.Dropped++ // an ifIndex the device's IF-MIB does not name
					continue
				}
				r.member(name, ifName)
			}
		}
		return r, nil
	}
}

// ── CISCO-VRF-MIB ───────────────────────────────────────────────────────────

var (
	ciscoVrfEntry   = []int{1, 3, 6, 1, 4, 1, 9, 9, 711, 1, 1, 1, 1}
	ciscoVrfIfEntry = []int{1, 3, 6, 1, 4, 1, 9, 9, 711, 1, 2, 1, 1}
)

func readCiscoVRF(ctx context.Context, e vrfEnv) (*vrfReading, error) {
	names, trunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(ciscoVrfEntry, 2), e.lim.maxInstances)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	r := newVRFReading(vrfSrcCisco)
	r.Truncated = trunc
	byIndex := map[string]string{}
	for idx, v := range names {
		name, ok := vrfName(strings.TrimSpace(string(v.raw)))
		if !ok || v.tag != 0x04 {
			r.Dropped++
			continue
		}
		byIndex[idx] = name
		r.instance(name)
	}
	if oper, _, err := e.walk(ctx, e.addr, e.creds, oidPlus(ciscoVrfEntry, 4), e.lim.maxInstances); err == nil {
		for idx, v := range oper {
			if name := byIndex[idx]; name != "" && isIntegerTag(v.tag) {
				if n := v.int(); n == 1 || n == 2 {
					r.Instances[name].Oper = int(n)
				}
			}
		}
	}
	if mem, mtrunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(ciscoVrfIfEntry, 2), e.lim.maxMembers); err == nil {
		r.Truncated = r.Truncated || mtrunc
		ifn := e.ifNames()
		for idx := range mem {
			a := arcsOf(idx)
			if len(a) != 2 {
				r.Dropped++
				continue
			}
			name, ifName := byIndex[strconv.Itoa(a[0])], ifn[strconv.Itoa(a[1])]
			if name == "" || ifName == "" {
				r.Dropped++
				continue
			}
			r.member(name, ifName)
		}
	}
	return r, nil
}

// ── JUNIPER-VPN-MIB ─────────────────────────────────────────────────────────

var (
	jnxVpnEntry   = []int{1, 3, 6, 1, 4, 1, 2636, 3, 26, 1, 2, 1}
	jnxVpnIfEntry = []int{1, 3, 6, 1, 4, 1, 2636, 3, 26, 1, 3, 1}
)

// jnxBgpIPVpn is jnxVpnType bgpIpVpn(2) — Junos `instance-type vrf`. Other
// types (L2VPN, VPLS, circuits) are not routing instances in this sense.
const jnxBgpIPVpn = 2

func readJuniperVPN(ctx context.Context, e vrfEnv) (*vrfReading, error) {
	rows, trunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(jnxVpnEntry, 3), e.lim.maxInstances)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	r := newVRFReading(vrfSrcJuniper)
	r.Truncated = trunc
	for idx := range rows {
		a := arcsOf(idx)
		if len(a) < 2 || a[0] != jnxBgpIPVpn {
			continue // not an L3 VRF: skipped, not an error
		}
		name, _, ok := splitLenString(a[1:], 0)
		if !ok {
			r.Dropped++
			continue
		}
		r.instance(name)
	}
	if len(r.Instances) == 0 {
		return r, nil // the MIB answered; this device has no L3 VRFs
	}
	if ids, _, err := e.walk(ctx, e.addr, e.creds, oidPlus(jnxVpnEntry, 7), e.lim.maxInstances); err == nil {
		for idx, v := range ids {
			a := arcsOf(idx)
			if len(a) < 2 || a[0] != jnxBgpIPVpn {
				continue
			}
			if name, _, ok := splitLenString(a[1:], 0); ok && r.Instances[name] != nil {
				r.Instances[name].RD = renderRD(v.raw)
			}
		}
	}
	// jnxVpnIfIndex is "the index of this interface in the VPN" in the MIB
	// text, not guaranteed to be ifIndex: a value IF-MIB does not name is
	// dropped and counted rather than published as membership.
	if mem, mtrunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(jnxVpnIfEntry, 10), e.lim.maxMembers); err == nil {
		r.Truncated = r.Truncated || mtrunc
		ifn := e.ifNames()
		for idx := range mem {
			a := arcsOf(idx)
			if len(a) < 3 || a[0] != jnxBgpIPVpn {
				continue
			}
			name, rest, ok := splitLenString(a[1:], 1)
			ifName := ""
			if ok {
				ifName = ifn[strconv.Itoa(rest[0])]
			}
			if !ok || ifName == "" || r.Instances[name] == nil {
				r.Dropped++
				continue
			}
			r.member(name, ifName)
		}
	}
	return r, nil
}

// ── ARISTA-VRF-MIB ──────────────────────────────────────────────────────────

var (
	aristaVrfEntry   = []int{1, 3, 6, 1, 4, 1, 30065, 3, 18, 1, 1, 1}
	aristaVrfIfEntry = []int{1, 3, 6, 1, 4, 1, 30065, 3, 18, 1, 2, 1}
)

func readAristaVRF(ctx context.Context, e vrfEnv) (*vrfReading, error) {
	state, trunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(aristaVrfEntry, 4), e.lim.maxInstances)
	if err != nil || len(state) == 0 {
		return nil, err
	}
	r := newVRFReading(vrfSrcArista)
	r.Truncated = trunc
	for idx, v := range state {
		name, _, ok := splitLenString(arcsOf(idx), 0)
		if !ok || !isIntegerTag(v.tag) {
			r.Dropped++
			continue
		}
		in := r.instance(name)
		switch v.int() { // active(1) / inactive(2)
		case 1:
			in.Oper = 1
		case 2:
			in.Oper = 2
		}
	}
	if rds, _, err := e.walk(ctx, e.addr, e.creds, oidPlus(aristaVrfEntry, 3), e.lim.maxInstances); err == nil {
		for idx, v := range rds {
			if name, _, ok := splitLenString(arcsOf(idx), 0); ok && r.Instances[name] != nil {
				r.Instances[name].RD = renderRD(v.raw)
			}
		}
	}
	// Membership: INDEX {ifIndex}, the VRF name is the VALUE. Rows exist only
	// for active routed interfaces, so a down interface drops out of the list.
	if mem, mtrunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(aristaVrfIfEntry, 1), e.lim.maxMembers); err == nil {
		r.Truncated = r.Truncated || mtrunc
		ifn := e.ifNames()
		for idx, v := range mem {
			name, ok := vrfName(strings.TrimSpace(string(v.raw)))
			ifName := ifn[idx]
			if !ok || ifName == "" {
				r.Dropped++
				continue
			}
			r.instance(name)
			r.member(name, ifName)
		}
	}
	return r, nil
}

// ── TIMETRA-VRTR-MIB (Nokia SR OS) ──────────────────────────────────────────

var (
	vRtrConfEntry = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 3, 1, 1}
	vRtrStatEntry = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 3, 2, 1}
	vRtrIfEntry   = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 3, 4, 1}
)

func readNokiaVRtr(ctx context.Context, e vrfEnv) (*vrfReading, error) {
	types, trunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(vRtrConfEntry, 28), e.lim.maxInstances)
	if err != nil || len(types) == 0 {
		return nil, err
	}
	names, _, err := e.walk(ctx, e.addr, e.creds, oidPlus(vRtrConfEntry, 4), e.lim.maxInstances)
	if err != nil {
		return nil, err
	}
	r := newVRFReading(vrfSrcNokia)
	r.Truncated = trunc
	byID := map[string]string{}
	for id, t := range types {
		kind := ""
		switch t.int() { // baseRouter(1) is the global table, not an instance
		case 2:
			kind = "vprn"
		case 3:
			kind = "vr"
		default:
			continue
		}
		v, has := names[id]
		name, ok := "", false
		if has {
			name, ok = vrfName(strings.TrimSpace(string(v.raw)))
		}
		if !ok {
			r.Dropped++
			continue
		}
		byID[id] = name
		r.instance(name).Kind = kind
	}
	if rds, _, err := e.walk(ctx, e.addr, e.creds, oidPlus(vRtrConfEntry, 19), e.lim.maxInstances); err == nil {
		for id, v := range rds {
			if name := byID[id]; name != "" {
				r.Instances[name].RD = renderRD(v.raw)
			}
		}
	}
	if oper, _, err := e.walk(ctx, e.addr, e.creds, oidPlus(vRtrStatEntry, 1), e.lim.maxInstances); err == nil {
		for id, v := range oper {
			if name := byID[id]; name != "" {
				switch v.int() { // TmnxOperState inService(2) / outOfService(3)
				case 2:
					r.Instances[name].Oper = 1
				case 3:
					r.Instances[name].Oper = 2
				}
			}
		}
	}
	// Membership: vRtrIfName — the router interface's own name. Whether SR OS
	// vRtrIfIndex equals the IF-MIB ifIndex is not documented, so the Nokia
	// interface name is used as published, not joined through ifIndex.
	if mem, mtrunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(vRtrIfEntry, 4), e.lim.maxMembers); err == nil {
		r.Truncated = r.Truncated || mtrunc
		for idx, v := range mem {
			a := arcsOf(idx)
			if len(a) != 2 {
				r.Dropped++
				continue
			}
			name := byID[strconv.Itoa(a[0])]
			ifName := sanitizeLabel(strings.TrimSpace(string(v.raw)))
			if name == "" || ifName == "" {
				continue // an interface of the base router, or unnamed
			}
			r.member(name, ifName)
		}
	}
	return r, nil
}

// ── VIPTELA-OPER-VPN (vEdge) ────────────────────────────────────────────────

var viptelaIfEntry = []int{1, 3, 6, 1, 4, 1, 41916, 12, 2, 1, 1}

// readViptelaVPN: there is no VPN-list table; the VPNs are the distinct vpn-ids
// of interfaceTable, INDEX {VpnId, Ifname, AfType} = vpn, len, name…, af. Each
// interface appears once per address family, so membership is a set.
func readViptelaVPN(ctx context.Context, e vrfEnv) (*vrfReading, error) {
	rows, trunc, err := e.walk(ctx, e.addr, e.creds, oidPlus(viptelaIfEntry, 11), e.lim.maxMembers)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	r := newVRFReading(vrfSrcViptela)
	r.Truncated = trunc
	for idx := range rows {
		a := arcsOf(idx)
		if len(a) < 3 || a[0] > 65530 {
			r.Dropped++
			continue
		}
		ifName, _, ok := splitLenString(a[1:], 1)
		if !ok {
			r.Dropped++
			continue
		}
		vpn := strconv.Itoa(a[0])
		r.instance(vpn)
		r.member(vpn, sanitizeLabel(ifName))
	}
	return r, nil
}

// ── source order per vendor ─────────────────────────────────────────────────

var (
	srcL3VPN   = vrfSource{vrfSrcL3VPN, readL3VPNFamily(vrfSrcL3VPN, l3vpnVrfEntry, l3vpnIfConf, 2)}
	srcMPLSVPN = vrfSource{vrfSrcMPLSVPN, readL3VPNFamily(vrfSrcMPLSVPN, mplsVpnVrfEntry, mplsVpnIfConf, 3)}
	srcCisco   = vrfSource{vrfSrcCisco, readCiscoVRF}
	srcJuniper = vrfSource{vrfSrcJuniper, readJuniperVPN}
	srcArista  = vrfSource{vrfSrcArista, readAristaVRF}
	srcNokia   = vrfSource{vrfSrcNokia, readNokiaVRtr}
	srcViptela = vrfSource{vrfSrcViptela, readViptelaVPN}
)

// vrfSourcesFor returns the probe order for a device's enterprise number:
// the vendor's own MIB first where it is the better source, then the
// standard, then the draft. Unknown vendors get the standards.
func vrfSourcesFor(enterprise int, known bool) []vrfSource {
	if !known {
		return []vrfSource{srcL3VPN, srcMPLSVPN}
	}
	switch enterprise {
	case 41916: // Viptela vEdge
		return []vrfSource{srcViptela}
	case 9: // Cisco IOS / IOS-XE (incl. SD-WAN cEdge) / IOS-XR / NX-OS
		return []vrfSource{srcL3VPN, srcMPLSVPN, srcCisco}
	case 2636: // Juniper
		return []vrfSource{srcJuniper, srcL3VPN, srcMPLSVPN}
	case 30065: // Arista
		return []vrfSource{srcArista, srcL3VPN}
	case 6527: // Nokia SR OS
		return []vrfSource{srcNokia}
	}
	return []vrfSource{srcL3VPN, srcMPLSVPN}
}

// readVRFs probes the sources in order; the first that answers wins.
// ok=false means none answered.
func readVRFs(ctx context.Context, sources []vrfSource, e vrfEnv) (*vrfReading, error) {
	var lastErr error
	for _, s := range sources {
		r, err := s.read(ctx, e)
		if err != nil {
			lastErr = err
			continue
		}
		if r != nil {
			return r, nil
		}
	}
	return nil, lastErr
}

// vrfLines renders a reading as metric lines.
func vrfLines(device string, r *vrfReading, now int64) []string {
	names := make([]string, 0, len(r.Instances))
	for n := range r.Instances {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		in := r.Instances[n]
		out = append(out, fmt.Sprintf("device_vrf_info{device=%q,vrf=%q,kind=%q,rd=%q,source=%q} 1 %d",
			device, sanitizeLabel(n), in.Kind, sanitizeLabel(in.RD), r.Source, now))
		if in.Oper != 0 {
			out = append(out, fmt.Sprintf("device_vrf_oper_status{device=%q,vrf=%q,source=%q} %d %d",
				device, sanitizeLabel(n), r.Source, in.Oper, now))
		}
		ifs := make([]string, 0, len(r.Members[n]))
		for i := range r.Members[n] {
			ifs = append(ifs, i)
		}
		sort.Strings(ifs)
		for _, i := range ifs {
			out = append(out, fmt.Sprintf("device_vrf_if_info{device=%q,vrf=%q,ifName=%q,source=%q} 1 %d",
				device, sanitizeLabel(n), sanitizeLabel(i), r.Source, now))
		}
	}
	t := 0
	if r.Truncated {
		t = 1
	}
	out = append(out,
		fmt.Sprintf("collector_vrf_walk_truncated{device=%q} %d %d", device, t, now),
		fmt.Sprintf("collector_vrf_rows_dropped{device=%q} %d %d", device, r.Dropped, now))
	return out
}

// ── the collector ───────────────────────────────────────────────────────────

type vrfCollector struct {
	// emitEvery is how often the series are (re)published; refresh is how
	// often a device is actually walked. Membership changes rarely, but a
	// series published only every refresh would go stale between walks
	// (the metric store's lookback is 5 m), so the last reading is re-emitted.
	emitEvery time.Duration
	refresh   time.Duration
	workers   int
	lim       vrfLimits
	targets   TargetFunc
	walk      walkFn
	get       getFn
	ifNames   func(ctx context.Context, addr string, creds snmpCreds) map[string]string

	stMu   sync.Mutex
	source map[string]string    // device → the source that answered last time
	cache  map[string]vrfResult // device → last walk result
	walked map[string]time.Time // device → when it was last walked
	now    func() time.Time

	mu     sync.RWMutex
	status Status
}

// NewVRFInstances builds the routing-instance collector.
func NewVRFInstances(targets TargetFunc) Collector {
	return &vrfCollector{
		emitEvery: time.Minute,
		refresh:   envDuration("VRF_POLL_INTERVAL", 10*time.Minute),
		workers:   envIntBounded("VRF_WORKERS", 8, 1, 64),
		lim: vrfLimits{
			maxInstances: envIntBounded("VRF_MAX_INSTANCES", 4096, 16, 65536),
			maxMembers:   envIntBounded("VRF_MAX_MEMBERS", 16384, 64, 262144),
		},
		targets: targets,
		walk:    snmpWalkColumnBounded,
		get:     snmpGet,
		ifNames: ifNameMap,
		source:  map[string]string{},
		cache:   map[string]vrfResult{},
		walked:  map[string]time.Time{},
		now:     time.Now,
		status:  Status{Name: "vrf_instances", Healthy: true, Kind: "discovery"},
	}
}

func (c *vrfCollector) Name() string { return "vrf_instances" }

func (c *vrfCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *vrfCollector) Run(ctx context.Context) error {
	t := time.NewTicker(c.emitEvery)
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

type vrfResult struct {
	id       string
	answered bool
	reading  *vrfReading
	err      string
}

// capability is the device_vrf_capability label: the source that answered,
// "no_instances" when the agent answered SNMP but no routing-instance MIB,
// "walk_failed" when it answered but a routing-instance walk errored (so
// "none" would be a guess), or "not_answering" when it did not answer at all.
func (r vrfResult) capability() string {
	switch {
	case r.reading != nil:
		return r.reading.Source
	case r.answered && r.err == "":
		return "no_instances"
	case r.answered:
		return "walk_failed"
	}
	return "not_answering"
}

// vrfFailLogAt rate-limits the walk-failure log (one line a minute across the
// collector; device_vrf_capability carries every device's state).
var vrfFailLogAt atomic.Int64

func logVRFFailure(device, err string) {
	now := time.Now().Unix()
	if last := vrfFailLogAt.Load(); now-last >= 60 && vrfFailLogAt.CompareAndSwap(last, now) {
		log.Printf("vrf_instances: routing-instance walk FAILED device=%s: %s — its instances are unknown this cycle, not absent", device, err)
	}
}

func (c *vrfCollector) pollOnce(ctx context.Context) {
	var targets []Target
	if c.targets != nil {
		targets = c.targets()
	}
	start := time.Now()
	jobs := make(chan Target)
	results := make(chan vrfResult, len(targets))
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
	answered, withVRFs := 0, 0
	var lastErr string
	for r := range results {
		if r.answered {
			answered++
		}
		if r.err != "" {
			lastErr = r.err
		}
		if r.reading != nil {
			if len(r.reading.Instances) > 0 {
				withVRFs++
			}
			lines = append(lines, vrfLines(r.id, r.reading, now)...)
		}
		lines = append(lines, fmt.Sprintf("device_vrf_capability{device=%q,source=%q} 1 %d", r.id, r.capability(), now))
	}
	c.forgetGone(targets)
	healthy := cycleHealthy(len(targets), answered)
	lines = append(lines,
		collectorUpLine("vrf_instances", healthy, now),
		fmt.Sprintf(`collector_targets{collector="vrf_instances"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="vrf_instances"} %d %d`, answered, now),
		fmt.Sprintf(`collector_vrf_devices_with_instances{collector="vrf_instances"} %d %d`, withVRFs, now),
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

// forgetGone drops cached state for devices no longer in the inventory, so the
// cache is bounded by the inventory.
func (c *vrfCollector) forgetGone(targets []Target) {
	live := make(map[string]bool, len(targets))
	for _, tg := range targets {
		live[tg.ID] = true
	}
	c.stMu.Lock()
	defer c.stMu.Unlock()
	for id := range c.cache {
		if !live[id] {
			delete(c.cache, id)
			delete(c.walked, id)
			delete(c.source, id)
		}
	}
}

// pollDevice returns the cached result while it is fresh, else walks.
func (c *vrfCollector) pollDevice(ctx context.Context, tg Target) vrfResult {
	c.stMu.Lock()
	cached, has := c.cache[tg.ID]
	at := c.walked[tg.ID]
	c.stMu.Unlock()
	if has && c.now().Sub(at) < c.refresh {
		return cached
	}
	res := c.walkDevice(ctx, tg)
	c.stMu.Lock()
	c.cache[tg.ID] = res
	c.walked[tg.ID] = c.now()
	c.stMu.Unlock()
	return res
}

func (c *vrfCollector) walkDevice(ctx context.Context, tg Target) vrfResult {
	res := vrfResult{id: tg.ID}
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
	sources := vrfSourcesFor(ent, known)
	// The source that answered last time goes first: one walk per cycle for a
	// steady device instead of re-probing every MIB.
	c.stMu.Lock()
	last := c.source[tg.ID]
	c.stMu.Unlock()
	if last != "" {
		for i, s := range sources {
			if s.name == last && i > 0 {
				sources = append([]vrfSource{s}, append(append([]vrfSource{}, sources[:i]...), sources[i+1:]...)...)
				break
			}
		}
	}

	var once sync.Once
	var names map[string]string
	env := vrfEnv{walk: c.walk, addr: addr, creds: creds, lim: c.lim, ifNames: func() map[string]string {
		once.Do(func() { names = c.ifNames(dctx, addr, creds) })
		return names
	}}
	r, err := readVRFs(dctx, sources, env)
	if err != nil && r == nil {
		res.err = err.Error()
		logVRFFailure(tg.ID, res.err)
	}
	c.stMu.Lock()
	if r != nil {
		c.source[tg.ID] = r.Source
	} else {
		delete(c.source, tg.ID)
	}
	c.stMu.Unlock()
	res.reading = r
	return res
}
