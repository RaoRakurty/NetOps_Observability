// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// sdwan_overlay.go — SD-WAN overlay facts over SNMP (tracker 349, step 5;
// design of record docs/design/SDWAN_OVERLAY_TOPOLOGY_2026-10-10.md).
//
// The SNMP-only path to an SD-WAN topology: a customer who runs no SD-WAN
// Manager connector still gets the overlay, from what every Cisco SD-WAN edge
// answers over SNMP with the credential already stored for it.
//
// WHAT IT READS — two MIB families with the SAME table layout:
//
//	Viptela-OS vEdge   VIPTELA-BFD / VIPTELA-SECURITY / VIPTELA-OPER-SYSTEM (enterprise 41916)
//	IOS XE SD-WAN cEdge CISCO-SDWAN-BFD / -SECURITY / -OPER-SYSTEM-MIB (9.9.1002/1006/1004; IOS XE ≥ 17.6.1a)
//
//	local properties  system-ip, site-id                      (identity — "is this an SD-WAN edge")
//	system status     personality (vedge | vsmart | vbond | vmanage)
//	TLOC summary      per local TLOC: sessions total / up / flaps   (cheap, O(transports))
//	BFD sessions      per session: remote system-ip, site-id, local + remote color, state
//
// CAPABILITY FIRST. Customer estates mix IOS XE versions (the cEdge MIBs start at
// 17.6.1a), SNMP views that exclude vendor subtrees, and vEdges beside cEdges.
// So every device is PROBED for what it actually answers, the result is recorded
// per device (available | partial | not_answering) and published, and only a
// capable device is walked further. A device that answers nothing costs one
// short probe, repeated on a slow cadence so a later-enabled MIB is noticed.
//
// BOUNDED (§9). Every column walk carries a row cap; a cap that is hit is
// reported (Truncated + a metric) — a missing peer is then UNKNOWN, never down.
// Sessions are folded per remote system-ip while they are read, so what is kept
// per device is O(peers), not O(sessions). The expensive BFD walk runs only when
// it can have changed (first sight, TLOC sessions not all up, flap counter moved)
// or on a slow refresh.
//
// TENANT (§3a). The published payload carries NO tenant: the reader stamps it from
// inventory, exactly as LLDP and tunnels do.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── the fact contract (source-agnostic: an SD-WAN Manager connector can publish
// the same shape) ────────────────────────────────────────────────────────────

// Overlay capability levels.
const (
	OverlayAvailable    = "available"     // identity + transport/session tables answered
	OverlayPartial      = "partial"       // some SD-WAN tables answered, not all
	OverlayNotAnswering = "not_answering" // no SD-WAN MIB answered (not published)
)

// OverlayDeviceFacts is one device's SD-WAN overlay view.
type OverlayDeviceFacts struct {
	DeviceID    string        `json:"device_id"`
	MIB         string        `json:"mib"`        // viptela | cisco-sdwan
	Capability  string        `json:"capability"` // available | partial
	Personality string        `json:"personality,omitempty"`
	SystemIP    string        `json:"system_ip,omitempty"`
	SiteID      string        `json:"site_id,omitempty"`
	TLOCs       []OverlayTLOC `json:"tlocs,omitempty"`
	Peers       []OverlayPeer `json:"peers,omitempty"`
	// LocalTLOCAddrs are this device's own transport addresses, from the
	// source side of its BFD sessions. With the peers' remote addresses they
	// resolve which device owns which system-ip without trusting any identity
	// column (the local-properties columns differ between releases — measured
	// on the lab 2026-10-10: a vEdge answered its site-id column with the
	// vBond hostname and left system-ip empty).
	LocalTLOCAddrs []string `json:"local_tloc_addrs,omitempty"`
	// SessionsRead is how many BFD session rows the last detail walk folded.
	SessionsRead int `json:"sessions_read"`
	// Truncated: a walk hit its row cap — peers beyond it are UNKNOWN, not down.
	Truncated bool `json:"truncated"`
	// DetailRead: the BFD table has been read at least once (Peers is empty
	// because it was not read yet, versus because there are no sessions).
	DetailRead bool      `json:"detail_read"`
	WalkedAt   time.Time `json:"walked_at"`           // identity + TLOC
	DetailAt   time.Time `json:"detail_at,omitempty"` // BFD sessions
	// OMP control-plane sessions (sdwan_omp.go). OMPRead says the table was
	// read; per-peer rows are kept for edges only (a controller lists every
	// edge), the counts always.
	OMPRead  bool             `json:"omp_read"`
	OMPPeers []OverlayOMPPeer `json:"omp_peers,omitempty"`
	OMPUp    int              `json:"omp_up"`
	OMPNotUp int              `json:"omp_not_up"`
	ompAll   []OverlayOMPPeer
}

// OverlayTLOC is one local transport locator (an interface on a transport).
type OverlayTLOC struct {
	Interface string `json:"interface"`
	Encap     string `json:"encap,omitempty"`
	Total     int64  `json:"sessions_total"`
	Up        int64  `json:"sessions_up"`
	Flaps     int64  `json:"sessions_flap"`
}

// OverlayPeer is every session this device holds with one remote edge.
type OverlayPeer struct {
	SystemIP   string              `json:"system_ip"`
	SiteID     string              `json:"site_id,omitempty"`
	ColorPairs []OverlayColorPairs `json:"color_pairs"`
	// TLOCAddrs are the peer's transport addresses as this device reaches them
	// (the destination side of the sessions).
	TLOCAddrs []string `json:"tloc_addrs,omitempty"`
}

// OverlayColorPairs folds the sessions of one (local color, remote color, proto).
type OverlayColorPairs struct {
	LocalColor  string `json:"local_color"`
	RemoteColor string `json:"remote_color"`
	Proto       string `json:"proto,omitempty"`
	Sessions    int    `json:"sessions"`
	Up          int    `json:"up"`
	// State is the best state seen across the folded sessions.
	State string `json:"state"`
}

// ── MIB layout ───────────────────────────────────────────────────────────────

type sdwanMIB struct {
	name        string
	local       []int // local-properties group: .1 device type, .8 site-id, .12 system-ip
	personality []int // system-status personality
	bfdEntry    []int // bfdSessionsListEntry
	tlocEntry   []int // bfdSummary TLOC entry
}

// The two families share their column numbering (verified against the MIB
// definitions; the live check is the per-device capability probe itself).
var sdwanMIBs = []sdwanMIB{
	{
		name:        "viptela",
		local:       []int{1, 3, 6, 1, 4, 1, 41916, 4, 2, 5},
		personality: []int{1, 3, 6, 1, 4, 1, 41916, 11, 1, 1},
		bfdEntry:    []int{1, 3, 6, 1, 4, 1, 41916, 6, 1, 1, 1},
		tlocEntry:   []int{1, 3, 6, 1, 4, 1, 41916, 6, 1, 6, 1},
	},
	{
		name:        "cisco-sdwan",
		local:       []int{1, 3, 6, 1, 4, 1, 9, 9, 1006, 1, 2, 5},
		personality: []int{1, 3, 6, 1, 4, 1, 9, 9, 1004, 1, 1, 1},
		bfdEntry:    []int{1, 3, 6, 1, 4, 1, 9, 9, 1002, 1, 1, 1, 1},
		tlocEntry:   []int{1, 3, 6, 1, 4, 1, 9, 9, 1002, 1, 1, 6, 1},
	},
}

// Column numbers. controlLocalProperties is numbered identically in every
// published release of both families (Viptela 20.9–26.1, IOS XE SD-WAN
// 17.9–26.1): .8 DnsName (the vBond hostname), .9 SiteId (Unsigned32),
// .12 TlsPort, .13 SystemIp (InetAddressIP). Pinned by
// TestSDWANOIDsArePinnedToTheMIB.
const (
	localSiteID   = 9
	localSystemIP = 13
	bfdSystemIP   = 6
	bfdSiteID     = 7
	bfdLocalColor = 8
	bfdColor      = 9
	bfdState      = 10
	tlocTotal     = 3
	tlocUp        = 4
	tlocFlap      = 5
)

func col(base []int, n int) []int { return append(append([]int{}, base...), n) }

var sdwanColors = map[int64]string{
	1: "default", 2: "mpls", 3: "metro-ethernet", 4: "biz-internet", 5: "public-internet",
	6: "lte", 7: "3g", 8: "red", 9: "green", 10: "blue", 11: "gold", 12: "silver",
	13: "bronze", 14: "custom1", 15: "custom2", 16: "custom3", 17: "private1",
	18: "private2", 19: "private3", 20: "private4", 21: "private5", 22: "private6",
}

func colorName(v berVal) string {
	if n := v.int(); n > 0 {
		if s, ok := sdwanColors[n]; ok {
			return s
		}
		return "color-" + strconv.FormatInt(n, 10)
	}
	return strings.ToLower(strings.TrimSpace(v.str())) // some agents answer the name
}

var bfdStates = map[int64]string{0: "admin-down", 1: "down", 2: "init", 3: "up", 4: "invalid", 5: "inactive"}

// stateRank orders states so the fold keeps the best one.
var stateRank = map[string]int{"up": 5, "init": 4, "down": 3, "inactive": 2, "admin-down": 1, "invalid": 0}

func stateName(v berVal) string {
	if s, ok := bfdStates[v.int()]; ok {
		return s
	}
	return "unknown"
}

var encapNames = map[int]string{1: "gre", 2: "ipsec"}

// addrValue decodes an address-valued column: an IpAddress / 4- or 16-octet
// string, or a printable dotted string.
func addrValue(v berVal) string {
	switch len(v.raw) {
	case 4, 16:
		if a, ok := netip.AddrFromSlice(v.raw); ok {
			return a.Unmap().String()
		}
	}
	s := strings.TrimSpace(v.str())
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return s
}

func isIntegerTag(t byte) bool { return t == 0x02 || t == 0x41 || t == 0x42 || t == 0x47 }

// siteIDValue accepts only an integer site-id (Unsigned32 in every MIB
// revision). A non-integer answer means the column means something else on
// this release — it is dropped, never published as a site.
func siteIDValue(v berVal) string {
	if !isIntegerTag(v.tag) {
		return ""
	}
	return strconv.FormatInt(v.int(), 10)
}

// systemIPValue accepts only a value that IS an IP address.
func systemIPValue(v berVal) string {
	a := addrValue(v)
	if _, err := netip.ParseAddr(a); err != nil {
		return ""
	}
	return a
}

// ── index parsing ────────────────────────────────────────────────────────────

func parseArcs(idx string) ([]int, bool) {
	parts := strings.Split(idx, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func arcsAddr(arcs []int) string {
	b := make([]byte, len(arcs))
	for i, a := range arcs {
		if a > 255 {
			return ""
		}
		b[i] = byte(a)
	}
	if a, ok := netip.AddrFromSlice(b); ok {
		return a.Unmap().String()
	}
	return ""
}

// bfdIndex is the decoded BFD session INDEX {SrcIp, DstIp, Proto, SrcPort, DstPort}.
type bfdIndex struct {
	src, dst string
	proto    string
}

// parseBFDIndex decodes a session row index. The InetAddressIP index may be
// encoded with or without its length octet (agents differ, and the MIB does not
// settle it), so the total arc count decides: 11/35 arcs are fixed-size IPv4/IPv6,
// 13/37 are length-prefixed.
func parseBFDIndex(idx string) (bfdIndex, bool) {
	a, ok := parseArcs(idx)
	if !ok {
		return bfdIndex{}, false
	}
	var src, dst []int
	var rest []int
	switch len(a) {
	case 11:
		src, dst, rest = a[0:4], a[4:8], a[8:]
	case 13:
		if a[0] != 4 || a[5] != 4 {
			return bfdIndex{}, false
		}
		src, dst, rest = a[1:5], a[6:10], a[10:]
	case 35:
		src, dst, rest = a[0:16], a[16:32], a[32:]
	case 37:
		if a[0] != 16 || a[17] != 16 {
			return bfdIndex{}, false
		}
		src, dst, rest = a[1:17], a[18:34], a[34:]
	default:
		return bfdIndex{}, false
	}
	out := bfdIndex{src: arcsAddr(src), dst: arcsAddr(dst), proto: encapNames[rest[0]]}
	if out.src == "" || out.dst == "" {
		return bfdIndex{}, false
	}
	return out, true
}

// parseTLOCIndex decodes a TLOC summary row index {IfName, Encap}: IfName is a
// length-prefixed string; an agent that omits the length is read as
// "every arc but the last".
func parseTLOCIndex(idx string) (ifName, encap string, ok bool) {
	a, ok := parseArcs(idx)
	if !ok || len(a) < 2 {
		return "", "", false
	}
	var name []int
	if n := a[0]; n > 0 && len(a) == n+2 {
		name = a[1 : n+1]
	} else {
		name = a[:len(a)-1]
	}
	b := make([]byte, 0, len(name))
	for _, c := range name {
		if c < 0x20 || c > 0x7e {
			return "", "", false
		}
		b = append(b, byte(c))
	}
	enc := encapNames[a[len(a)-1]]
	if enc == "" {
		enc = strconv.Itoa(a[len(a)-1])
	}
	return string(b), enc, true
}

// ── the walks ────────────────────────────────────────────────────────────────

// overlayLimits bounds one device's walks.
type overlayLimits struct {
	maxSessionRows int // BFD session rows per column
	maxTLOCRows    int
	maxOMPRows     int // OMP peer rows per column (a controller lists every edge)
}

// walkFn is the bounded column walk (snmpWalkColumnBounded in production; a
// stub in tests).
type walkFn func(ctx context.Context, addr string, creds snmpCreds, col []int, maxRows int) (map[string]berVal, bool, error)

// probeOverlay finds which SD-WAN MIB family the device answers and reads its
// identity + TLOC summary. MIB == "" means none answered.
func probeOverlay(ctx context.Context, walk walkFn, addr string, creds snmpCreds, lim overlayLimits) (OverlayDeviceFacts, error) {
	var lastErr error
	for _, m := range sdwanMIBs {
		sys, _, err := walk(ctx, addr, creds, col(m.local, localSystemIP), 4)
		if err != nil {
			lastErr = err
		}
		tl, tlTrunc, terr := walk(ctx, addr, creds, col(m.tlocEntry, tlocTotal), lim.maxTLOCRows)
		if terr != nil && lastErr == nil {
			lastErr = terr
		}
		if len(sys) == 0 && len(tl) == 0 {
			continue
		}
		f := OverlayDeviceFacts{MIB: m.name, WalkedAt: time.Now().UTC(), Truncated: tlTrunc}
		for _, v := range sys {
			f.SystemIP = systemIPValue(v)
			break
		}
		if site, _, err := walk(ctx, addr, creds, col(m.local, localSiteID), 4); err == nil {
			for _, v := range site {
				f.SiteID = siteIDValue(v)
				break
			}
		}
		if pers, _, err := walk(ctx, addr, creds, m.personality, 4); err == nil {
			for _, v := range pers {
				f.Personality = strings.ToLower(strings.TrimSpace(v.str()))
				break
			}
		}
		if len(tl) > 0 {
			up, _, _ := walk(ctx, addr, creds, col(m.tlocEntry, tlocUp), lim.maxTLOCRows)   // best-effort: missing column → 0 up
			fl, _, _ := walk(ctx, addr, creds, col(m.tlocEntry, tlocFlap), lim.maxTLOCRows) // best-effort: missing column → 0 flaps
			for idx, v := range tl {
				name, enc, ok := parseTLOCIndex(idx)
				if !ok {
					continue
				}
				f.TLOCs = append(f.TLOCs, OverlayTLOC{Interface: name, Encap: enc,
					Total: v.int(), Up: up[idx].int(), Flaps: fl[idx].int()})
			}
			sort.Slice(f.TLOCs, func(i, j int) bool {
				if f.TLOCs[i].Interface != f.TLOCs[j].Interface {
					return f.TLOCs[i].Interface < f.TLOCs[j].Interface
				}
				return f.TLOCs[i].Encap < f.TLOCs[j].Encap
			})
		}
		f.Capability = OverlayPartial
		if f.SystemIP != "" && len(f.TLOCs) > 0 {
			f.Capability = OverlayAvailable
		}
		return f, nil
	}
	return OverlayDeviceFacts{Capability: OverlayNotAnswering}, lastErr
}

// readSessions walks the BFD session table of the device's MIB family and folds
// the rows per remote system-ip and (local color, remote color, proto).
func readSessions(ctx context.Context, walk walkFn, addr string, creds snmpCreds, mib string, lim overlayLimits) (peers []OverlayPeer, local []string, rows int, truncated bool, err error) {
	var m *sdwanMIB
	for i := range sdwanMIBs {
		if sdwanMIBs[i].name == mib {
			m = &sdwanMIBs[i]
		}
	}
	if m == nil {
		return nil, nil, 0, false, fmt.Errorf("sdwan overlay: unknown MIB family %q", mib)
	}
	cols := map[int]map[string]berVal{}
	for _, c := range []int{bfdSystemIP, bfdSiteID, bfdLocalColor, bfdColor, bfdState} {
		vals, trunc, werr := walk(ctx, addr, creds, col(m.bfdEntry, c), lim.maxSessionRows)
		if werr != nil {
			return nil, nil, 0, false, werr
		}
		truncated = truncated || trunc
		cols[c] = vals
	}
	type key struct{ local, remote, proto string }
	byPeer := map[string]*OverlayPeer{}
	pairs := map[string]map[key]*OverlayColorPairs{}
	peerAddrs := map[string]map[string]bool{}
	localAddrs := map[string]bool{}
	for idx, sysv := range cols[bfdSystemIP] {
		bi, ok := parseBFDIndex(idx)
		if !ok {
			continue
		}
		rows++
		sys := addrValue(sysv)
		if sys == "" {
			continue
		}
		p := byPeer[sys]
		if p == nil {
			p = &OverlayPeer{SystemIP: sys, SiteID: siteIDValue(cols[bfdSiteID][idx])}
			byPeer[sys] = p
			pairs[sys] = map[key]*OverlayColorPairs{}
			peerAddrs[sys] = map[string]bool{}
		}
		peerAddrs[sys][bi.dst] = true
		localAddrs[bi.src] = true
		k := key{colorName(cols[bfdLocalColor][idx]), colorName(cols[bfdColor][idx]), bi.proto}
		cp := pairs[sys][k]
		if cp == nil {
			cp = &OverlayColorPairs{LocalColor: k.local, RemoteColor: k.remote, Proto: k.proto, State: "unknown"}
			pairs[sys][k] = cp
		}
		st := stateName(cols[bfdState][idx])
		cp.Sessions++
		if st == "up" {
			cp.Up++
		}
		if stateRank[st] > stateRank[cp.State] || cp.State == "unknown" {
			cp.State = st
		}
	}
	for sys, p := range byPeer {
		for _, cp := range pairs[sys] {
			p.ColorPairs = append(p.ColorPairs, *cp)
		}
		p.TLOCAddrs = sortedKeys(peerAddrs[sys])
		sort.Slice(p.ColorPairs, func(i, j int) bool {
			a, b := p.ColorPairs[i], p.ColorPairs[j]
			if a.LocalColor != b.LocalColor {
				return a.LocalColor < b.LocalColor
			}
			if a.RemoteColor != b.RemoteColor {
				return a.RemoteColor < b.RemoteColor
			}
			return a.Proto < b.Proto
		})
		peers = append(peers, *p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].SystemIP < peers[j].SystemIP })
	return peers, sortedKeys(localAddrs), rows, truncated, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── the collector ────────────────────────────────────────────────────────────

const (
	sdwanOverlayKeyPrefix = "netops:sdwan:overlay:"
	sdwanOverlayMembers   = "netops:sdwan:overlay:members"
)

type overlayDevState struct {
	facts       OverlayDeviceFacts // last published (capable devices only)
	probedAt    time.Time
	capability  string
	lastFlapSum int64
}

type sdwanOverlayCollector struct {
	interval       time.Duration
	reprobeCapable time.Duration // identity refresh for a capable device
	reprobeOthers  time.Duration // re-probe for a device that answered nothing
	detailEvery    time.Duration // BFD refresh when nothing suggests a change
	workers        int
	limits         overlayLimits
	targets        TargetFunc
	walk           walkFn
	publish        func(ctx context.Context, f OverlayDeviceFacts, ttl time.Duration) error

	stMu  sync.Mutex
	state map[string]*overlayDevState

	mu     sync.RWMutex
	status Status
}

// NewSDWANOverlay builds the SD-WAN overlay collector.
func NewSDWANOverlay(targets TargetFunc) Collector {
	return &sdwanOverlayCollector{
		interval:       90 * time.Second,
		reprobeCapable: 6 * time.Hour,
		reprobeOthers:  30 * time.Minute,
		detailEvery:    envDuration("SDWAN_OVERLAY_DETAIL_INTERVAL", 30*time.Minute),
		workers:        envIntBounded("SDWAN_OVERLAY_WORKERS", 8, 1, 64),
		limits: overlayLimits{
			maxSessionRows: envIntBounded("SDWAN_BFD_MAX_ROWS", 20000, 100, 200000),
			maxTLOCRows:    256,
			maxOMPRows:     envIntBounded("SDWAN_OMP_MAX_ROWS", 4096, 16, 100000),
		},
		targets: targets,
		walk:    snmpWalkColumnBounded,
		publish: publishOverlayFacts,
		state:   map[string]*overlayDevState{},
		status:  Status{Name: "sdwan_overlay", Healthy: true, Kind: "discovery"},
	}
}

// envIntBounded reads an integer knob clamped to [lo, hi] (§9: an operator
// typo must not unbound a walk or spawn a thousand workers).
func envIntBounded(key string, def, lo, hi int) int {
	n := envInt(key, def) // logs and falls back on a non-integer / non-positive value
	if n < lo {
		log.Printf("collectors: %s=%d is below the floor %d — using %d", key, n, lo, lo)
		return lo
	}
	if n > hi {
		log.Printf("collectors: %s=%d is above the ceiling %d — using %d", key, n, hi, hi)
		return hi
	}
	return n
}

func (c *sdwanOverlayCollector) Name() string { return "sdwan_overlay" }

func (c *sdwanOverlayCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *sdwanOverlayCollector) Run(ctx context.Context) error {
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

// deviceResult is one device's outcome for the cycle.
type deviceResult struct {
	id         string
	probed     bool // an SNMP probe ran this cycle
	answered   bool // the device answered SNMP at all this cycle
	capability string
	facts      *OverlayDeviceFacts // non-nil for a capable device
	err        string
}

func (c *sdwanOverlayCollector) pollOnce(ctx context.Context) {
	var targets []Target
	if c.targets != nil {
		targets = c.targets()
	}
	start := time.Now()
	jobs := make(chan Target)
	results := make(chan deviceResult, len(targets))
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
	answered, probed, capable, truncatedDevs, publishFailed := 0, 0, 0, 0, 0
	var lastErr string
	for r := range results {
		if r.probed {
			probed++
			if r.answered {
				answered++
			}
		}
		if r.err != "" {
			lastErr = r.err
			if strings.HasPrefix(r.err, "publish:") {
				publishFailed++
			}
		}
		if r.facts == nil {
			continue
		}
		capable++
		f := r.facts
		lines = append(lines,
			fmt.Sprintf(`device_sdwan_overlay_capable{device=%q,mib=%q,level=%q} 1 %d`, r.id, f.MIB, f.Capability, now))
		var total, up int64
		for _, t := range f.TLOCs {
			total += t.Total
			up += t.Up
		}
		lines = append(lines,
			fmt.Sprintf(`device_sdwan_tloc_sessions_total{device=%q} %d %d`, r.id, total, now),
			fmt.Sprintf(`device_sdwan_tloc_sessions_up{device=%q} %d %d`, r.id, up, now))
		if f.DetailRead {
			peersUp, peersDown := 0, 0
			for _, p := range f.Peers {
				if peerUp(p) {
					peersUp++
				} else {
					peersDown++
				}
			}
			lines = append(lines,
				fmt.Sprintf(`device_sdwan_bfd_peers{device=%q,state="up"} %d %d`, r.id, peersUp, now),
				fmt.Sprintf(`device_sdwan_bfd_peers{device=%q,state="not_up"} %d %d`, r.id, peersDown, now),
				fmt.Sprintf(`collector_sdwan_walk_rows{device=%q} %d %d`, r.id, f.SessionsRead, now))
		}
		if f.OMPRead {
			lines = append(lines, ompLines(r.id, f.MIB, f.Personality, f.ompAll, now)...)
		}
		t := 0
		if f.Truncated {
			t = 1
			truncatedDevs++
		}
		lines = append(lines, fmt.Sprintf(`collector_sdwan_walk_truncated{device=%q} %d %d`, r.id, t, now))
	}
	healthy := publishFailed == 0 && cycleHealthy(probed, answered)
	lines = append(lines,
		collectorUpLine("sdwan_overlay", healthy, now),
		fmt.Sprintf(`collector_targets{collector="sdwan_overlay"} %d %d`, len(targets), now),
		fmt.Sprintf(`collector_targets_reachable{collector="sdwan_overlay"} %d %d`, answered, now),
		fmt.Sprintf(`collector_sdwan_capable_devices{collector="sdwan_overlay"} %d %d`, capable, now),
		fmt.Sprintf(`collector_sdwan_truncated_devices{collector="sdwan_overlay"} %d %d`, truncatedDevs, now),
		fmt.Sprintf(`collector_store_write_failed{collector="sdwan_overlay",store="valkey"} %d %d`, b2i(publishFailed > 0), now),
	)
	emitMetrics(ctx, strings.Join(lines, "\n"))

	c.mu.Lock()
	c.status.LastTick = start.UTC()
	c.status.Targets = len(targets)
	c.status.Reachable = answered
	c.status.LastPollMillis = time.Since(start).Milliseconds()
	c.status.Healthy = healthy
	c.status.LastError = cycleError(probed, answered, lastErr)
	c.mu.Unlock()
}

// peerUp: at least one of the peer's color pairs has an up session.
func peerUp(p OverlayPeer) bool {
	for _, cp := range p.ColorPairs {
		if cp.Up > 0 {
			return true
		}
	}
	return false
}

// pollDevice runs whatever this device is due for and publishes a capable one.
func (c *sdwanOverlayCollector) pollDevice(ctx context.Context, tg Target) deviceResult {
	res := deviceResult{id: tg.ID}
	c.stMu.Lock()
	st := c.state[tg.ID]
	if st == nil {
		st = &overlayDevState{}
		c.state[tg.ID] = st
	}
	snap := *st
	c.stMu.Unlock()

	now := time.Now()
	capableBefore := snap.capability == OverlayAvailable || snap.capability == OverlayPartial
	reprobe := snap.probedAt.IsZero() ||
		(capableBefore && now.Sub(snap.probedAt) >= c.reprobeCapable) ||
		(!capableBefore && now.Sub(snap.probedAt) >= c.reprobeOthers)
	if !capableBefore && !reprobe {
		res.capability = snap.capability
		return res // a non-SD-WAN device, not due: costs nothing this cycle
	}

	addr := withPort(tg.Address, 161)
	creds := tg.creds()
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res.probed = true

	// Identity + TLOC: every cycle for a capable device (cheap), else on the probe cadence.
	f, err := probeOverlay(pctx, c.walk, addr, creds, c.limits)
	if f.Capability == OverlayNotAnswering {
		if err != nil {
			res.err = err.Error()
		} else {
			res.answered = true // the agent answered, just not with SD-WAN tables
		}
		c.recordCapability(tg.ID, OverlayNotAnswering, now, "", nil)
		res.capability = OverlayNotAnswering
		return res
	}
	res.answered = true
	f.DeviceID = tg.ID
	if !reprobe {
		f.Personality, f.SiteID = firstNonEmptyStr(f.Personality, snap.facts.Personality), firstNonEmptyStr(f.SiteID, snap.facts.SiteID)
	}

	// BFD detail: only when it can have changed, or on the slow refresh.
	var flapSum int64
	allUp := true
	for _, t := range f.TLOCs {
		flapSum += t.Flaps
		if t.Up < t.Total {
			allUp = false
		}
	}
	due := !snap.facts.DetailRead || !allUp || flapSum != snap.lastFlapSum || now.Sub(snap.facts.DetailAt) >= c.detailEvery
	if due {
		dctx, dcancel := context.WithTimeout(ctx, 120*time.Second)
		peers, local, rows, trunc, derr := readSessions(dctx, c.walk, addr, creds, f.MIB, c.limits)
		dcancel()
		if derr != nil {
			// Keep the previous detail rather than publishing an empty overlay:
			// an unread table is UNKNOWN, never "no tunnels".
			res.err = "bfd walk: " + derr.Error()
			f.Peers, f.SessionsRead, f.DetailRead, f.DetailAt = snap.facts.Peers, snap.facts.SessionsRead, snap.facts.DetailRead, snap.facts.DetailAt
			f.LocalTLOCAddrs = snap.facts.LocalTLOCAddrs
			f.Truncated = f.Truncated || snap.facts.Truncated
		} else {
			f.Peers, f.SessionsRead, f.DetailRead, f.DetailAt = peers, rows, true, time.Now().UTC()
			f.LocalTLOCAddrs = local
			f.Truncated = f.Truncated || trunc
			// Sessions + transports are what the overlay needs; a system-ip the
			// identity column did not give is resolved from peers downstream.
			if len(peers) > 0 && len(f.TLOCs) > 0 {
				f.Capability = OverlayAvailable
			}
		}
	} else {
		f.Peers, f.SessionsRead, f.DetailRead, f.DetailAt = snap.facts.Peers, snap.facts.SessionsRead, snap.facts.DetailRead, snap.facts.DetailAt
		f.LocalTLOCAddrs = snap.facts.LocalTLOCAddrs
	}

	// OMP sessions: every cycle for a capable device (a handful of rows on an
	// edge). An unread table keeps the previous reading — UNKNOWN, never
	// "no controllers".
	octx, ocancel := context.WithTimeout(ctx, 20*time.Second)
	omp, _, oerr := readOMP(octx, c.walk, addr, creds, f.MIB, c.limits.maxOMPRows)
	ocancel()
	if oerr != nil {
		f.OMPRead, f.OMPPeers, f.OMPUp, f.OMPNotUp, f.ompAll = snap.facts.OMPRead, snap.facts.OMPPeers, snap.facts.OMPUp, snap.facts.OMPNotUp, snap.facts.ompAll
	} else {
		f.OMPRead, f.ompAll = true, omp
		f.OMPUp, f.OMPNotUp = 0, 0
		for _, p := range omp {
			if p.Up() {
				f.OMPUp++
			} else {
				f.OMPNotUp++
			}
		}
		if !isController(f.Personality) {
			f.OMPPeers = omp
		}
	}

	if perr := c.publish(ctx, f, 3*c.detailEvery); perr != nil {
		res.err = "publish: " + perr.Error()
	}
	c.recordCapability(tg.ID, f.Capability, now, f.MIB, &f)
	c.stMu.Lock()
	c.state[tg.ID].lastFlapSum = flapSum
	c.stMu.Unlock()
	res.capability = f.Capability
	res.facts = &f
	return res
}

// recordCapability stores the device's state and logs a capability CHANGE (§10:
// an edge whose SD-WAN MIBs stop answering must be visible, not silent).
func (c *sdwanOverlayCollector) recordCapability(id, capability string, now time.Time, mib string, f *OverlayDeviceFacts) {
	c.stMu.Lock()
	st := c.state[id]
	prev := st.capability
	st.capability = capability
	st.probedAt = now
	if f != nil {
		st.facts = *f
	}
	c.stMu.Unlock()
	if prev == capability || (prev == "" && capability == OverlayNotAnswering) {
		return
	}
	switch {
	case f != nil:
		log.Printf("sdwan-overlay: device=%s capability=%s (was %q) mib=%s personality=%q system_ip=%s tlocs=%d",
			id, capability, prev, mib, f.Personality, f.SystemIP, len(f.TLOCs))
	default:
		log.Printf("sdwan-overlay: device=%s capability=%s (was %q) — no SD-WAN MIB answered (IOS XE < 17.6.1a, or the SNMP view excludes the SD-WAN subtrees)", id, capability, prev)
	}
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ── publish / fetch ─────────────────────────────────────────────────────────

// publishOverlayFacts writes one device's facts under its own key and registers
// it in the member set (per-device keys: the overlay is O(N²) estate-wide, and
// one shared blob would be rewritten whole on every change).
func publishOverlayFacts(ctx context.Context, f OverlayDeviceFacts, ttl time.Duration) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	conn, err := redisDial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	secs := strconv.Itoa(int(ttl.Seconds()))
	if _, err := redisCmd(conn, "SET", sdwanOverlayKeyPrefix+f.DeviceID, string(b), "EX", secs); err != nil {
		return err
	}
	if _, err := redisCmd(conn, "SADD", sdwanOverlayMembers, f.DeviceID); err != nil {
		return err
	}
	_, err = redisCmd(conn, "EXPIRE", sdwanOverlayMembers, secs)
	return err
}

// maxOverlayMembers bounds the member-set read (§9). Far above any single
// estate; a count past it is corrupt, not real.
const maxOverlayMembers = 200000

// FetchOverlayFacts reads every published device's overlay facts. Absent →
// empty map, nil error. Unread → error (tracker 307: unread is not empty).
// A member whose key expired is simply absent (its device stopped answering
// for longer than the TTL).
func FetchOverlayFacts(ctx context.Context) (map[string]OverlayDeviceFacts, error) {
	out := map[string]OverlayDeviceFacts{}
	conn, err := redisDial(ctx)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	members, err := redisArray(conn, maxOverlayMembers, "SMEMBERS", sdwanOverlayMembers)
	if err != nil {
		return out, fmt.Errorf("sdwan overlay: member set unread: %w", err)
	}
	ids := make([]string, 0, len(members))
	for _, m := range members {
		if m != nil && *m != "" {
			ids = append(ids, *m)
		}
	}
	sort.Strings(ids)
	const chunk = 200
	for i := 0; i < len(ids); i += chunk {
		end := i + chunk
		if end > len(ids) {
			end = len(ids)
		}
		args := []string{"MGET"}
		for _, id := range ids[i:end] {
			args = append(args, sdwanOverlayKeyPrefix+id)
		}
		vals, err := redisArray(conn, chunk, args...)
		if err != nil {
			return out, fmt.Errorf("sdwan overlay: facts unread: %w", err)
		}
		for j, v := range vals {
			if v == nil || i+j >= end {
				continue
			}
			var f OverlayDeviceFacts
			if err := json.Unmarshal([]byte(*v), &f); err != nil {
				return out, fmt.Errorf("sdwan overlay: facts for %s will not decode (we authored them — corrupt evidence): %w", ids[i+j], err)
			}
			out[ids[i+j]] = f
		}
	}
	return out, nil
}
