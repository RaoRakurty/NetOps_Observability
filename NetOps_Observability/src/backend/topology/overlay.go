// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// overlay.go — SD-WAN overlay inference (tracker 349, step 6; design of record
// docs/design/SDWAN_OVERLAY_TOPOLOGY_2026-10-10.md). Pure: no I/O.
//
// From the per-device overlay facts the SNMP collector publishes
// (collectors.OverlayDeviceFacts) it derives:
//
//   - OBSERVED overlay edges — one per pair of edges that hold BFD sessions,
//     whatever the number of colors/sessions between them (colour-independent
//     id, so a colour flap never churns the edge), with the folded per-colour
//     state;
//   - INFERRED transport nodes — one per (tenant, colour): the provider network
//     behind a colour is never visible, so it is drawn as an inferred `wan`
//     node, health derived from the observed sessions on that colour;
//   - inferred membership edges — each edge to the transports it uses.
//
// SYSTEM-IP RESOLUTION does not trust any identity column (they differ between
// releases — the lab's vEdges answered none): a peer's system-ip is owned by
// the device whose own transport addresses, or interface addresses, are the
// addresses that peer is reached at. That also resolves edges whose SD-WAN MIBs
// do not answer at all. An address or system-ip claimed by two devices is
// AMBIGUOUS and never resolved.
//
// SCALE: a near-full mesh of N edges is N² pairs. Past a per-tenant cap, or for
// a dense mesh, only the EXCEPTIONS (pairs not fully up) are drawn and the rest
// is summarised on the transport node (design §scale-2).
//
// TENANT (§3a): every map is partitioned by tenant; a device is only ever
// resolved to, paired with, or attached to a node of its own tenant.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"netops/backend/collectors"
)

// KindWAN is a transport/handoff node (SD-WAN colour, ISP, MPLS).
const KindWAN = "wan"

// RelOverlay is an observed SD-WAN overlay adjacency (BFD sessions).
const RelOverlay = "overlay"

// RelInferred is a derived, not directly observed, relationship.
const RelInferred = "inferred"

// Evidence sources for overlay records.
const (
	SrcSDWANBFD  = "sdwan_bfd"  // observed BFD sessions
	SrcSDWANTLOC = "sdwan_tloc" // observed transport attachment, inferred network
)

// Overlay shapes per tenant.
const (
	OverlayShapePairs      = "pairs"      // every pair drawn
	OverlayShapeExceptions = "exceptions" // only pairs not fully up drawn
)

// OverlayInput is everything InferOverlay needs, already tenant-scoped by the
// caller to the devices the principal can see.
type OverlayInput struct {
	DevTenant map[string]string                        // device id → tenant (every visible device)
	Facts     map[string]collectors.OverlayDeviceFacts // device id → its published overlay facts
	IfAddrs   map[string][]string                      // device id → interface addresses
	// MaxPairEdges caps the overlay pair edges drawn per tenant before the
	// view switches to exceptions-only (0 → 2,000).
	MaxPairEdges int
	// DenseMeshMin: a tenant with at least this many overlay members whose
	// pair density is ≥ 0.9 is drawn exceptions-only (0 → 16).
	DenseMeshMin int
}

// OverlayStats is what the inference could and could not establish.
type OverlayStats struct {
	PairsObserved  int               // distinct device pairs with sessions
	PairsDrawn     int               // pair edges in the result
	Unresolved     int               // peer system-ips owned by no visible device
	Ambiguous      int               // system-ips / addresses claimed by more than one device
	ResolvedByPeer int               // edges identified only through their peers (no own facts)
	Shape          map[string]string // tenant → OverlayShapePairs | OverlayShapeExceptions
}

// OverlayResult is the projected overlay.
type OverlayResult struct {
	Nodes []Node
	Edges []Edge
	Stats OverlayStats
	// SystemIPs: tenant → system-ip → device id (resolved owners only).
	SystemIPs map[string]map[string]string
}

// TransportNodeID is the stable, tenant-namespaced id of a transport node, so a
// cross-tenant view can never merge two tenants' colours into one cloud.
func TransportNodeID(tenant, color string) string {
	h := sha256.Sum256([]byte(tenant))
	return "wan:" + hex.EncodeToString(h[:6]) + ":" + color
}

// pairAgg is one device pair's folded sessions. Built for 10^5–10^6 pairs: no
// per-pair maps — colours are a bitmask over the inference's colour table and
// the two reporting ends are two flags.
type pairAgg struct {
	tenant, a, b string
	colors       uint64 // bit i = colour i in colorNames (≤ 64 colours; more fold into bit 63)
	sessions     int
	up           int
	aReported    bool
	bReported    bool
}

// colorMask is the bit for colour index i (colours past 63 share bit 63; an
// estate with more than 64 colours still renders, with merged colour labels).
func colorMask(i int) uint64 {
	if i > 63 {
		i = 63
	}
	return 1 << uint(i)
}

// InferOverlay projects the SD-WAN overlay.
func InferOverlay(in OverlayInput) OverlayResult {
	maxPairs := in.MaxPairEdges
	if maxPairs <= 0 {
		maxPairs = 2000
	}
	denseMin := in.DenseMeshMin
	if denseMin <= 0 {
		denseMin = 16
	}
	res := OverlayResult{SystemIPs: map[string]map[string]string{}, Stats: OverlayStats{Shape: map[string]string{}}}

	// ── 1. address ownership, per tenant ──────────────────────────────────────
	addrOwner := map[string]map[string]string{} // tenant → addr → device ("" = ambiguous)
	claimAddr := func(tenant, addr, dev string) {
		addr = normAddr(addr)
		if addr == "" {
			return
		}
		m := addrOwner[tenant]
		if m == nil {
			m = map[string]string{}
			addrOwner[tenant] = m
		}
		if prev, ok := m[addr]; ok && prev != dev {
			m[addr] = "" // two devices claim it: never resolve through it
			return
		}
		m[addr] = dev
	}
	for dev, f := range in.Facts {
		t, ok := in.DevTenant[dev]
		if !ok {
			continue // not a device this caller can see
		}
		for _, a := range f.LocalTLOCAddrs {
			claimAddr(t, a, dev)
		}
	}
	for dev, addrs := range in.IfAddrs {
		t, ok := in.DevTenant[dev]
		if !ok {
			continue
		}
		for _, a := range addrs {
			claimAddr(t, a, dev)
		}
	}

	// ── 2. system-ip ownership, per tenant ────────────────────────────────────
	sysOwner := map[string]map[string]string{} // tenant → sysip → device ("" = ambiguous)
	setOwner := func(tenant, sys, dev string) {
		m := sysOwner[tenant]
		if m == nil {
			m = map[string]string{}
			sysOwner[tenant] = m
		}
		prev, ok := m[sys]
		switch {
		case !ok:
			m[sys] = dev
		case prev != dev && prev != "":
			m[sys] = "" // two devices: ambiguous
		}
	}
	// a. a system-ip the device itself answered (validated by the collector).
	explicit := map[string]map[string]bool{}
	for dev, f := range in.Facts {
		t, ok := in.DevTenant[dev]
		if !ok || f.SystemIP == "" {
			continue
		}
		setOwner(t, f.SystemIP, dev)
		if explicit[t] == nil {
			explicit[t] = map[string]bool{}
		}
		explicit[t][f.SystemIP] = true
	}
	// b. the peers' view: a system-ip is owned by the device its transport
	//    addresses belong to. An explicit answer is not overridden.
	devs := sortedFactIDs(in.Facts)
	for _, dev := range devs {
		f := in.Facts[dev]
		t, ok := in.DevTenant[dev]
		if !ok {
			continue
		}
		ex, owned := explicit[t], addrOwner[t]
		for _, p := range f.Peers {
			if p.SystemIP == "" || ex[p.SystemIP] {
				continue
			}
			// The collector publishes canonical addresses (netip); only the
			// interface-map side needed normalising. The FIRST address that
			// resolves is the vote: every address of one peer row belongs to
			// the same remote edge, so further lookups add cost, not evidence.
			for _, a := range p.TLOCAddrs {
				if owner := owned[a]; owner != "" {
					if owner != dev {
						setOwner(t, p.SystemIP, owner)
					}
					break
				}
			}
		}
	}
	for t, m := range sysOwner {
		for sys, dev := range m {
			if dev == "" {
				res.Stats.Ambiguous++
				continue
			}
			if res.SystemIPs[t] == nil {
				res.SystemIPs[t] = map[string]string{}
			}
			res.SystemIPs[t][sys] = dev
		}
	}

	// ── 3. pairs and colours ──────────────────────────────────────────────────
	// Built for 10^5–10^6 pairs: device ids are interned to ints once, pairs are
	// keyed by one uint64, colour membership is a flat []bool per colour. No
	// string is hashed per session.
	devNames := make([]string, 0, len(in.DevTenant))
	for d := range in.DevTenant {
		devNames = append(devNames, d)
	}
	sort.Strings(devNames)
	devIdx := make(map[string]uint32, len(devNames))
	for i, d := range devNames {
		devIdx[d] = uint32(i)
	}
	type colorKey struct {
		tenant string
		color  int
	}
	type colorAgg struct {
		members  []bool
		count    int
		sessions int
		up       int
	}
	// Pairs are stored BY VALUE in one slice and found through a pre-sized index:
	// 10^6 pairs must not be 10^6 heap objects for the collector to walk.
	peerRows := 0
	for _, f := range in.Facts {
		peerRows += len(f.Peers)
	}
	pairIdx := make(map[uint64]int32, peerRows/2+1)
	pairArr := make([]pairAgg, 0, peerRows/2+1)
	colors := map[colorKey]*colorAgg{}
	hasFacts := make([]bool, len(devNames))
	for d := range in.Facts {
		if i, ok := devIdx[d]; ok {
			hasFacts[i] = true
		}
	}
	colorIdx := map[string]int{}
	var colorNames []string
	colorOf := func(c string) int {
		i, ok := colorIdx[c]
		if !ok {
			i = len(colorNames)
			colorIdx[c] = i
			colorNames = append(colorNames, c)
		}
		return i
	}
	// Per-tenant colour aggregates, cached by colour index for the inner loop.
	tenantColors := map[string]*[]*colorAgg{}
	addColorMember := func(t string, tc *[]*colorAgg, ci int, dev uint32, sessions, up int) {
		for len(*tc) <= ci {
			*tc = append(*tc, nil)
		}
		c := (*tc)[ci]
		if c == nil {
			c = &colorAgg{members: make([]bool, len(devNames))}
			(*tc)[ci] = c
			colors[colorKey{t, ci}] = c
		}
		if !c.members[dev] {
			c.members[dev] = true
			c.count++
		}
		c.sessions += sessions
		c.up += up
	}
	seenUnresolved := map[string]bool{}
	byPeer := map[string]bool{}
	for _, dev := range devs {
		f := in.Facts[dev]
		t, ok := in.DevTenant[dev]
		if !ok {
			continue
		}
		di := devIdx[dev]
		owners := res.SystemIPs[t]
		tc := tenantColors[t]
		if tc == nil {
			tc = &[]*colorAgg{}
			tenantColors[t] = tc
		}
		for _, p := range f.Peers {
			other := owners[p.SystemIP]
			if other == "" || other == dev {
				// Unresolved = owned by no visible device. An AMBIGUOUS system-ip
				// is already counted as such and is not counted twice.
				if other == "" && !hasKey(sysOwner[t], p.SystemIP) && !seenUnresolved[t+"|"+p.SystemIP] {
					seenUnresolved[t+"|"+p.SystemIP] = true
					res.Stats.Unresolved++
				}
				continue
			}
			oi := devIdx[other]
			if !hasFacts[oi] {
				byPeer[other] = true
			}
			lo, hi := di, oi
			if lo > hi {
				lo, hi = hi, lo
			}
			k := uint64(lo)<<32 | uint64(hi)
			pi, ok := pairIdx[k]
			if !ok {
				pi = int32(len(pairArr))
				pairArr = append(pairArr, pairAgg{tenant: t, a: devNames[lo], b: devNames[hi]})
				pairIdx[k] = pi
			}
			pa := &pairArr[pi]
			if di == lo {
				pa.aReported = true
			} else {
				pa.bReported = true
			}
			for _, cp := range p.ColorPairs {
				if cp.LocalColor != "" {
					lc := colorOf(cp.LocalColor)
					pa.colors |= colorMask(lc)
					addColorMember(t, tc, lc, di, cp.Sessions, cp.Up)
				}
				if cp.RemoteColor != "" {
					rc := colorOf(cp.RemoteColor)
					pa.colors |= colorMask(rc)
					addColorMember(t, tc, rc, oi, 0, 0)
				}
				pa.sessions += cp.Sessions
				pa.up += cp.Up
			}
		}
	}
	res.Stats.PairsObserved = len(pairArr)
	res.Stats.ResolvedByPeer = len(byPeer)

	// ── 4. shape per tenant, then edges ───────────────────────────────────────
	perTenantPairs := map[string]int{}
	inPair := make([]bool, len(devNames))
	perTenantMembers := map[string]int{}
	for k, pi := range pairIdx {
		pa := &pairArr[pi]
		perTenantPairs[pa.tenant]++
		for _, i := range [2]uint32{uint32(k >> 32), uint32(k)} {
			if !inPair[i] {
				inPair[i] = true
				perTenantMembers[pa.tenant]++
			}
		}
	}
	for t, n := range perTenantPairs {
		members := perTenantMembers[t]
		shape := OverlayShapePairs
		possible := members * (members - 1) / 2
		dense := members >= denseMin && possible > 0 && float64(n) >= 0.9*float64(possible)
		if n > maxPairs || dense {
			shape = OverlayShapeExceptions
		}
		res.Stats.Shape[t] = shape
	}
	// Only the pairs that will be DRAWN are sorted (exceptions mode draws a
	// handful out of 10^6).
	keys := make([]uint64, 0, 64)
	for k, pi := range pairIdx {
		pa := &pairArr[pi]
		if res.Stats.Shape[pa.tenant] == OverlayShapeExceptions && pa.sessions > 0 && pa.up == pa.sessions {
			continue // summarised on the transport node
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] }) // devNames is sorted, so this is id order
	for _, k := range keys {
		pa := &pairArr[pairIdx[k]]
		status := StatusDown
		switch {
		case pa.sessions > 0 && pa.up == pa.sessions:
			status = StatusUp
		case pa.up > 0:
			status = StatusDegraded
		}
		var cs []string
		for i, name := range colorNames {
			if pa.colors&colorMask(i) != 0 {
				cs = append(cs, name)
			}
		}
		sort.Strings(cs)
		reporters := 0
		if pa.aReported {
			reporters++
		}
		if pa.bReported {
			reporters++
		}
		conf := 0.85
		if reporters == 2 {
			conf = 0.95 // both ends reported the sessions
		}
		res.Edges = append(res.Edges, Edge{
			ID: "sdwan|" + pa.a + "|" + pa.b, Source: pa.a, Target: pa.b,
			Relationship: RelOverlay, Protocol: SrcSDWANBFD, Status: status, Confidence: conf,
			Evidence: []EvidenceRef{{Source: SrcSDWANBFD, Confidence: conf,
				Detail: fmt.Sprintf("SD-WAN tunnels over %s — %d of %d BFD sessions up (reported by %s)", strings.Join(cs, ", "), pa.up, pa.sessions, ends(reporters))}},
			Tags: map[string]string{"provenance": "observed", "colors": strings.Join(cs, ","), "overlay": "sdwan"},
		})
		res.Stats.PairsDrawn++
	}

	// ── 5. transport nodes + membership ───────────────────────────────────────
	ckeys := make([]colorKey, 0, len(colors))
	for k := range colors {
		ckeys = append(ckeys, k)
	}
	sort.Slice(ckeys, func(i, j int) bool {
		if ckeys[i].tenant != ckeys[j].tenant {
			return ckeys[i].tenant < ckeys[j].tenant
		}
		return colorNames[ckeys[i].color] < colorNames[ckeys[j].color]
	})
	for _, k := range ckeys {
		c := colors[k]
		color := colorNames[k.color]
		id := TransportNodeID(k.tenant, color)
		health := HealthUnknown
		switch {
		case c.sessions > 0 && c.up == c.sessions:
			health = HealthOK
		case c.up > 0:
			health = HealthWarning
		case c.sessions > 0:
			health = HealthCritical
		}
		res.Nodes = append(res.Nodes, Node{
			ID: id, Label: "WAN transport · " + color, Kind: KindWAN, Health: health,
			Confidence: 0.6, Resolved: true,
			Metrics: map[string]float64{"members": float64(c.count), "sessions": float64(c.sessions), "sessions_up": float64(c.up)},
			Evidence: []EvidenceRef{{Source: SrcSDWANTLOC, Confidence: 0.6,
				Detail: fmt.Sprintf("Inferred: the provider network behind SD-WAN colour %q is not visible; %d edge(s) attach to it, %d of %d BFD sessions up", color, c.count, c.up, c.sessions)}},
			Tags: map[string]string{"provenance": "inferred", "overlay": "sdwan", "color": color, "shape": res.Stats.Shape[k.tenant]},
		})
		for di, member := range c.members {
			if !member {
				continue
			}
			dev := devNames[di]
			res.Edges = append(res.Edges, Edge{
				ID: "sdwan-tloc|" + dev + "|" + color, Source: dev, Target: id,
				Relationship: RelInferred, Protocol: SrcSDWANTLOC, Status: StatusUnknown, Confidence: 0.6,
				Evidence: []EvidenceRef{{Source: SrcSDWANTLOC, Confidence: 0.6,
					Detail: "Attaches to SD-WAN colour " + color + " (observed in its BFD sessions); the transport network itself is inferred"}},
				Tags: map[string]string{"provenance": "inferred", "overlay": "sdwan", "color": color},
			})
		}
	}
	return res
}

func sortedFactIDs(m map[string]collectors.OverlayDeviceFacts) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func ends(n int) string {
	if n == 2 {
		return "both ends"
	}
	return "one end"
}

func hasKey(m map[string]string, k string) bool {
	_, ok := m[k]
	return ok
}
