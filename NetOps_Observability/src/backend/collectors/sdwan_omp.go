// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// sdwan_omp.go — Cisco SD-WAN OMP peers: the control-plane sessions an edge
// holds with its vSmart controllers (and a controller with every edge). An
// edge whose OMP sessions are down keeps forwarding on stale routes for a
// while, then loses them — a fault BFD alone does not show.
//
// Numeric OIDs compiled with snmptranslate; the columns are identical in every
// published release of each family (VIPTELA-OMP 20.9–26.1, CISCO-SDWAN-OMP-MIB
// 17.9–26.1), but the two families number them differently:
//
//	              table                         type state site routes-rcvd  INDEX
//	viptela       41916.5.2.2.1 ompSummaryPeers  .2   .5    .4   .34          {Peer InetAddressIP}
//	cisco-sdwan   9.9.1003.1.2.2.1 ompSummaryMt  .3   .7    .5   .36          {TenantId, Peer}
//
// The cEdge TenantId is SD-WAN multitenancy — NOT a Correlix tenant — and is
// never used as one.

type ompLayout struct {
	entry                      []int
	colType, colState, colSite int
	colRoutesRcvd              int
	leadingArcs                int // index arcs before the peer address (cEdge TenantId)
}

var ompLayouts = map[string]ompLayout{
	"viptela":     {entry: []int{1, 3, 6, 1, 4, 1, 41916, 5, 2, 2, 1}, colType: 2, colState: 5, colSite: 4, colRoutesRcvd: 34},
	"cisco-sdwan": {entry: []int{1, 3, 6, 1, 4, 1, 9, 9, 1003, 1, 2, 2, 1}, colType: 3, colState: 7, colSite: 5, colRoutesRcvd: 36, leadingArcs: 1},
}

// OMP peer types and states (the MIB enums, identical in both families).
var ompTypes = map[int64]string{0: "unknown", 1: "vedge", 2: "vhub", 3: "vsmart", 4: "vbond", 5: "vmanage", 6: "ztp", 7: "vcontainer"}

// ompStateNames: up(3) and up-in-gr(8, graceful restart) are the healthy ones.
var ompStateNames = map[int64]string{0: "invalid", 1: "init", 2: "handshake", 3: "up", 4: "down", 5: "init-in-gr", 6: "down-in-gr", 7: "handshake-in-gr", 8: "up-in-gr"}

// OverlayOMPPeer is one OMP session.
type OverlayOMPPeer struct {
	SystemIP       string `json:"system_ip"`
	Type           string `json:"type,omitempty"`
	SiteID         string `json:"site_id,omitempty"`
	State          int64  `json:"state"` // the MIB enum, 0..8
	RoutesReceived int64  `json:"routes_received"`
	routesKnown    bool
}

// Up reports a healthy OMP session (up, or up during graceful restart).
func (p OverlayOMPPeer) Up() bool { return p.State == 3 || p.State == 8 }

// ompPeerAddr decodes the peer address from a row index: `lead` leading arcs,
// then an InetAddressIP with or without its length octet.
func ompPeerAddr(idx string, lead int) (string, bool) {
	arcs, ok := parseArcs(idx)
	if !ok || len(arcs) < lead {
		return "", false
	}
	a := arcs[lead:]
	switch len(a) {
	case 5, 17: // length-prefixed
		if a[0] != len(a)-1 {
			return "", false
		}
		a = a[1:]
	case 4, 16:
	default:
		return "", false
	}
	addr := arcsAddr(a)
	return addr, addr != ""
}

// readOMP walks the OMP peer table. ok=false when the table did not answer.
func readOMP(ctx context.Context, walk walkFn, addr string, creds snmpCreds, mib string, maxRows int) (peers []OverlayOMPPeer, truncated bool, err error) {
	l, known := ompLayouts[mib]
	if !known {
		return nil, false, nil
	}
	states, trunc, err := walk(ctx, addr, creds, col(l.entry, l.colState), maxRows)
	if err != nil {
		return nil, false, err
	}
	byIdx := map[string]*OverlayOMPPeer{}
	for idx, v := range states {
		ip, ok := ompPeerAddr(idx, l.leadingArcs)
		if !ok || !isIntegerTag(v.tag) {
			continue
		}
		st := v.int()
		if _, valid := ompStateNames[st]; !valid {
			continue
		}
		byIdx[idx] = &OverlayOMPPeer{SystemIP: ip, State: st}
	}
	if len(byIdx) == 0 {
		return nil, trunc, nil
	}
	if types, _, terr := walk(ctx, addr, creds, col(l.entry, l.colType), maxRows); terr == nil {
		for idx, v := range types {
			if p := byIdx[idx]; p != nil && isIntegerTag(v.tag) {
				p.Type = ompTypes[v.int()]
			}
		}
	}
	if sites, _, serr := walk(ctx, addr, creds, col(l.entry, l.colSite), maxRows); serr == nil {
		for idx, v := range sites {
			if p := byIdx[idx]; p != nil {
				p.SiteID = siteIDValue(v)
			}
		}
	}
	if rr, _, rerr := walk(ctx, addr, creds, col(l.entry, l.colRoutesRcvd), maxRows); rerr == nil {
		for idx, v := range rr {
			if p := byIdx[idx]; p != nil && isIntegerTag(v.tag) {
				p.RoutesReceived, p.routesKnown = v.int(), true
			}
		}
	}
	idxs := make([]string, 0, len(byIdx))
	for idx := range byIdx {
		idxs = append(idxs, idx)
	}
	sort.Strings(idxs)
	for _, idx := range idxs {
		peers = append(peers, *byIdx[idx])
	}
	return peers, trunc, nil
}

// isController: on a vSmart / vBond / vManage the OMP table lists every edge,
// so per-peer series are not emitted there — counts only (bounded cardinality).
func isController(personality string) bool {
	p := strings.ToLower(personality)
	return strings.Contains(p, "vsmart") || strings.Contains(p, "vbond") || strings.Contains(p, "vmanage") || strings.Contains(p, "controller")
}

// ompLines renders a device's OMP state.
func ompLines(device, mib, personality string, peers []OverlayOMPPeer, now int64) []string {
	up, notUp := 0, 0
	var out []string
	controller := isController(personality)
	for _, p := range peers {
		if p.Up() {
			up++
		} else {
			notUp++
		}
		if controller {
			continue
		}
		out = append(out, fmt.Sprintf(`device_omp_peer_state{device=%q,peer=%q,type=%q,site_id=%q,mib=%q} %d %d`,
			device, p.SystemIP, p.Type, p.SiteID, mib, p.State, now))
		if p.routesKnown {
			out = append(out, fmt.Sprintf(`device_omp_peer_routes_received{device=%q,peer=%q,mib=%q} %s %d`,
				device, p.SystemIP, mib, strconv.FormatInt(p.RoutesReceived, 10), now))
		}
	}
	out = append(out,
		fmt.Sprintf(`device_omp_peers{device=%q,state="up"} %d %d`, device, up, now),
		fmt.Sprintf(`device_omp_peers{device=%q,state="not_up"} %d %d`, device, notUp, now))
	return out
}
