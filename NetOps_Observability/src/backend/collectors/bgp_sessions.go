// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sort"
	"strings"
)

// bgp_sessions.go — each device's BGP sessions as the WAN rule needs them:
// which local address each session runs from, and both ASes (tracker 436 (b)).
//
// BGP4-MIB (RFC 4273) bgpPeerTable is the standard source every vendor's agent
// answers for the default instance: Cisco IOS/IOS-XE/IOS-XR/NX-OS, Juniper,
// Arista EOS (IPv4 sessions). Nokia SR OS and SONiC leave it empty or partial —
// their sessions come from TIMETRA-BGP-MIB / CISCO-BGP4-MIB in bgp_vrf_peers.go,
// which carries no local address today, so those devices state nothing here
// (stated, not guessed). The poller already walks bgpPeerRemoteAs and reads
// bgpLocalAs for the BGP panels; this adds one column, bgpPeerLocalAddr, walked
// only on a device that listed at least one peer.
//
// An eBGP session to a peer the inventory does not hold, from a port's own
// address, is the classic hand-off to a carrier or another organisation — the
// one WAN fact a plain router states without a controller (wan.ExternalBGP).

// bgpPeerLocalAddrOID is BGP4-MIB bgpPeerLocalAddr (IpAddress), indexed by
// bgpPeerRemoteAddr — the same index as bgpPeerRemoteAs.
var bgpPeerLocalAddrOID = []int{1, 3, 6, 1, 2, 1, 15, 3, 1, 5}

const (
	// bgpSessionsKey holds deviceID → BGPSessions, published every cycle with
	// the interface maps' TTL (a dead collector must let it self-expire).
	bgpSessionsKey    = "netops:topology:bgp_sessions"
	bgpSessionsTTLSec = ifRowPublishTTLSec
	// maxBGPSessionDevices / maxBGPPeersPerDevice bound the published state (a
	// hostile or broken agent must not grow it without limit).
	maxBGPSessionDevices = 20000
	maxBGPPeersPerDevice = 4096
)

// BGPSession is one BGP4-MIB session of one device.
type BGPSession struct {
	// Local is bgpPeerLocalAddr, canonical IP text ("" = the agent reported
	// none, or 0.0.0.0: a session that is not up has no local address).
	Local string `json:"local,omitempty"`
	// RemoteAS is bgpPeerRemoteAs (0 = not reported).
	RemoteAS int64 `json:"remote_as,omitempty"`
}

// BGPSessions is one device's BGP4-MIB sessions, keyed by the peer address.
type BGPSessions struct {
	// LocalAS is bgpLocalAs (0 = not reported; 23456 = AS_TRANS, a 4-byte AS
	// the 16-bit object cannot carry).
	LocalAS int64                 `json:"local_as,omitempty"`
	Peers   map[string]BGPSession `json:"peers"`
}

// bgpSessionReading collects one device's BGP facts during a poll.
type bgpSessionReading struct {
	localAS        int64
	remoteAS       map[string]int64
	remoteASWalked bool
}

func (r *bgpSessionReading) noteRemoteAS(rows map[string]berVal) {
	r.remoteASWalked = true
	if r.remoteAS == nil {
		r.remoteAS = map[string]int64{}
	}
	for idx, v := range rows {
		r.remoteAS[idx] = valueInt(v)
	}
}

// canonIP returns the canonical text of a usable unicast address; "" for junk,
// unspecified, loopback, multicast or link-local.
func canonIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return ""
	}
	return ip.String()
}

// sessions finishes the reading: the peers the remote-AS walk listed, each with
// its local address when walkLocal returns one. read says the result is the
// device's whole answer (both walks finished), so it may replace the last one.
func (r *bgpSessionReading) sessions(walkLocal func() (map[string]berVal, error)) (BGPSessions, bool) {
	out := BGPSessions{LocalAS: r.localAS, Peers: map[string]BGPSession{}}
	if !r.remoteASWalked {
		return out, false
	}
	if len(r.remoteAS) == 0 {
		return out, true // BGP4-MIB answered and lists no peer
	}
	peers := make([]string, 0, len(r.remoteAS))
	for p := range r.remoteAS {
		peers = append(peers, p)
	}
	sort.Strings(peers)
	for _, p := range peers {
		peer := canonIP(p)
		if peer == "" || len(out.Peers) >= maxBGPPeersPerDevice {
			continue
		}
		out.Peers[peer] = BGPSession{RemoteAS: r.remoteAS[p]}
	}
	locals, err := walkLocal()
	if err != nil {
		return out, false
	}
	for idx, v := range locals {
		peer := canonIP(idx)
		s, ok := out.Peers[peer]
		if !ok {
			continue
		}
		s.Local = canonIP(v.ip())
		out.Peers[peer] = s
	}
	return out, true
}

// bgpSessionRows keeps each device's last-read sessions for the publish. Owned
// by pollOnce. A device whose sessions were not read this cycle keeps its last
// ones; a device that leaves the target set loses them.
type bgpSessionRows map[string]BGPSessions

// update folds one cycle into the rows and returns what to publish.
func (a bgpSessionRows) update(targets []Target, results []deviceOutcome) map[string]BGPSessions {
	in := make(map[string]bool, len(targets))
	for i, tg := range targets {
		in[tg.ID] = true
		r := results[i]
		if r.id == "" || !r.bgpRead {
			continue
		}
		if len(r.bgp.Peers) == 0 {
			delete(a, tg.ID)
			continue
		}
		if _, ok := a[tg.ID]; !ok && len(a) >= maxBGPSessionDevices {
			continue
		}
		a[tg.ID] = r.bgp
	}
	for id := range a {
		if !in[id] {
			delete(a, id)
		}
	}
	out := make(map[string]BGPSessions, len(a))
	for id, s := range a {
		out[id] = s
	}
	return out
}

// FetchBGPSessions reads every device's BGP4-MIB sessions. Absent or no
// key-value channel → an empty map, nil error; unread or undecodable → an
// error (tracker 307: we authored it, so a decode failure is corrupt evidence).
// Untrusted on the way back in: addresses are re-canonicalised and bounded.
func FetchBGPSessions(ctx context.Context) (map[string]BGPSessions, error) {
	raw := map[string]BGPSessions{}
	if err := redisGetJSON(ctx, "BGP sessions", bgpSessionsKey, &raw); err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return map[string]BGPSessions{}, nil
		}
		return map[string]BGPSessions{}, err
	}
	out := make(map[string]BGPSessions, len(raw))
	for dev, s := range raw {
		if dev == "" || len(out) >= maxBGPSessionDevices {
			continue
		}
		clean := BGPSessions{LocalAS: s.LocalAS, Peers: map[string]BGPSession{}}
		for p, sess := range s.Peers {
			peer := canonIP(p)
			if peer == "" || len(clean.Peers) >= maxBGPPeersPerDevice {
				continue
			}
			clean.Peers[peer] = BGPSession{Local: canonIP(sess.Local), RemoteAS: sess.RemoteAS}
		}
		out[dev] = clean
	}
	return out, nil
}

// publishBGPSessions writes the cycle's sessions.
func publishBGPSessions(ctx context.Context, sessions map[string]BGPSessions) {
	b, err := json.Marshal(sessions)
	if err != nil {
		log.Printf("snmpmetrics: BGP sessions not published this cycle: %v — the WAN rule reads last cycle's", err)
		return
	}
	redisPublish(ctx, "bgp-sessions", bgpSessionsKey, string(b), bgpSessionsTTLSec)
}
