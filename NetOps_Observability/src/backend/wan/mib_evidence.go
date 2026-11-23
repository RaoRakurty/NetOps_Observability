// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// mib_evidence.go — the WAN facts a plain router states over standard MIBs,
// with no SD-WAN controller (tracker 436 (b)/(c)). Pure: the api reads the
// interface bridge (IF-MIB ifType) and the published BGP4-MIB sessions and
// passes them in.

// SNMPIf is what the device's own IF-MIB says about one interface.
type SNMPIf struct {
	// Kind is the closed-set kind the IANA ifType states (ifbridge.IfTypeKind:
	// "ethernet", "loopback", "tunnel", "wan_media"; "" = nothing).
	Kind string
	// Type names the ifType for evidence, e.g. "ppp(23)".
	Type string
}

// BGPSession is one BGP4-MIB session of one device: the peer, the local
// address the session runs from, and the peer's AS.
type BGPSession struct {
	Peer, Local string
	RemoteAS    int64
}

// ExternalPeer is an eBGP session to a peer outside the inventory, keyed by the
// local address it runs from (ExternalBGPPeers).
type ExternalPeer struct {
	Peer              string
	RemoteAS, LocalAS int64
}

// asTrans is AS_TRANS (RFC 6793): the 16-bit bgpLocalAs / bgpPeerRemoteAs of a
// 4-byte AS.
const asTrans = 23456

// ebgp reports a session between two different ASes, when that can be told: the
// router's own AS must be known and not AS_TRANS (its real 4-byte AS is then
// unknown); a peer showing AS_TRANS to a 2-byte-AS router has a 4-byte AS, so
// it is a different AS.
func ebgp(localAS, remoteAS int64) bool {
	if localAS <= 0 || localAS == asTrans || remoteAS <= 0 {
		return false
	}
	return remoteAS != localAS
}

// canonAddr is the canonical text of a parseable address; "" otherwise.
func canonAddr(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// ExternalBGPPeers picks, from one device's BGP4-MIB sessions, the eBGP
// sessions to a peer the inventory does not hold (inventory: every address of
// every device the CALLER may see — management addresses and interface
// addresses — so another tenant's device never decides what a caller's port
// is, and to a tenant another tenant's router IS an external party). A session
// with no local address (not up) states nothing. Keyed by the local address;
// two external peers on one address (an exchange LAN) name the lowest peer
// address, deterministically.
func ExternalBGPPeers(sessions []BGPSession, localAS int64, inventory map[string]bool) map[string]ExternalPeer {
	out := map[string]ExternalPeer{}
	for _, s := range sessions {
		peer, local := canonAddr(s.Peer), canonAddr(s.Local)
		if peer == "" || local == "" || inventory[peer] || !ebgp(localAS, s.RemoteAS) {
			continue
		}
		if cur, ok := out[local]; ok && !addrLess(peer, cur.Peer) {
			continue
		}
		out[local] = ExternalPeer{Peer: peer, RemoteAS: s.RemoteAS, LocalAS: localAS}
	}
	return out
}

// addrLess orders two canonical addresses numerically (IPv4 before IPv6).
func addrLess(a, b string) bool {
	pa, pb := net.ParseIP(a), net.ParseIP(b)
	a4, b4 := pa.To4(), pb.To4()
	if (a4 != nil) != (b4 != nil) {
		return a4 != nil
	}
	if a4 != nil {
		pa, pb = a4, b4
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// externalFor is the external peer reached from one of the interface's
// addresses (the lowest address that has one).
func externalFor(addrs []string, ext map[string]ExternalPeer) *ExternalPeer {
	if len(ext) == 0 {
		return nil
	}
	sorted := append([]string(nil), addrs...)
	sort.Slice(sorted, func(i, j int) bool { return addrLess(sorted[i], sorted[j]) })
	for _, a := range sorted {
		if p, ok := ext[a]; ok {
			return &p
		}
	}
	return nil
}

// peerText is "203.0.113.1 (AS 64500)", the eBGP peer as evidence reads it.
func peerText(p ExternalPeer) string {
	return p.Peer + " (AS " + strconv.FormatInt(p.RemoteAS, 10) + ")"
}
