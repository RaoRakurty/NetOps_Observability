// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"net/netip"
	"regexp"
	"strings"
)

// sdwan_tunnel.go — ONE identity for an SD-WAN tunnel, whichever end reports it.
//
// vManage reports each BFD session from both ends, mirrored (verified on a
// 20.6.1 fabric with vEdge 20.6 and IOS XE 17.3 edges, 2026-10-25):
//
//	A's row: vdevice-name=A  system-ip=B  local-color=cA  color=cB
//	B's row: vdevice-name=B  system-ip=A  local-color=cB  color=cA
//
// Keyed by the reporting end, the two halves never met: each end became its own
// correlation node, so "the tunnel A↔B is down" arrived as two unrelated facts.
// Sorting the two TLOCs (system-ip, colour) gives both ends the same id.
//
// The id avoids every character the correlation engine gives structure to —
// ':' (device:component) and '->' (probe path) — so it is one opaque entity.

var tunnelColor = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)

// CanonicalTunnelID returns the tunnel id for the session between TLOC
// (aIP, aColor) and TLOC (bIP, bColor), or "" when either end is not a valid
// IPv4 system-ip with a plain colour name. Cisco SD-WAN system-ips are IPv4.
func CanonicalTunnelID(aIP, aColor, bIP, bColor string) string {
	a, okA := tloc(aIP, aColor)
	b, okB := tloc(bIP, bColor)
	if !okA || !okB || a == b {
		return ""
	}
	if b < a {
		a, b = b, a
	}
	return a + "|" + b
}

func tloc(ip, color string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is4() {
		return "", false
	}
	c := strings.ToLower(strings.TrimSpace(color))
	if !tunnelColor.MatchString(c) {
		return "", false
	}
	return addr.String() + "/" + c, true
}
