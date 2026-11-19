// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// ipsec.go — the IPsec security-association read (tracker 420 (a)).
//
// Only the IOS-XE parser exists, built from `show crypto ipsec sa` captured on
// a real Cisco IOS XE 17.3.2 SD-WAN edge (lab, 2026-11-19) — the output the
// battery's vpn area reads. Every other dialect's IPsec command is the
// vendor's documented read (doc_claimed): its output stays raw evidence until
// a capture exists. The IKE (phase 1) read has no parser: the lab's edges key
// their tunnels through the SD-WAN controllers, so `show crypto ikev2 sa`
// printed nothing, and an empty capture proves nothing.

import "strings"

// maxIPsecSAs bounds one parse (§9): an edge in a large overlay has one SA
// pair per peer, and an adversarial capture must not grow the result without
// limit.
const maxIPsecSAs = 2000

// IPsecSA is one protected flow toward one peer, as the device reports it.
// Counters are CUMULATIVE since the SA pair came up — one read shows what the
// SA has carried, not what it is carrying now.
type IPsecSA struct {
	// Interface is the tunnel interface the flow is bound to ("Tunnel1").
	Interface string `json:"interface"`
	// Peer is current_peer; PeerPort its UDP port when NAT-T/UDP-encapsulated.
	Peer     string `json:"peer"`
	PeerPort *int   `json:"peer_port,omitempty"`
	// LocalEndpoint / RemoteEndpoint are the crypto endpoints.
	LocalEndpoint  string `json:"local_endpoint,omitempty"`
	RemoteEndpoint string `json:"remote_endpoint,omitempty"`
	// PktsEncaps / PktsDecaps are packets sent / received through the SA.
	PktsEncaps *int64 `json:"pkts_encaps,omitempty"`
	PktsDecaps *int64 `json:"pkts_decaps,omitempty"`
	SendErrors *int64 `json:"send_errors,omitempty"`
	RecvErrors *int64 `json:"recv_errors,omitempty"`
	// InboundESP / OutboundESP count the ESP SAs listed in each direction;
	// InboundStatus / OutboundStatus are the first such SA's Status verbatim
	// ("ACTIVE(ACTIVE)"), empty when the direction lists none.
	InboundESP     int    `json:"inbound_esp"`
	OutboundESP    int    `json:"outbound_esp"`
	InboundStatus  string `json:"inbound_status,omitempty"`
	OutboundStatus string `json:"outbound_status,omitempty"`
}

func registerIPsecParsers(l *Library) {
	l.register(CmdIPsecSA, parseIOSXEIPsecSA, DialectCiscoIOSXE)
}

// parseIOSXEIPsecSA reads `show crypto ipsec sa`. A flow starts at its
// `current_peer` line and owns every counter, endpoint and SA line until the
// next one; the enclosing `interface:` header names its tunnel. A line the
// parser does not author against is ignored, never folded into a row.
func parseIOSXEIPsecSA(lines []string) Result {
	var res Result
	iface := ""
	sec := "" // "in" / "out" while inside an ESP SA list, else ""
	var cur *IPsecSA
	flush := func() {
		if cur != nil && len(res.IPsecSAs) < maxIPsecSAs {
			res.IPsecSAs = append(res.IPsecSAs, *cur)
		}
		cur = nil
	}
	for _, ln := range lines {
		t := trim(ln)
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "interface: "):
			flush()
			iface = trim(t[len("interface: "):])
			sec = ""
		case strings.HasPrefix(lower, "current_peer "):
			flush()
			fs := fields(t)
			if len(fs) < 2 || !(looksIPv4(fs[1]) || strings.Contains(fs[1], ":")) {
				continue
			}
			cur = &IPsecSA{Interface: iface, Peer: fs[1]}
			if len(fs) >= 4 && strings.EqualFold(fs[2], "port") {
				if n, ok := atoiOK(fs[3]); ok && n > 0 && n <= 65535 {
					p := int(n)
					cur.PeerPort = &p
				}
			}
			sec = ""
		case cur == nil:
			continue
		case strings.HasPrefix(lower, "#pkts encaps:"):
			cur.PktsEncaps = ipsecCount(t, "#pkts encaps:")
		case strings.HasPrefix(lower, "#pkts decaps:"):
			cur.PktsDecaps = ipsecCount(t, "#pkts decaps:")
		case strings.HasPrefix(lower, "#send errors"):
			cur.SendErrors = ipsecCount(t, "#send errors")
			if i := strings.Index(t, "#recv errors"); i >= 0 { // exact device case: never an offset from the folded copy
				cur.RecvErrors = ipsecCount(t[i:], "#recv errors")
			}
		case strings.HasPrefix(lower, "local crypto endpt.:"):
			for _, part := range strings.Split(t, ",") {
				p := trim(part)
				if v, ok := strings.CutPrefix(p, "local crypto endpt.:"); ok {
					cur.LocalEndpoint = trim(v)
				}
				if v, ok := strings.CutPrefix(p, "remote crypto endpt.:"); ok {
					cur.RemoteEndpoint = trim(v)
				}
			}
		case lower == "inbound esp sas:":
			sec = "in"
		case lower == "outbound esp sas:":
			sec = "out"
		case strings.HasSuffix(lower, " sas:"): // ah / pcp lists: not ESP
			sec = ""
		case strings.HasPrefix(lower, "spi: ") && sec != "":
			if sec == "in" {
				cur.InboundESP++
			} else {
				cur.OutboundESP++
			}
		case strings.HasPrefix(lower, "status: ") && sec != "":
			st := trim(t[len("status: "):])
			if sec == "in" && cur.InboundStatus == "" {
				cur.InboundStatus = st
			}
			if sec == "out" && cur.OutboundStatus == "" {
				cur.OutboundStatus = st
			}
		}
	}
	flush()
	return res
}

// ipsecCount reads the integer right after marker ("#pkts encaps: 92145,").
// The marker is matched in the device's own (lower) case on the original
// line, so the offset slices the string it was measured on.
func ipsecCount(t, marker string) *int64 {
	i := strings.Index(t, marker)
	if i < 0 {
		return nil
	}
	fs := fields(strings.TrimSpace(t[i+len(marker):]))
	if len(fs) == 0 {
		return nil
	}
	n, ok := atoiOK(strings.TrimRight(fs[0], ","))
	if !ok || n < 0 {
		return nil
	}
	return &n
}
