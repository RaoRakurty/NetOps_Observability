// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// classify.go — which interfaces are WAN, decided per INTERFACE from evidence.
//
// Until 2026-11-22 the projection took every addressed port of any device whose
// NAME matched the WAN pattern ("wan|edge|gw|dmz"), so an SD-WAN edge listed its
// LAN, loopback, system and service ports as WAN circuits (owner report). The
// rule here reads what the platform already knows about each port and states
// why: a confirmed WAN interface is measured and becomes a circuit; a possible
// one is shown apart, never probed, until an operator marks it; everything else
// is not WAN. The device-name pattern only makes a device a candidate.
//
// Pure: no IO. The api assembles Facts from the interface bridge (controller
// rows: VPN, port role, interface kind; the device's own IF-MIB ifType), the
// SD-WAN overlay facts (TLOC interfaces), the device's BGP4-MIB sessions, the
// policy and the operator's marks (tracker 436: the last two MIB facts are what
// a plain router states without a controller).

// Confidence of a WAN verdict.
const (
	Confirmed = "confirmed"
	Possible  = "possible"
)

// Basis is the first rule that decided an interface, a closed set.
type Basis string

const (
	// Confirmed.
	BasisOperator            Basis = "operator"             // an operator marked it WAN
	BasisSDWANTransport      Basis = "sdwan_transport_port" // controller: VPN 0, port role transport
	BasisSDWANTLOC           Basis = "sdwan_tloc"           // the device's SD-WAN TLOC table names it
	BasisSDWANTunnelSource   Basis = "sdwan_tunnel_source"  // VPN 0, an SD-WAN tunnel rides its address
	BasisDeclaredNextHop     Basis = "declared_next_hop"    // the policy names an ISP next-hop for this port
	BasisWANMedia            Basis = "wan_media_type"       // IF-MIB ifType: a medium that only carries WAN circuits
	BasisExternalBGP         Basis = "external_bgp_peer"    // BGP4-MIB: eBGP to a peer outside the inventory from its address
	BasisTransportNoTunnel   Basis = "transport_vpn_no_tunnel"
	BasisDescribedAsWAN      Basis = "described_as_wan"
	BasisPublicAddress       Basis = "public_address"
	BasisLinked              Basis = "linked"
	BasisCandidateRouterOnly Basis = "wan_router_only"
)

// Marks an operator sets on an interface.
const (
	MarkWAN    = "wan"
	MarkNotWAN = "not_wan"
)

// Evidence is one fact behind a verdict, in plain words.
type Evidence struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
}

// IfFacts is everything known about one interface of one device.
type IfFacts struct {
	Name  string
	Addrs []string // canonical IP text
	// VRF is the controller's VPN/VRF ("" = not reported).
	VRF string
	// Role and Kind are the bridge's closed-set port role and interface kind
	// (Kind from the controller, else from the device's IF-MIB ifType).
	Role, Kind string
	// IfType names the IF-MIB ifType behind a "wan_media" Kind, for evidence.
	IfType string
	// ExternalBGP is an eBGP session to a peer outside the inventory that runs
	// from one of this interface's addresses (nil = none).
	ExternalBGP *ExternalPeer
	Alias       string
	// InTLOC: the device's SD-WAN TLOC table names this interface, or one of its
	// addresses is a local TLOC (BFD source) address.
	InTLOC bool
	// TunnelOver names an SD-WAN tunnel interface on this device that carries
	// the same address in VPN 0 (cEdge: Tunnel1 rides GigabitEthernet1).
	TunnelOver string
	// NextHop is the policy's ISP next-hop declared for exactly this port.
	NextHop string
	// Linked names the WAN-candidate device this port is directly connected to.
	Linked string
	// Mark is the operator's mark (MarkWAN, MarkNotWAN, "").
	Mark string
}

// DeviceFacts is one device and its interfaces.
type DeviceFacts struct {
	// Candidate: something says this device sits at the WAN edge (its name
	// matches the policy pattern, or it is an SD-WAN edge). It only widens what
	// is offered as POSSIBLE; it never confirms an interface.
	Candidate bool
	// SDWAN: the controller or the overlay knows this device as an SD-WAN edge,
	// so its VPN numbers carry the SD-WAN meaning (0 transport, 512 management,
	// others service).
	SDWAN  bool
	Ifaces []IfFacts
}

// Verdict is the decision for one interface. Confidence "" means not WAN.
type Verdict struct {
	Interface  string
	Confidence string
	Basis      Basis
	Reason     string
	Evidence   []Evidence
}

var (
	loopbackNamePattern = regexp.MustCompile(`(?i)^(lo|loopback|system|null|nvi|sdwan-system-intf|dialer|vlan-?if-?mgmt)\d*([./:]\d+)*$`)
	tunnelNamePattern   = regexp.MustCompile(`(?i)^(tunnel|tu|gr-|ip-|st|ipsec|vti|gre)\d`)
	wanWordPattern      = regexp.MustCompile(`(?i)(^|[^a-z])(wan|isp|inet|internet|mpls|uplink|transport|circuit|broadband|lte|dsl)([^a-z]|$)`)
)

// isLoopbackLike: a loopback, system, null or NVI interface, by name or kind.
func isLoopbackLike(f IfFacts) bool {
	return loopbackNamePattern.MatchString(strings.TrimSpace(f.Name)) || f.Kind == "loopback" || f.Role == "loopback"
}

// IsTunnelInterface: a tunnel virtual interface, by kind or name.
func IsTunnelInterface(name, kind string) bool {
	return kind == "tunnel" || tunnelNamePattern.MatchString(strings.TrimSpace(name))
}

// sdwanVPN reads an SD-WAN VPN number; ok=false when the VRF is not numeric.
func sdwanVPN(vrf string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(vrf))
	return n, err == nil && n >= 0
}

// publicAddr: any address that is globally routable unicast and not RFC 1918,
// CGNAT, documentation, loopback or link-local.
func publicAddr(addrs []string) string {
	cgnat := net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
			continue
		}
		return a
	}
	return ""
}

func ev(source, detail string) Evidence { return Evidence{Source: source, Detail: detail} }

// Classify decides every interface of one device. Deterministic: the result is
// sorted by interface name. Rules, first match wins:
//
//  1. Operator mark: "not WAN" hides it, "WAN" confirms it. Then a management
//     port (by name, or SD-WAN VPN 512) is not WAN, whatever else is said.
//  2. Confirmed evidence: SD-WAN transport port; SD-WAN TLOC; SD-WAN tunnel
//     source; a next-hop declared for exactly this port; a WAN medium (IF-MIB
//     ifType: serial, PPP, DSL, cellular…); on a WAN-candidate device, an eBGP
//     session to a peer outside the inventory from the port's address (never
//     a loopback or tunnel). Positive evidence beats the exclusions below (a
//     TLOC bound to a loopback is still WAN, a PPPoE dialer is ppp(23)).
//  3. Not WAN: management; loopback / system / null / NVI; tunnel virtual
//     interfaces (their port is the WAN interface); SD-WAN service, management
//     and internal VPNs; a port the controller calls service.
//  4. Possible: an eBGP session to a peer outside the inventory on a device
//     that does not look like a WAN router; VPN 0 with no tunnel; a WAN word in
//     the description; a public
//     address on a candidate device; directly connected to a candidate device;
//     else, on a candidate device with nothing confirmed, every remaining
//     addressed port.
//  5. Otherwise not WAN.
func Classify(d DeviceFacts) []Verdict {
	out := make([]Verdict, 0, len(d.Ifaces))
	confirmed := 0
	var rest []int // indexes of interfaces left undecided after rule 4's specific tests
	for _, f := range d.Ifaces {
		v := classifyOne(d, f)
		if v.Confidence == Confirmed {
			confirmed++
		}
		out = append(out, v)
	}
	for i, f := range d.Ifaces {
		if out[i].Confidence == "" && out[i].Basis == "" && d.Candidate && len(f.Addrs) > 0 {
			rest = append(rest, i)
		}
	}
	if confirmed == 0 {
		for _, i := range rest {
			out[i] = Verdict{Interface: d.Ifaces[i].Name, Confidence: Possible, Basis: BasisCandidateRouterOnly,
				Reason:   "On a device that looks like a WAN router, but nothing says which of its ports is WAN — mark the right one.",
				Evidence: []Evidence{ev("device", "the device looks like a WAN router, and none of its ports is confirmed")}}
		}
	}
	for i := range out {
		if out[i].Confidence == "" {
			out[i].Basis = "" // an exclusion is not a basis on the wire
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Interface < out[b].Interface })
	return out
}

// KindWANMedia is the bridge's kind for a medium that only carries WAN
// circuits (ifbridge.KindWANMedia; the closed set's spelling, not imported, so
// this package stays free of the bridge).
const KindWANMedia = "wan_media"

// mediaText is the ifType as evidence reads it ("ppp(23)"), or a plain phrase
// when the controller stated the kind without a number.
func mediaText(f IfFacts) string {
	if f.IfType != "" {
		return f.IfType
	}
	return "a WAN medium"
}

// externalBGPPort: an eBGP session to an external peer runs from this port, and
// the port is one that can own a WAN hand-off — never a loopback (a multihop
// session's source) or a tunnel (its underlay is the WAN port).
func externalBGPPort(f IfFacts) bool {
	return f.ExternalBGP != nil && !isLoopbackLike(f) && !IsTunnelInterface(f.Name, f.Kind)
}

// excluded marks a verdict decided as NOT WAN by an exclusion (rule 3), so the
// candidate-router fallback leaves it alone.
const excluded Basis = "-excluded"

// sdwanMgmtVPN is the SD-WAN management VPN.
const sdwanMgmtVPN = 512

func classifyOne(d DeviceFacts, f IfFacts) Verdict {
	v := Verdict{Interface: f.Name}
	switch f.Mark {
	case MarkNotWAN:
		v.Basis = excluded
		return v
	case MarkWAN:
		v.Confidence, v.Basis = Confirmed, BasisOperator
		v.Reason = "Marked as WAN by an operator."
		v.Evidence = []Evidence{ev("operator", "marked as WAN")}
		return v
	}
	vpn, numeric := sdwanVPN(f.VRF)
	transportVPN := numeric && vpn == 0
	// A management port is never WAN transport, whatever else is said about it
	// (only an operator's mark, above, overrides): on a shared management
	// segment it would pull the whole fabric in.
	if IsMgmtInterface(f.Name) || (d.SDWAN && numeric && vpn == sdwanMgmtVPN) {
		v.Basis = excluded
		return v
	}

	// 2. Confirmed evidence.
	switch {
	case f.Role == "transport" && (transportVPN || f.VRF == ""):
		v.Confidence, v.Basis = Confirmed, BasisSDWANTransport
		v.Reason = "SD-WAN transport interface, as the controller reports it."
		v.Evidence = []Evidence{ev("controller", "port type transport, VPN 0")}
	case f.InTLOC:
		v.Confidence, v.Basis = Confirmed, BasisSDWANTLOC
		v.Reason = "SD-WAN transport interface — the device lists it as a transport locator."
		v.Evidence = []Evidence{ev("sdwan", "named in the device's transport locator (TLOC) table")}
	case transportVPN && f.TunnelOver != "":
		v.Confidence, v.Basis = Confirmed, BasisSDWANTunnelSource
		v.Reason = "SD-WAN transport interface — tunnel " + f.TunnelOver + " runs over it."
		v.Evidence = []Evidence{ev("controller", "VPN 0, and tunnel "+f.TunnelOver+" uses the same address")}
	case f.NextHop != "":
		v.Confidence, v.Basis = Confirmed, BasisDeclaredNextHop
		v.Reason = "An ISP next-hop (" + f.NextHop + ") is configured for this port."
		v.Evidence = []Evidence{ev("policy", "next-hop "+f.NextHop+" configured for this port")}
	case f.Kind == KindWANMedia:
		v.Confidence, v.Basis = Confirmed, BasisWANMedia
		v.Reason = "Its medium only carries WAN circuits, as the device reports it (" + mediaText(f) + ")."
		v.Evidence = []Evidence{ev("snmp", "IF-MIB ifType "+mediaText(f))}
	case d.Candidate && externalBGPPort(f):
		p := *f.ExternalBGP
		v.Confidence, v.Basis = Confirmed, BasisExternalBGP
		v.Reason = "An eBGP session to " + peerText(p) + ", which is not in the inventory, runs from this port."
		v.Evidence = []Evidence{ev("bgp", "eBGP peer "+peerText(p)+" from this port's address; this router is AS "+strconv.FormatInt(p.LocalAS, 10))}
	}
	if v.Confidence == Confirmed {
		if f.Alias != "" && wanWordPattern.MatchString(f.Alias) {
			v.Evidence = append(v.Evidence, ev("description", f.Alias))
		}
		return v
	}

	// 3. Not WAN.
	switch {
	case d.SDWAN && numeric && vpn != 0:
		// SD-WAN VPN 512 is management, 65528+ the controller's own, any other a
		// service (LAN) VPN.
		v.Basis = excluded
		return v
	case isLoopbackLike(f), IsTunnelInterface(f.Name, f.Kind), f.Role == "service":
		v.Basis = excluded
		return v
	}

	// 4. Possible.
	switch {
	case externalBGPPort(f):
		p := *f.ExternalBGP
		v.Confidence, v.Basis = Possible, BasisExternalBGP
		v.Reason = "An eBGP session to " + peerText(p) + ", which is not in the inventory, runs from this port — on a device that does not look like a WAN router, so it is not measured until marked."
		v.Evidence = []Evidence{ev("bgp", "eBGP peer "+peerText(p)+" from this port's address; this router is AS "+strconv.FormatInt(p.LocalAS, 10))}
	case d.SDWAN && transportVPN && len(f.Addrs) > 0:
		v.Confidence, v.Basis = Possible, BasisTransportNoTunnel
		v.Reason = "In the SD-WAN transport VPN, but no tunnel runs over it."
		v.Evidence = []Evidence{ev("controller", "VPN 0 with an address and no tunnel")}
	case f.Alias != "" && wanWordPattern.MatchString(f.Alias):
		v.Confidence, v.Basis = Possible, BasisDescribedAsWAN
		v.Reason = "Its description reads like a WAN link: “" + f.Alias + "”."
		v.Evidence = []Evidence{ev("description", f.Alias)}
	case d.Candidate && publicAddr(f.Addrs) != "":
		a := publicAddr(f.Addrs)
		v.Confidence, v.Basis = Possible, BasisPublicAddress
		v.Reason = "Has a public address (" + a + ") on a device that looks like a WAN router."
		v.Evidence = []Evidence{ev("address", a+" is a public address")}
	case f.Linked != "":
		v.Confidence, v.Basis = Possible, BasisLinked
		v.Reason = "Directly connected to " + f.Linked + ", which looks like a WAN router — this is usually the LAN side."
		v.Evidence = []Evidence{ev("neighbor", "directly connected to "+f.Linked)}
	}
	return v
}
