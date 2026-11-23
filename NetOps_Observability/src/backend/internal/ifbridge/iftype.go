// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"strconv"
	"strings"
)

// iftype.go — what an interface's IANA ifType says about it (tracker 436 (c)).
//
// IF-MIB ifType (1.3.6.1.2.1.2.2.1.3) is answered by every vendor's agent —
// Cisco IOS/IOS-XE/IOS-XR/NX-OS, Juniper, Nokia SR OS, Arista EOS, SONiC — and a
// controller that reports interfaces (cEdge `interface-type`) states the same
// IANA type by name. Only what the number states for certain is mapped:
//
//   - Ethernet → KindEthernet: a LAN medium; it says nothing about WAN (most
//     WAN hand-offs today are Ethernet too).
//   - softwareLoopback → KindLoopback; tunnel / mplsTunnel → KindTunnel: never
//     the WAN port itself (a tunnel borrows the address of the port it rides).
//   - Media that only ever carry a WAN or access circuit → KindWANMedia: serial
//     (propPointToPointSerial, HDLC, PPP), Frame Relay, ATM, T1/E1/T3, SONET,
//     ISDN, the DSL family, DOCSIS cable and cellular (wwanPP/wwanPP2). A PPPoE
//     dialer is ppp(23), a Juniper `se-`/`t1-`/`pp0` port is serial/ds1/ppp, a
//     cellular modem is wwanPP: on a router no controller describes, this is
//     the one fact the device itself states about which port faces a carrier.
//
// Everything else (other, propVirtual, l2vlan, l3ipvlan, LAG, bridge, unknown
// numbers) says nothing: "" — never a guess.

// KindWANMedia is an interface whose medium only ever carries a WAN or access
// circuit (see IfTypeKind).
const KindWANMedia = "wan_media"

// ianaIfType is one IANA ifType this package states something about.
type ianaIfType struct {
	name, kind string
}

// ianaIfTypes are the IANAifType-MIB numbers with a kind. Names are the MIB's.
var ianaIfTypes = map[int]ianaIfType{
	6:   {"ethernetCsmacd", KindEthernet},
	62:  {"fastEther", KindEthernet},
	69:  {"fastEtherFX", KindEthernet},
	117: {"gigabitEthernet", KindEthernet},
	24:  {"softwareLoopback", KindLoopback},
	131: {"tunnel", KindTunnel},
	150: {"mplsTunnel", KindTunnel},
	18:  {"ds1", KindWANMedia},
	19:  {"e1", KindWANMedia},
	20:  {"basicISDN", KindWANMedia},
	21:  {"primaryISDN", KindWANMedia},
	22:  {"propPointToPointSerial", KindWANMedia},
	23:  {"ppp", KindWANMedia},
	30:  {"ds3", KindWANMedia},
	32:  {"frameRelay", KindWANMedia},
	37:  {"atm", KindWANMedia},
	39:  {"sonet", KindWANMedia},
	63:  {"isdn", KindWANMedia},
	94:  {"adsl", KindWANMedia},
	95:  {"radsl", KindWANMedia},
	96:  {"sdsl", KindWANMedia},
	97:  {"vdsl", KindWANMedia},
	118: {"hdlc", KindWANMedia},
	127: {"docsCableMaclayer", KindWANMedia},
	169: {"shdsl", KindWANMedia},
	230: {"adsl2", KindWANMedia},
	238: {"adsl2plus", KindWANMedia},
	243: {"wwanPP", KindWANMedia},
	244: {"wwanPP2", KindWANMedia},
	251: {"vdsl2", KindWANMedia},
}

// ianaNameKind maps a controller's IANA ifType NAME to the WAN-media and tunnel
// kinds IfTypeKind states, keyed lower-case without hyphens: the MIB spells
// `propPointToPointSerial`, the YANG identity `prop-point-to-point-serial`, and
// both fold to one key. Ethernet / loopback / tunnel / other keep CleanKind's
// original spellings.
var ianaNameKind = func() map[string]string {
	m := map[string]string{}
	for _, t := range ianaIfTypes {
		if t.kind == KindWANMedia || t.kind == KindTunnel {
			m[strings.ToLower(t.name)] = t.kind
		}
	}
	return m
}()

// ianaKindByName reads a controller's IANA ifType name (lower-case, prefix
// already removed); "" when it names none of the WAN-media or tunnel types.
func ianaKindByName(k string) string {
	return ianaNameKind[strings.ReplaceAll(k, "-", "")]
}

// IfTypeKind is the closed-set kind an IANA ifType number states; "" when it
// states nothing this package knows.
func IfTypeKind(n int) string {
	return ianaIfTypes[n].kind
}

// IfTypeName is the IANAifType-MIB name of a number this package knows; "".
func IfTypeName(n int) string {
	return ianaIfTypes[n].name
}

// maxIfTypeDigits bounds an ifType (IANAifType is a small positive integer).
const maxIfTypeDigits = 5

// ParseIfType reads an ifType the SNMP half carries as decimal text; 0 (not a
// valid IANA number) for anything else. Agent output is untrusted (§3).
func ParseIfType(s string) int {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxIfTypeDigits {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
