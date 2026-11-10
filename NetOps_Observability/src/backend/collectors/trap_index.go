// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// trap_index.go — what a varbind's instance suffix says about the row it names.
//
// bgpPeerState.192.168.200.34 is the bgpPeerTable row of peer 192.168.200.34, and
// cbgpPeer2State.1.4.10.0.0.1 is the cbgpPeer2Table row of (ipv4, 10.0.0.1). The
// receiver used to keep only the object name, so the peer was lost (tracker 387).
// The arcs are decoded here from the column's INDEX clause, which gen_index.py
// writes into the OID index from the MIB itself (index_syntax): no table is named
// in this file, and a new vendor's table decodes as soon as its MIB is indexed.
//
// Never guess. A suffix that does not decode exactly, with every arc consumed and
// every value legal for its syntax, is an error, and the caller records the row as
// unparsed beside the raw OID, which is never rewritten.

// Index syntaxes, as gen_index.py states them (mibs/README.md).
const (
	idxIPv4        = "ipv4"         // IpAddress: 4 arcs
	idxInt         = "int"          // any INTEGER-based syntax: 1 arc
	idxInetType    = "inet_type"    // InetAddressType (RFC 4001): 1 arc
	idxInetAddress = "inet_address" // InetAddress: length arc + octets (or IMPLIED)
	idxString      = "string"       // variable OCTET STRING: length arc + octets
	idxFixedPrefix = "fixed:"       // fixed-size OCTET STRING: N arcs, no length
)

// RFC 4001 InetAddressType values, by name, and the address length each implies.
var inetAddressTypes = map[uint32]string{0: "unknown", 1: "ipv4", 2: "ipv6", 3: "ipv4z", 4: "ipv6z", 16: "dns"}

var inetAddressLen = map[string]int{"unknown": 0, "ipv4": 4, "ipv6": 16, "ipv4z": 8, "ipv6z": 20}

// maxIndexArcs bounds the work on one suffix (the OID itself is already capped
// at maxTrapOIDChars, so this only fires on a hostile suffix).
const maxIndexArcs = 128

var errIndexMalformed = errors.New("index suffix does not decode")

// trapIndexPart is one decoded index object of a row.
type trapIndexPart struct {
	OID    string // the index object's OID (what a pack keys a meaning by)
	Name   string // the index object's name, as the MIB writes it
	Syntax string
	Text   string // the value as an operator reads it: 10.0.0.1, 2001:db8::1, ipv4, 7
	// AFI is the address family an inet_type part states, or the family an
	// address part was decoded as.
	AFI string
}

// parseIndexArcs reads a dotted suffix into sub-identifiers.
func parseIndexArcs(suffix string) ([]uint32, error) {
	if suffix == "" {
		return nil, errIndexMalformed
	}
	parts := strings.Split(suffix, ".")
	if len(parts) > maxIndexArcs {
		return nil, errIndexMalformed
	}
	out := make([]uint32, len(parts))
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return nil, errIndexMalformed
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, errIndexMalformed
		}
		out[i] = uint32(v)
	}
	return out, nil
}

// octetsOf takes n arcs as octets; any arc above 255 is not an octet.
func octetsOf(arcs []uint32, n int) ([]byte, bool) {
	if n < 0 || len(arcs) < n {
		return nil, false
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		if arcs[i] > 255 {
			return nil, false
		}
		b[i] = byte(arcs[i])
	}
	return b, true
}

// inetAddressText renders RFC 4001 InetAddress octets for a type. A zone index
// (ipv4z/ipv6z) is the trailing 4 octets, written `%<zone>` as RFC 4007 does.
func inetAddressText(afi string, b []byte) (string, bool) {
	switch afi {
	case "ipv4", "ipv6":
		a, ok := netip.AddrFromSlice(b)
		if !ok || (afi == "ipv4") != a.Is4() {
			return "", false
		}
		return a.String(), true
	case "ipv4z", "ipv6z":
		n := len(b) - 4
		a, ok := netip.AddrFromSlice(b[:n])
		if !ok {
			return "", false
		}
		return fmt.Sprintf("%s%%%d", a.String(), binary.BigEndian.Uint32(b[n:])), true
	case "dns":
		if len(b) == 0 || !isPrintable(b) || strings.ContainsAny(string(b), " \t\r\n") {
			return "", false
		}
		return string(b), true
	}
	return "", false
}

// decodeTrapIndex decodes a column instance suffix by the column's INDEX clause.
func decodeTrapIndex(n OIDNode, suffix string) ([]trapIndexPart, error) {
	if len(n.IndexSyntax) == 0 || len(n.IndexSyntax) != len(n.IndexOIDs) || len(n.Index) != len(n.IndexOIDs) {
		return nil, errIndexMalformed
	}
	arcs, err := parseIndexArcs(suffix)
	if err != nil {
		return nil, err
	}
	parts := make([]trapIndexPart, 0, len(n.IndexSyntax))
	afi := "" // the family the latest inet_type part stated
	for i, syn := range n.IndexSyntax {
		last := i == len(n.IndexSyntax)-1
		implied := last && n.IndexImplied
		p := trapIndexPart{OID: n.IndexOIDs[i], Name: n.Index[i], Syntax: syn}
		switch {
		case syn == idxInt:
			if len(arcs) < 1 {
				return nil, errIndexMalformed
			}
			p.Text, arcs = strconv.FormatUint(uint64(arcs[0]), 10), arcs[1:]
		case syn == idxIPv4:
			b, ok := octetsOf(arcs, 4)
			if !ok {
				return nil, errIndexMalformed
			}
			p.Text, p.AFI, arcs = netip.AddrFrom4([4]byte(b)).String(), "ipv4", arcs[4:]
		case syn == idxInetType:
			if len(arcs) < 1 {
				return nil, errIndexMalformed
			}
			name, ok := inetAddressTypes[arcs[0]]
			if !ok {
				return nil, errIndexMalformed
			}
			p.Text, p.AFI, afi, arcs = name, name, name, arcs[1:]
		case syn == idxInetAddress || syn == idxString:
			size := len(arcs)
			if !implied {
				if len(arcs) < 1 {
					return nil, errIndexMalformed
				}
				size, arcs = int(arcs[0]), arcs[1:]
			}
			b, ok := octetsOf(arcs, size)
			if !ok {
				return nil, errIndexMalformed
			}
			arcs = arcs[size:]
			if syn == idxString {
				p.Text = octetStr(b)
				break
			}
			fam := afi
			if fam == "" { // an InetAddress with no type before it: its length says
				switch size {
				case 4:
					fam = "ipv4"
				case 16:
					fam = "ipv6"
				default:
					return nil, errIndexMalformed
				}
			}
			if want, fixed := inetAddressLen[fam]; fixed && want != size {
				return nil, errIndexMalformed
			}
			if fam == "unknown" {
				p.AFI = fam // RFC 4001: unknown carries a zero-length address
				break
			}
			txt, ok := inetAddressText(fam, b)
			if !ok {
				return nil, errIndexMalformed
			}
			p.Text, p.AFI = txt, fam
		case strings.HasPrefix(syn, idxFixedPrefix):
			size, err := strconv.Atoi(strings.TrimPrefix(syn, idxFixedPrefix))
			if err != nil || size <= 0 {
				return nil, errIndexMalformed
			}
			b, ok := octetsOf(arcs, size)
			if !ok {
				return nil, errIndexMalformed
			}
			arcs = arcs[size:]
			if a, ok := netip.AddrFromSlice(b); ok && (size == 4 || size == 16) {
				p.Text, p.AFI = a.String(), map[bool]string{true: "ipv4", false: "ipv6"}[size == 4]
			} else {
				p.Text = octetStr(b)
			}
		default: // "unknown" or a syntax this receiver does not know: never guess
			return nil, errIndexMalformed
		}
		parts = append(parts, p)
	}
	if len(arcs) != 0 {
		return nil, errIndexMalformed // the clause did not explain every arc
	}
	return parts, nil
}

// decodeBareAddressIndex reads a suffix that is ONLY an address's octets: 4 arcs
// for IPv4, 16 for IPv6, nothing else. A pack enables it per table, for a vendor
// that drops the type and length arcs its own MIB states (IOS-XE's cbgpPeer2Table,
// recorded on the lab). The two lengths cannot collide with the MIB's own forms
// (type.len.4 octets is 6 arcs, type.len.16 is 18), so the reading is unambiguous.
func decodeBareAddressIndex(suffix string) (addr, afi string, err error) {
	arcs, err := parseIndexArcs(suffix)
	if err != nil {
		return "", "", err
	}
	if len(arcs) != 4 && len(arcs) != 16 {
		return "", "", errIndexMalformed
	}
	b, ok := octetsOf(arcs, len(arcs))
	if !ok {
		return "", "", errIndexMalformed
	}
	afi = "ipv4"
	if len(b) == 16 {
		afi = "ipv6"
	}
	txt, ok := inetAddressText(afi, b)
	if !ok {
		return "", "", errIndexMalformed
	}
	return txt, afi, nil
}
