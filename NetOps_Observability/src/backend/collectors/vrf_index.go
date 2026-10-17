// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
)

// vrf_index.go — the PURE half of the routing-instance collector: SNMP row
// index decoding, route-distinguisher rendering and name validation. No IO, so
// every vendor's index shape is pinned by a unit test with hostile inputs.

// maxVRFNameLen bounds an instance name taken from an index or a value. The
// longest MIB definition is JUNIPER-VPN-MIB jnxVpnName (1..128).
const maxVRFNameLen = 128

// vrfName validates an instance name: printable ASCII only, bounded. A name
// that is not is dropped (and counted by the caller) — never hex-dumped into a
// label.
func vrfName(s string) (string, bool) {
	if s == "" || len(s) > maxVRFNameLen {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return "", false
		}
	}
	return s, true
}

// arcsString turns index arcs into a string, refusing any arc that is not a
// printable byte.
func arcsString(arcs []int) (string, bool) {
	b := make([]byte, len(arcs))
	for i, a := range arcs {
		if a < 0x20 || a > 0x7e {
			return "", false
		}
		b[i] = byte(a)
	}
	return vrfName(string(b))
}

// splitLenString decodes a length-prefixed (non-IMPLIED) OCTET STRING index
// component followed by `trailing` fixed arcs: len, c1..cN, t1..tK. When the
// length octet disagrees with the arc count (an agent that encodes the name
// IMPLIED), every arc before the trailing ones is taken as the name instead.
func splitLenString(arcs []int, trailing int) (name string, rest []int, ok bool) {
	if len(arcs) < 1+trailing {
		return "", nil, false
	}
	if n := arcs[0]; n >= 1 && 1+n+trailing == len(arcs) {
		if s, ok := arcsString(arcs[1 : 1+n]); ok {
			return s, arcs[1+n:], true
		}
		return "", nil, false
	}
	// Fallback: IMPLIED encoding (no length octet).
	if len(arcs) <= trailing {
		return "", nil, false
	}
	s, ok := arcsString(arcs[:len(arcs)-trailing])
	if !ok {
		return "", nil, false
	}
	return s, arcs[len(arcs)-trailing:], true
}

// renderRD renders a route distinguisher. An 8-octet value is the RFC 4364
// binary form (type 0: 2-byte ASN:4-byte number; type 1: IPv4:2-byte number;
// type 2: 4-byte ASN:2-byte number). Printable ASCII ("65000:100") passes
// through. Anything else is "" — never a hex dump in a label.
func renderRD(raw []byte) string {
	if len(raw) == 8 {
		typ := binary.BigEndian.Uint16(raw[0:2])
		switch typ {
		case 0:
			return strconv.FormatUint(uint64(binary.BigEndian.Uint16(raw[2:4])), 10) + ":" +
				strconv.FormatUint(uint64(binary.BigEndian.Uint32(raw[4:8])), 10)
		case 1:
			a := netip.AddrFrom4([4]byte{raw[2], raw[3], raw[4], raw[5]})
			return a.String() + ":" + strconv.FormatUint(uint64(binary.BigEndian.Uint16(raw[6:8])), 10)
		case 2:
			return strconv.FormatUint(uint64(binary.BigEndian.Uint32(raw[2:6])), 10) + ":" +
				strconv.FormatUint(uint64(binary.BigEndian.Uint16(raw[6:8])), 10)
		}
	}
	s := strings.TrimSpace(string(raw))
	if s == "" || len(s) > 64 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}
