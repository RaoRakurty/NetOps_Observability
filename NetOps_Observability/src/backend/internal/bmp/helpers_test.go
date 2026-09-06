// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// helpers_test.go — the MOCK TELEMETRY STREAM (§11): hand-built RFC 7854
// frames, assembled the way a router assembles them.
//
// Every builder here writes bytes ONLY. Nothing in this file reuses the
// parser's own constants for field WIDTHS, so a parser that silently changed
// an offset would be caught rather than agreed with.

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

// frame wraps a payload in the 6-byte BMP common header.
func frame(typ MsgType, payload []byte) []byte {
	out := make([]byte, 0, 6+len(payload))
	out = append(out, 3) // version
	out = append(out, be32(uint32(6+len(payload)))...)
	out = append(out, byte(typ))
	return append(out, payload...)
}

// peerHeader builds the 42-byte per-peer header.
func peerHeader(flags byte, addr string, as uint32, bgpID string) []byte {
	out := make([]byte, 0, 42)
	out = append(out, 0)     // peer type: global instance
	out = append(out, flags) // V/L/A/O
	out = append(out, make([]byte, 8)...)
	a := netip.MustParseAddr(addr)
	if a.Is4() {
		out = append(out, make([]byte, 12)...)
		v4 := a.As4()
		out = append(out, v4[:]...)
	} else {
		v6 := a.As16()
		out = append(out, v6[:]...)
	}
	out = append(out, be32(as)...)
	id := netip.MustParseAddr(bgpID).As4()
	out = append(out, id[:]...)
	out = append(out, be32(1700000000)...) // timestamp sec
	out = append(out, be32(0)...)          // timestamp usec
	return out
}

// tlv builds one information TLV.
func tlv(typ uint16, val string) []byte {
	out := append([]byte{}, be16(typ)...)
	out = append(out, be16(uint16(len(val)))...)
	return append(out, []byte(val)...)
}

// bgpMessage wraps a body in the 19-byte BGP header.
func bgpMessage(typ byte, body []byte) []byte {
	out := make([]byte, 0, 19+len(body))
	for i := 0; i < 16; i++ {
		out = append(out, 0xFF)
	}
	out = append(out, be16(uint16(19+len(body)))...)
	out = append(out, typ)
	return append(out, body...)
}

// attr builds one path attribute (non-extended length).
func attr(flags, code byte, val []byte) []byte {
	out := []byte{flags, code, byte(len(val))}
	return append(out, val...)
}

// attrExt builds one path attribute with the extended-length flag.
func attrExt(flags, code byte, val []byte) []byte {
	out := []byte{flags | attrFlagExtendedLength, code}
	out = append(out, be16(uint16(len(val)))...)
	return append(out, val...)
}

// nlri encodes one prefix in BGP NLRI form (length in bits, then the
// significant octets only).
func nlri(cidr string) []byte {
	p := netip.MustParsePrefix(cidr)
	bits := p.Bits()
	n := (bits + 7) / 8
	var raw []byte
	if p.Addr().Is4() {
		a := p.Addr().As4()
		raw = a[:n]
	} else {
		a := p.Addr().As16()
		raw = a[:n]
	}
	return append([]byte{byte(bits)}, raw...)
}

// updateBody assembles a BGP UPDATE body (everything after the BGP header).
func updateBody(withdrawn, attrs, announced []byte) []byte {
	out := append([]byte{}, be16(uint16(len(withdrawn)))...)
	out = append(out, withdrawn...)
	out = append(out, be16(uint16(len(attrs)))...)
	out = append(out, attrs...)
	return append(out, announced...)
}

// routeMonitoring builds a complete Route Monitoring frame.
func routeMonitoring(peerFlags byte, peerAddr string, as uint32, body []byte) []byte {
	payload := append([]byte{}, peerHeader(peerFlags, peerAddr, as, "10.0.0.1")...)
	payload = append(payload, bgpMessage(2, body)...)
	return frame(MsgRouteMonitoring, payload)
}

// initiation builds an Initiation frame naming the router.
func initiation(sysName, sysDescr string) []byte {
	payload := append([]byte{}, tlv(tlvSysDesc, sysDescr)...)
	payload = append(payload, tlv(tlvSysName, sysName)...)
	return frame(MsgInitiation, payload)
}

// peerUp builds a Peer Up frame with two (empty) OPEN messages.
func peerUp(peerFlags byte, peerAddr string, as uint32) []byte {
	payload := append([]byte{}, peerHeader(peerFlags, peerAddr, as, "10.0.0.1")...)
	local := netip.MustParseAddr("10.255.0.1").As4()
	payload = append(payload, make([]byte, 12)...)
	payload = append(payload, local[:]...)
	payload = append(payload, be16(179)...)   // local port
	payload = append(payload, be16(45000)...) // remote port
	payload = append(payload, bgpMessage(1, []byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0})...)
	payload = append(payload, bgpMessage(1, []byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0})...)
	return frame(MsgPeerUp, payload)
}

// peerDownNotification builds a Peer Down carrying a BGP NOTIFICATION.
func peerDownNotification(peerAddr string, as uint32, code, subcode byte) []byte {
	payload := append([]byte{}, peerHeader(0, peerAddr, as, "10.0.0.1")...)
	payload = append(payload, 1) // reason: local system closed, NOTIFICATION follows
	payload = append(payload, bgpMessage(3, []byte{code, subcode})...)
	return frame(MsgPeerDown, payload)
}

// statsReport builds a Statistics Report with the given (type, 4-byte value)
// counters.
func statsReport(peerAddr string, entries map[uint16]uint32) []byte {
	payload := append([]byte{}, peerHeader(0, peerAddr, 65000, "10.0.0.1")...)
	payload = append(payload, be32(uint32(len(entries)))...)
	// Deterministic order so the frame is byte-stable across runs.
	for t := uint16(0); t < 32; t++ {
		v, ok := entries[t]
		if !ok {
			continue
		}
		payload = append(payload, be16(t)...)
		payload = append(payload, be16(4)...)
		payload = append(payload, be32(v)...)
	}
	return frame(MsgStatisticsReport, payload)
}

// termination builds a Termination frame with a reason code.
func termination(reason uint16) []byte {
	payload := append([]byte{}, be16(tlvReason)...)
	payload = append(payload, be16(2)...)
	payload = append(payload, be16(reason)...)
	return frame(MsgTermination, payload)
}

// fixedClock is a deterministic clock for the store and the listener.
func fixedClock() func() time.Time {
	base := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	var n int64
	return func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Millisecond)
	}
}

// mustParse parses a frame and fails the test if it does not.
func mustParse(t *testing.T, b []byte) *Message {
	t.Helper()
	m, err := ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	return m
}
