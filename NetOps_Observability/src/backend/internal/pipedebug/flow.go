// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// flow.go — the `--kind flow` probe: a NetFlow v5 record the STACK's own
// goflow2 listener accepts, carrying the marker as a deterministic tuple.
//
// WHY A TUPLE AND NOT A STRING. syslog and trap both have a free-text field, so
// the marker travels inside the record verbatim and every downstream query is a
// substring match. A flow record has NO such field: goflow2's schema is the
// fifteen numeric/address columns in deployment/docker/clickhouse/init.sql, and
// NetFlow v5 has no vendor-extension space at all. Pretending otherwise — for
// example stuffing the marker into a comment field that does not exist, or
// claiming a counter delta "is" the record — is exactly the kind of fabricated
// evidence this whole tool is written against. So the marker is DERIVED into a
// flow tuple instead, and every stage reason says that is what it is.
//
// WHY IT IS SAFE TO PUT ON A REAL PIPELINE.
//
//   - The addresses come from RFC 5737 documentation space (192.0.2.0/24
//     TEST-NET-1 and 198.51.100.0/24 TEST-NET-2). Those prefixes are reserved
//     for documentation and are not routable on the public internet, so the
//     probe can never collide with, or be mistaken for, real traffic.
//   - The ASNs come from the RFC 6996 private 16-bit range (64512–65534), which
//     NetFlow v5's two-byte AS fields can actually carry.
//   - bytes and packets are 1, so a probe cannot move a top-talkers ranking.
//   - The tuple is derived from a SHA-256 of the marker, so two concurrent
//     traces never collide and a stage cannot file one trace's record as
//     another's.
//
// COLLISION BUDGET. The queried tuple carries 8 (src octet) + 8 (dst octet) +
// 15 (src port) + 15 (dst port) + 10 (src AS) + 10 (dst AS) = 66 bits of
// marker-derived entropy inside a 30-minute window, on address space that
// carries no production traffic. That is the honest number; it is written here
// rather than left implicit because "the marker is in the record" and "the
// record matches a 66-bit fingerprint" are different claims.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	// EnvFlowTarget names the stack's flow collector (host:port, UDP).
	EnvFlowTarget = "DEBUG_FLOW_TARGET"
	// DefaultFlowTarget is goflow2's NetFlow listener inside the compose
	// network (docker-compose.yml: `-listen netflow://:2055,...`).
	DefaultFlowTarget = "goflow2:2055"

	// flowSrcPrefix / flowDstPrefix are RFC 5737 documentation prefixes.
	flowSrcPrefix = "192.0.2."
	flowDstPrefix = "198.51.100."

	// flowASBase / flowASSpan bound the probe into RFC 6996's private 16-bit
	// ASN range (64512–65534), which is what NetFlow v5's 2-byte AS fields can
	// represent at all.
	flowASBase = 64512
	flowASSpan = 1023

	// flowPortBase is the start of the IANA dynamic/ephemeral port range, so a
	// probe's ports can never be read as a service.
	flowPortBase = 49152
	flowPortSpan = 16383
)

// FlowFingerprint is the marker rendered as a flow tuple. Every field is
// derived from the marker alone, so the SAME marker always yields the SAME
// tuple: the injector builds it, and every downstream stage query rebuilds it
// rather than passing it around.
type FlowFingerprint struct {
	SrcAddr string `json:"src_addr"`
	DstAddr string `json:"dst_addr"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	SrcAS   uint16 `json:"src_as"`
	DstAS   uint16 `json:"dst_as"`
	// Proto is UDP (17). A probe must not look like a TCP conversation with no
	// handshake, which is a shape some analytics treat as a scan signal.
	Proto uint8 `json:"proto"`
}

// NewFlowFingerprint derives the tuple for a marker.
func NewFlowFingerprint(marker string) FlowFingerprint {
	h := sha256.Sum256([]byte(MarkerField + "=" + marker))
	return FlowFingerprint{
		// 1..254: .0 is the network address and .255 the broadcast address, and
		// neither is a plausible flow endpoint.
		SrcAddr: flowSrcPrefix + fmt.Sprint(1+int(h[0])%254),
		DstAddr: flowDstPrefix + fmt.Sprint(1+int(h[1])%254),
		SrcPort: uint16(flowPortBase + int(binary.BigEndian.Uint16(h[2:4]))%flowPortSpan), // #nosec G115 -- bounded to 49152+16382 < 65536
		DstPort: uint16(flowPortBase + int(binary.BigEndian.Uint16(h[4:6]))%flowPortSpan), // #nosec G115 -- same bound
		SrcAS:   uint16(flowASBase + int(binary.BigEndian.Uint16(h[6:8]))%flowASSpan),     // #nosec G115 -- bounded to 64512+1022 < 65536
		DstAS:   uint16(flowASBase + int(binary.BigEndian.Uint16(h[8:10]))%flowASSpan),    // #nosec G115 -- same bound
		Proto:   17,
	}
}

// String renders the fingerprint the way the stage reasons and the log files
// quote it, so an operator can paste it straight into a flow filter.
func (f FlowFingerprint) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d proto=%d src_as=%d dst_as=%d",
		f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort, f.Proto, f.SrcAS, f.DstAS)
}

// Fields renders the fingerprint as the evidence detail a module log file
// carries.
func (f FlowFingerprint) Fields() map[string]any {
	return map[string]any{
		"src_addr": f.SrcAddr, "dst_addr": f.DstAddr,
		"src_port": f.SrcPort, "dst_port": f.DstPort,
		"src_as": f.SrcAS, "dst_as": f.DstAS, "proto": f.Proto,
	}
}

// BuildNetFlowV5 renders a one-record NetFlow v5 export packet carrying the
// marker's fingerprint.
//
// NetFlow v5 is chosen over v9/IPFIX deliberately: it is SELF-DESCRIBING. v9
// and IPFIX are template-based, so a collector drops data records until it has
// received the matching template for that (exporter, domain, template-id)
// triple — which would make a single-datagram probe silently unobservable on a
// freshly-started collector, and "silently unobservable" is the one outcome
// this tool exists to remove. v5 needs no prior state at all.
//
// Layout (RFC-less but universally implemented; goflow2 decodes it on the
// netflow:// listener): a 24-byte header followed by 48-byte records.
func BuildNetFlowV5(marker string, now time.Time, uptime time.Duration) ([]byte, error) {
	if !ValidMarker(marker) {
		return nil, fmt.Errorf("invalid marker")
	}
	f := NewFlowFingerprint(marker)
	src := net.ParseIP(f.SrcAddr).To4()
	dst := net.ParseIP(f.DstAddr).To4()
	if src == nil || dst == nil {
		// Unreachable while the prefixes above are literals, but a derivation
		// that silently produced a nil address would emit a packet of zero
		// addresses that every stage would then fail to find.
		return nil, fmt.Errorf("flow fingerprint did not render an IPv4 address pair")
	}

	pkt := make([]byte, 0, 24+48)
	hdr := make([]byte, 24)
	binary.BigEndian.PutUint16(hdr[0:2], 5)                                     // version
	binary.BigEndian.PutUint16(hdr[2:4], 1)                                     // count
	binary.BigEndian.PutUint32(hdr[4:8], uint32(uptime.Milliseconds()%(1<<32))) // #nosec G115 -- modulo-bounded below 2^32
	binary.BigEndian.PutUint32(hdr[8:12], uint32(now.UTC().Unix()))             // #nosec G115 -- wall clock, positive and below 2^32 until 2106
	binary.BigEndian.PutUint32(hdr[12:16], uint32(now.UTC().Nanosecond()))      // #nosec G115 -- Nanosecond() < 1e9
	binary.BigEndian.PutUint32(hdr[16:20], 0)                                   // flow_sequence
	hdr[20] = 0                                                                 // engine_type
	hdr[21] = 0                                                                 // engine_id
	binary.BigEndian.PutUint16(hdr[22:24], 0)                                   // sampling_interval: 0 = unsampled
	pkt = append(pkt, hdr...)

	rec := make([]byte, 48)
	copy(rec[0:4], src)
	copy(rec[4:8], dst)
	// nexthop 8:12 stays zero — a probe claims no forwarding decision.
	binary.BigEndian.PutUint16(rec[12:14], 0)                                     // input ifIndex
	binary.BigEndian.PutUint16(rec[14:16], 0)                                     // output ifIndex
	binary.BigEndian.PutUint32(rec[16:20], 1)                                     // dPkts   — one packet
	binary.BigEndian.PutUint32(rec[20:24], 1)                                     // dOctets — one byte; cannot move a ranking
	binary.BigEndian.PutUint32(rec[24:28], uint32(uptime.Milliseconds()%(1<<32))) // #nosec G115 -- modulo-bounded
	binary.BigEndian.PutUint32(rec[28:32], uint32(uptime.Milliseconds()%(1<<32))) // #nosec G115 -- modulo-bounded
	binary.BigEndian.PutUint16(rec[32:34], f.SrcPort)
	binary.BigEndian.PutUint16(rec[34:36], f.DstPort)
	rec[36] = 0       // pad1
	rec[37] = 0       // tcp_flags — none; this is UDP
	rec[38] = f.Proto // prot
	rec[39] = 0       // tos
	binary.BigEndian.PutUint16(rec[40:42], f.SrcAS)
	binary.BigEndian.PutUint16(rec[42:44], f.DstAS)
	rec[44] = 32                              // src_mask — a /32 host route: the probe is one endpoint, not a prefix
	rec[45] = 32                              // dst_mask
	binary.BigEndian.PutUint16(rec[46:48], 0) // pad2
	pkt = append(pkt, rec...)
	return pkt, nil
}

// FlowMarkerCH is the ClickHouse predicate that finds a flow probe. Every value
// interpolated is derived from a validated marker (ValidMarker) through
// NewFlowFingerprint, so it is a literal tuple of an address string from a
// fixed prefix and five integers — there is no caller-supplied text in it.
func FlowMarkerCH(marker string) string {
	f := NewFlowFingerprint(marker)
	return fmt.Sprintf(
		"src_addr = '%s' AND dst_addr = '%s' AND src_port = %d AND dst_port = %d AND src_as = %d AND dst_as = %d",
		f.SrcAddr, f.DstAddr, f.SrcPort, f.DstPort, f.SrcAS, f.DstAS)
}
