package pipedebug

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// The fingerprint is the flow probe's whole identity, so it must be a pure
// function of the marker: the injector builds it and every stage query rebuilds
// it independently, never passing it around.
func TestFlowFingerprintIsDeterministic(t *testing.T) {
	m := NewMarker(time.Unix(1757000000, 0))
	a, b := NewFlowFingerprint(m), NewFlowFingerprint(m)
	if a != b {
		t.Fatalf("the same marker produced two fingerprints:\n%+v\n%+v", a, b)
	}
	other := NewFlowFingerprint(NewMarker(time.Unix(1757000001, 0)))
	if a == other {
		t.Fatal("two different markers produced the same fingerprint")
	}
}

// SAFETY: the probe must live in RFC 5737 documentation space, in the RFC 6996
// private ASN range, and on ephemeral ports — so it can never collide with, or
// be mistaken for, real traffic.
func TestFlowFingerprintStaysInReservedSpace(t *testing.T) {
	for i := 0; i < 500; i++ {
		f := NewFlowFingerprint(NewMarker(time.Unix(int64(1757000000+i), 0)))
		if !strings.HasPrefix(f.SrcAddr, "192.0.2.") {
			t.Fatalf("src %s left TEST-NET-1", f.SrcAddr)
		}
		if !strings.HasPrefix(f.DstAddr, "198.51.100.") {
			t.Fatalf("dst %s left TEST-NET-2", f.DstAddr)
		}
		for _, ip := range []string{f.SrcAddr, f.DstAddr} {
			parsed := net.ParseIP(ip).To4()
			if parsed == nil {
				t.Fatalf("%s is not an IPv4 address", ip)
			}
			if last := parsed[3]; last == 0 || last == 255 {
				t.Fatalf("%s uses the network or broadcast address", ip)
			}
		}
		if f.SrcPort < 49152 || f.DstPort < 49152 {
			t.Fatalf("ports %d/%d are outside the ephemeral range", f.SrcPort, f.DstPort)
		}
		if f.SrcAS < 64512 || f.SrcAS > 65534 || f.DstAS < 64512 || f.DstAS > 65534 {
			t.Fatalf("AS %d/%d are outside the RFC 6996 private range", f.SrcAS, f.DstAS)
		}
		if f.Proto != 17 {
			t.Fatalf("proto %d is not UDP", f.Proto)
		}
	}
}

// A probe must not be able to move a ranking, so its counters are 1/1 — and the
// packet has to decode as a well-formed NetFlow v5 export or goflow2 drops it
// silently, which would make the whole kind unobservable.
func TestBuildNetFlowV5Decodes(t *testing.T) {
	m := NewMarker(time.Unix(1757000000, 0))
	f := NewFlowFingerprint(m)
	pkt, err := BuildNetFlowV5(m, time.Unix(1757000000, 0).UTC(), 90*time.Second)
	if err != nil {
		t.Fatalf("BuildNetFlowV5: %v", err)
	}
	if len(pkt) != 24+48 {
		t.Fatalf("packet is %d bytes, want %d (24-byte header + one 48-byte record)", len(pkt), 24+48)
	}
	if v := binary.BigEndian.Uint16(pkt[0:2]); v != 5 {
		t.Fatalf("version %d, want 5 (v9/IPFIX would need a template packet first)", v)
	}
	if c := binary.BigEndian.Uint16(pkt[2:4]); c != 1 {
		t.Fatalf("count %d, want 1", c)
	}
	rec := pkt[24:]
	if got := net.IP(rec[0:4]).String(); got != f.SrcAddr {
		t.Fatalf("srcaddr %s, want %s", got, f.SrcAddr)
	}
	if got := net.IP(rec[4:8]).String(); got != f.DstAddr {
		t.Fatalf("dstaddr %s, want %s", got, f.DstAddr)
	}
	if p := binary.BigEndian.Uint32(rec[16:20]); p != 1 {
		t.Fatalf("dPkts %d, want 1 — a probe must not move a ranking", p)
	}
	if o := binary.BigEndian.Uint32(rec[20:24]); o != 1 {
		t.Fatalf("dOctets %d, want 1", o)
	}
	if got := binary.BigEndian.Uint16(rec[32:34]); got != f.SrcPort {
		t.Fatalf("srcport %d, want %d", got, f.SrcPort)
	}
	if got := binary.BigEndian.Uint16(rec[34:36]); got != f.DstPort {
		t.Fatalf("dstport %d, want %d", got, f.DstPort)
	}
	if rec[38] != f.Proto {
		t.Fatalf("proto %d, want %d", rec[38], f.Proto)
	}
	if got := binary.BigEndian.Uint16(rec[40:42]); got != f.SrcAS {
		t.Fatalf("src_as %d, want %d", got, f.SrcAS)
	}
	if rec[37] != 0 {
		t.Fatalf("tcp_flags %d, want 0 — the probe is UDP and must not look like a half-open TCP scan", rec[37])
	}
}

func TestBuildNetFlowV5RejectsABadMarker(t *testing.T) {
	if _, err := BuildNetFlowV5("not-a-marker", time.Now(), time.Second); err == nil {
		t.Fatal("an invalid marker produced a packet")
	}
}

// The ClickHouse predicate must interpolate ONLY derived values — no caller
// text — and must name every field of the fingerprint.
func TestFlowMarkerCHIsTheFullTuple(t *testing.T) {
	m := NewMarker(time.Unix(1757000000, 0))
	f := NewFlowFingerprint(m)
	sql := FlowMarkerCH(m)
	for _, want := range []string{
		"src_addr = '" + f.SrcAddr + "'",
		"dst_addr = '" + f.DstAddr + "'",
		"src_port =", "dst_port =", "src_as =", "dst_as =",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("FlowMarkerCH is missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, m) {
		t.Fatal("the marker text itself leaked into the SQL — a flow record cannot carry it, and matching on it would never hit")
	}
}

func TestFlowKindWiring(t *testing.T) {
	if !Injectable(KindFlow) {
		t.Fatal("flow must be injectable")
	}
	if PassiveOnly(KindFlow) {
		t.Fatal("flow is not passive-only")
	}
	if got := TopicFor(KindFlow); got != "netops.flows.raw" {
		t.Fatalf("TopicFor(flow) = %q, want the RAW topic goflow2 produces", got)
	}
	if got := RawCHTable(KindFlow); got != "netops.flows" {
		t.Fatalf("RawCHTable(flow) = %q", got)
	}
	if got := SignalFor(KindFlow); got != "flows" {
		t.Fatalf("SignalFor(flow) = %q", got)
	}
}

// gNMI must be impossible to inject, at the level of the type system's closed
// sets rather than by convention.
func TestGNMIIsPassiveOnly(t *testing.T) {
	if !PassiveOnly(KindGNMI) {
		t.Fatal("gnmi must be passive-only — the debugger never writes to a device")
	}
	if Injectable(KindGNMI) {
		t.Fatal("gnmi must not be injectable")
	}
	if got := TopicFor(KindGNMI); got != "" {
		t.Fatalf("TopicFor(gnmi) = %q, want \"\" (gnmic writes straight to VictoriaMetrics by default)", got)
	}
	if got := SignalFor(KindGNMI); got != "" {
		t.Fatalf("SignalFor(gnmi) = %q, want \"\" (metrics never reach the search tier)", got)
	}
}

func TestParseKindAcceptsEveryShippedKind(t *testing.T) {
	for _, k := range []string{"syslog", "trap", "flow", "gnmi", "GNMI", " flow "} {
		if _, err := ParseKind(k); err != nil {
			t.Errorf("ParseKind(%q): %v", k, err)
		}
	}
	if _, err := ParseKind("netconf"); err == nil {
		t.Fatal("an unknown kind was accepted")
	}
}
