package collectors

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// quotedEchoIDSeq parses the original echo id/seq from an ICMP error body
// (quoted IP header + first 8 bytes of the original ICMP).
func TestQuotedEchoIDSeq(t *testing.T) {
	iphdr := make([]byte, 20)
	iphdr[0] = 0x45                                     // IPv4, IHL=5 (20 bytes)
	inner := []byte{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x05} // echo: id=0x1234, seq=5
	data := append(iphdr, inner...)

	id, seq, ok := quotedEchoIDSeq(data)
	if !ok || id != 0x1234 || seq != 5 {
		t.Fatalf("quotedEchoIDSeq = (%#x,%d,%v), want (0x1234,5,true)", id, seq, ok)
	}
	if _, _, ok := quotedEchoIDSeq([]byte{0x45}); ok {
		t.Fatal("short data should not parse")
	}
}

func TestPeerIP(t *testing.T) {
	if got := peerIP(&net.IPAddr{IP: net.ParseIP("10.0.0.1")}); got != "10.0.0.1" {
		t.Fatalf("IPAddr peerIP = %q", got)
	}
	if got := peerIP(&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 0}); got != "10.0.0.2" {
		t.Fatalf("UDPAddr peerIP = %q", got)
	}
}

func TestPathSignatureChange(t *testing.T) {
	a := []Hop{{IP: "1.1.1.1"}, {IP: "2.2.2.2"}, {IP: "9.9.9.9"}}
	b := []Hop{{IP: "1.1.1.1"}, {IP: "3.3.3.3"}, {IP: "9.9.9.9"}}
	if pathSignature(a) == pathSignature(b) {
		t.Fatal("different paths must have different signatures")
	}
	s1, s2 := pathSignature(a), pathSignature(a)
	if s1 != s2 {
		t.Fatal("same path must have stable signature")
	}
}

// pathRegistry stores and returns latest traces, newest first.
func TestPathRegistry(t *testing.T) {
	r := &pathRegistry{m: make(map[string]PathResult)}
	r.set(PathResult{Dst: "a", Method: "icmp", TS: time.Unix(100, 0)})
	r.set(PathResult{Dst: "b", Method: "icmp", TS: time.Unix(200, 0)})
	all := r.All()
	if len(all) != 2 || all[0].Dst != "b" {
		t.Fatalf("All() ordering wrong: %+v", all)
	}
	if _, ok := r.get("a", "icmp"); !ok {
		t.Fatal("get(a,icmp) missing")
	}
	// empty method normalizes to icmp (legacy default).
	if _, ok := r.get("a", ""); !ok {
		t.Fatal("get(a,\"\") should normalize to icmp")
	}

	// icmp and tcp traces to the SAME dst must coexist (not overwrite).
	r.set(PathResult{Dst: "a", Method: "tcp", TS: time.Unix(300, 0)})
	if _, ok := r.get("a", "tcp"); !ok {
		t.Fatal("get(a,tcp) missing — methods overwrote each other")
	}
	if _, ok := r.get("a", "icmp"); !ok {
		t.Fatal("get(a,icmp) lost after adding tcp")
	}
	if len(r.All()) != 3 {
		t.Fatalf("All() should hold 3 (a/icmp, a/tcp, b/icmp): %+v", r.All())
	}
}

func TestParseMethods(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{"icmp"}},
		{"icmp", []string{"icmp"}},
		{"tcp", []string{"tcp"}},
		{"both", []string{"icmp", "tcp"}},
		{"icmp,tcp", []string{"icmp", "tcp"}},
		{"tcp,icmp", []string{"tcp", "icmp"}},
		{"tcp,tcp", []string{"tcp"}},              // deduped
		{"bogus", []string{"icmp"}},               // unknown → default
		{" ICMP , TCP ", []string{"icmp", "tcp"}}, // trimmed + lowercased
	}
	for _, c := range cases {
		got := parseMethods(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("parseMethods(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("parseMethods(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

// buildSYN produces a 20-byte SYN with a checksum that validates to zero, and
// the right ports/seq/flags.
func TestBuildSYNAndChecksum(t *testing.T) {
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	syn := buildSYN(src, dst, 33434, 443, 0x11223344)
	if len(syn) != 20 {
		t.Fatalf("SYN len = %d, want 20", len(syn))
	}
	if syn[13] != 0x02 {
		t.Fatalf("flags = %#x, want SYN 0x02", syn[13])
	}
	// A correct checksum makes the checksum-over-segment validate to 0.
	if c := tcpChecksum(src, dst, syn); c != 0 {
		t.Fatalf("checksum validation = %#x, want 0", c)
	}
}

// quotedTCPSrcSeq parses the quoted TCP src-port + seq from an ICMP error body.
func TestQuotedTCPSrcSeq(t *testing.T) {
	iphdr := make([]byte, 20)
	iphdr[0] = 0x45
	tcp8 := []byte{0x82, 0x9a, 0x01, 0xbb, 0x11, 0x22, 0x33, 0x44} // sport 33434, dport 443, seq 0x11223344
	sport, seq, ok := quotedTCPSrcSeq(append(iphdr, tcp8...))
	if !ok || sport != 33434 || seq != 0x11223344 {
		t.Fatalf("quotedTCPSrcSeq = (%d,%#x,%v), want (33434,0x11223344,true)", sport, seq, ok)
	}
}

// parseTCPReply handles both IP-header-included and bare-TCP raw reads.
func TestParseTCPReply(t *testing.T) {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 443)   // sport
	binary.BigEndian.PutUint16(tcp[2:4], 33434) // dport
	binary.BigEndian.PutUint32(tcp[8:12], 0x11223345)
	tcp[13] = 0x12 // SYN-ACK
	// bare TCP
	sp, dp, ack, fl, ok := parseTCPReply(tcp)
	if !ok || sp != 443 || dp != 33434 || ack != 0x11223345 || fl != 0x12 {
		t.Fatalf("bare parseTCPReply = (%d,%d,%#x,%#x,%v)", sp, dp, ack, fl, ok)
	}
	// with IPv4 header
	iphdr := make([]byte, 20)
	iphdr[0] = 0x45
	sp, _, _, _, ok = parseTCPReply(append(iphdr, tcp...))
	if !ok || sp != 443 {
		t.Fatalf("ip+tcp parseTCPReply sp=%d ok=%v", sp, ok)
	}
}

// Live loopback trace — requires CAP_NET_RAW for the raw ICMP socket; skips
// cleanly where unavailable (CI without the capability).
func TestTraceLoopback(t *testing.T) {
	cfg := traceConfig{maxHops: 3, probes: 1, timeout: 500 * time.Millisecond, socketNet: "ip4:icmp"}
	res, err := traceOnce(context.Background(), "127.0.0.1", cfg)
	if err != nil {
		t.Skipf("raw ICMP unavailable (need CAP_NET_RAW): %v", err)
	}
	if !res.Reached {
		t.Fatalf("loopback trace did not reach 127.0.0.1: %+v", res.Hops)
	}
	if len(res.Hops) == 0 || res.Hops[len(res.Hops)-1].IP != "127.0.0.1" {
		t.Fatalf("last hop should be 127.0.0.1: %+v", res.Hops)
	}
}
