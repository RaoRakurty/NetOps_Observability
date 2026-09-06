// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"net"
	"testing"
	"time"
)

// NTP timestamp conversion round-trips to within sub-millisecond.
func TestNTPRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 123_000_000) // .123s
	got := ntpSeconds(ntpFromTime(now))
	want := float64(now.Unix()+ntpEpochOffset) + 0.123
	if diff := got - want; diff > 0.001 || diff < -0.001 {
		t.Fatalf("ntp round-trip = %.6f, want %.6f (diff %.6f)", got, want, diff)
	}
}

// Sender + reflected packet codecs round-trip (RFC 8762 §4.2.1 / §4.3).
func TestStampPacketRoundTrip(t *testing.T) {
	t1 := ntpNow()
	sp := encodeSenderPacket(7, t1, 44)
	if len(sp) != 44 {
		t.Fatalf("sender packet len = %d, want 44", len(sp))
	}
	seq, gotT1, ok := parseSenderPacket(sp)
	if !ok || seq != 7 || gotT1 != t1 {
		t.Fatalf("parseSenderPacket = (%d,%d,%v), want (7,%d,true)", seq, gotT1, ok, t1)
	}

	t2, t3 := ntpNow(), ntpNow()
	rp := encodeReflectedPacket(3, t3, t2, 7, t1, 255)
	if len(rp) != stampReflectedLen {
		t.Fatalf("reflected len = %d, want %d", len(rp), stampReflectedLen)
	}
	r, ok := parseReflectedPacket(rp)
	if !ok || r.senderSeq != 7 || r.t1 != t1 || r.t2 != t2 || r.t3 != t3 {
		t.Fatalf("parseReflectedPacket = %+v ok=%v, want senderSeq=7 t1=%d t2=%d t3=%d", r, ok, t1, t2, t3)
	}
}

// reflectPacket() echoes the sender seq + T1 and stamps T2/T3.
func TestReflect(t *testing.T) {
	t1 := ntpNow()
	in := encodeSenderPacket(42, t1, 44)
	t2 := ntpNow()
	out, ok := reflectPacket(in, 1, t2)
	if !ok {
		t.Fatal("reflect failed")
	}
	r, ok := parseReflectedPacket(out)
	if !ok || r.senderSeq != 42 || r.t1 != t1 || r.t2 != t2 {
		t.Fatalf("reflect round-trip = %+v ok=%v", r, ok)
	}
}

// meanAbsDiff implements the RFC 3393 PDV estimator.
func TestMeanAbsDiff(t *testing.T) {
	if v := meanAbsDiff([]stampSample{{rtt: 10}}); v != 0 {
		t.Fatalf("single sample PDV = %v, want 0", v)
	}
	// |12-10| + |11-12| = 2 + 1 = 3, over 2 gaps = 1.5
	if v := meanAbsDiff([]stampSample{{rtt: 10}, {rtt: 12}, {rtt: 11}}); v != 1.5 {
		t.Fatalf("PDV = %v, want 1.5", v)
	}
}

// End-to-end: a local reflector + probeSTAMP validate the full RFC exchange and
// the RTT/loss math over real UDP (loopback).
func TestProbeSTAMPLoopback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	// Minimal reflector goroutine using the production reflectPacket().
	go func() {
		buf := make([]byte, 1500)
		var seq uint32
		for {
			n, src, err := pc.ReadFrom(buf)
			t2 := ntpNow()
			if err != nil {
				return
			}
			if out, ok := reflectPacket(buf[:n], seq, t2); ok {
				seq++
				_, _ = pc.WriteTo(out, src)
			}
		}
	}()

	res, err := probeSTAMP(context.Background(), pc.LocalAddr().String(), 5)
	if err != nil {
		t.Fatalf("probeSTAMP: %v", err)
	}
	if res.sent != 5 {
		t.Fatalf("sent = %d, want 5", res.sent)
	}
	if res.recv == 0 {
		t.Fatal("no reflections received over loopback")
	}
	if res.lossPct < 0 || res.lossPct > 100 {
		t.Fatalf("loss = %.2f out of range", res.lossPct)
	}
	if res.rttMs < 0 {
		t.Fatalf("rtt = %.3f, want >= 0", res.rttMs)
	}
}
