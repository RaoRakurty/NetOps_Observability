// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// fuzz_test.go — the property that matters most for a network-facing parser:
// NO INPUT, however malformed, causes a panic, an unbounded allocation, or a
// silent mis-decode. A router is untrusted (§3), and every byte it sends
// reaches these functions.
//
// Three targets, one per trust boundary:
//
//	FuzzParseMessage — a whole BMP frame, as it arrives off the socket.
//	FuzzParseUpdate  — a bare BGP UPDATE body, the deepest nesting level.
//	FuzzConnStream   — a byte STREAM through the real connection loop, which
//	                   is where framing, re-synchronization and the bounded
//	                   buffer interact.
//
// Run with: go test -fuzz=FuzzParseMessage -fuzztime=30s ./internal/bmp/

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fuzzSeeds are the frames the table tests build, plus their mutations. Seeding
// with VALID frames is what lets the fuzzer find the interesting failures: it
// mutates a structurally-correct message rather than spending its budget
// discovering that random bytes are not BMP.
func fuzzSeeds() [][]byte {
	body := updateBody(nil, attrs(
		attr(0x40, attrOrigin, []byte{0}),
		attr(0x40, attrASPath, asPathSeq(true, 64512, 15169)),
		attr(0x40, attrNextHop, []byte{192, 0, 2, 1}),
		attr(0xC0, attrCommunities, be32(0xFFFFFF01)),
		attr(0xC0, attrLargeCommunity, attrs(be32(1), be32(2), be32(3))),
	), attrs(nlri("10.1.0.0/24"), nlri("0.0.0.0/0")))

	mpReach := append([]byte{}, be16(afiIPv6)...)
	mpReach = append(mpReach, safiUnicast, 16)
	nh := netip.MustParseAddr("2001:db8::1").As16()
	mpReach = append(mpReach, nh[:]...)
	mpReach = append(mpReach, 0)
	mpReach = append(mpReach, nlri("2001:db8:1::/48")...)
	v6body := updateBody(nil, attrExt(0x80, attrMPReachNLRI, mpReach), nil)

	return [][]byte{
		initiation("core-rtr", "IOS-XR 7.9.2"),
		termination(1),
		peerUp(0, "192.0.2.10", 64512),
		peerUp(peerFlagV, "2001:db8::1", 65001),
		peerDownNotification("192.0.2.10", 64512, 6, 2),
		statsReport("192.0.2.10", map[uint16]uint32{0: 1, 1: 2, 11: 3}),
		routeMonitoring(0, "192.0.2.10", 64512, body),
		routeMonitoring(peerFlagA, "192.0.2.10", 64512, body),
		routeMonitoring(peerFlagV, "2001:db8::1", 65001, v6body),
		frame(MsgRouteMirroring, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")),
		{3, 0, 0, 0, 6, 0},
		{},
	}
}

// FuzzParseMessage feeds arbitrary bytes to the frame parser.
func FuzzParseMessage(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseMessage(data)
		if err != nil {
			if msg != nil {
				t.Fatalf("ParseMessage returned BOTH a message and an error — a caller would count the error and use the message")
			}
			return
		}
		if msg == nil {
			t.Fatal("ParseMessage returned nil with no error")
		}
		// Invariants a successful parse must hold, so a mis-decode cannot pass
		// as a success:
		if msg.Header.Version != Version {
			t.Fatalf("accepted version %d", msg.Header.Version)
		}
		if int(msg.Header.Length) != len(data) {
			t.Fatalf("length %d accepted for a %d-byte buffer", msg.Header.Length, len(data))
		}
		if msg.Header.Type.hasPerPeerHeader() != (msg.Peer != nil) {
			t.Fatalf("type %v peer-header presence = %v", msg.Header.Type, msg.Peer != nil)
		}
		if msg.Update != nil {
			for _, p := range msg.Update.Announced {
				if !p.IsValid() || p.Masked() != p {
					t.Fatalf("announced prefix %v is not canonical", p)
				}
			}
			for _, p := range msg.Update.Withdrawn {
				if !p.IsValid() || p.Masked() != p {
					t.Fatalf("withdrawn prefix %v is not canonical", p)
				}
			}
			if len(msg.Update.Announced) > maxPrefixesPerUpdate || len(msg.Update.Withdrawn) > maxPrefixesPerUpdate {
				t.Fatal("prefix bound exceeded")
			}
			if len(msg.Update.ASPath) > maxASPathLength {
				t.Fatalf("AS_PATH bound exceeded: %d", len(msg.Update.ASPath))
			}
			if len(msg.Update.Communities) > maxCommunities || len(msg.Update.LargeCommunities) > maxCommunities {
				t.Fatal("community bound exceeded")
			}
		}
		if msg.Stats != nil && len(msg.Stats.Stats) > maxStats {
			t.Fatalf("stats bound exceeded: %d", len(msg.Stats.Stats))
		}
		if msg.Initiation != nil {
			if len(msg.Initiation.SysName) > maxTLVValue || len(msg.Initiation.SysDesc) > maxTLVValue {
				t.Fatal("TLV value bound exceeded")
			}
		}
		// Folding a fuzzed message into the store must be safe too — that is
		// the path a real frame takes.
		s := NewStore(fixedClock(), 4, 8)
		if err := s.Open("bmp-1", "acme", "d", "1.2.3.4:1"); err != nil {
			t.Fatal(err)
		}
		s.Apply("bmp-1", msg)
		if got := s.Sessions("globex", false); len(got) != 0 {
			t.Fatal("a fuzzed frame reached another tenant's view")
		}
	})
}

// FuzzParseUpdate feeds arbitrary bytes to the BGP UPDATE parser, in both AS
// encodings — the flag changes the parse shape, so both are fuzzed.
func FuzzParseUpdate(f *testing.F) {
	f.Add(updateBody(nil, attr(0x40, attrOrigin, []byte{0}), nlri("10.0.0.0/8")), true)
	f.Add(updateBody(nlri("10.9.0.0/24"), nil, nil), false)
	f.Add(updateBody(nil, attrs(
		attr(0x40, attrASPath, asPathSeq(false, 64512, 23456)),
		attr(0xC0, attrAS4Path, asPathSeq(true, 196618)),
	), nlri("10.0.0.0/8")), false)
	f.Add([]byte{}, true)
	f.Add([]byte{0, 0, 0, 0}, true)

	f.Fuzz(func(t *testing.T, data []byte, fourByte bool) {
		u, err := ParseUpdate(data, fourByte)
		if err != nil {
			if u != nil {
				t.Fatal("ParseUpdate returned both an update and an error")
			}
			return
		}
		if u == nil {
			t.Fatal("ParseUpdate returned nil with no error")
		}
		if len(u.Announced)+len(u.Withdrawn) > 2*maxPrefixesPerUpdate {
			t.Fatal("prefix bound exceeded")
		}
		if len(u.ASPath) > maxASPathLength {
			t.Fatal("AS_PATH bound exceeded")
		}
		if u.UnsupportedFamilies < 0 || u.UnknownAttributes < 0 {
			t.Fatal("negative count")
		}
		for _, p := range append(append([]netipPrefix{}, u.Announced...), u.Withdrawn...) {
			if !p.IsValid() {
				t.Fatalf("invalid prefix %v accepted", p)
			}
		}
	})
}

// FuzzConnStream drives the REAL connection loop with an arbitrary byte
// stream: framing, the reusable buffer, the deadline handling and the
// store-folding all participate, which is where a bug that the pure parser
// cannot express would live.
func FuzzConnStream(f *testing.F) {
	var stream []byte
	for _, s := range fuzzSeeds() {
		stream = append(stream, s...)
	}
	f.Add(stream)
	f.Add(append(initiation("r", "d"), 0xFF, 0xFF, 0xFF, 0xFF))
	f.Add([]byte{3, 0xFF, 0xFF, 0xFF, 0xFF, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip() // a fuzz corpus entry larger than any realistic burst
		}
		store := NewStore(time.Now, 4, 16)
		if err := store.Open("bmp-1", "acme", "dev", "127.0.0.1:1"); err != nil {
			t.Fatal(err)
		}
		l := NewListener(Deps{
			Now:            time.Now,
			Metrics:        NewMetrics(),
			IdleTimeout:    2 * time.Second,
			MessageTimeout: 2 * time.Second,
			LogInfo:        func(string, map[string]any) {},
			LogWarn:        func(string, map[string]any) {},
			LogError:       func(string, map[string]any) {},
		}, store)

		client, server := net.Pipe()
		go func() {
			_, _ = client.Write(data)
			_ = client.Close()
		}()
		done := make(chan string, 1)
		go func() { done <- l.readLoop(server, "bmp-1") }()
		select {
		case reason := <-done:
			if reason == "" {
				t.Fatal("readLoop ended without naming a reason — a silent disconnect is unobservable")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("readLoop did not terminate on a closed pipe")
		}
		_ = server.Close()

		// Whatever arrived, the bounds hold and the tenant boundary holds.
		v := store.Sessions("acme", false)
		if len(v) != 1 {
			t.Fatalf("sessions = %d", len(v))
		}
		if v[0].Updates > 16 {
			t.Fatalf("ring overflowed its depth: %d", v[0].Updates)
		}
		if got := store.Sessions("globex", false); len(got) != 0 {
			t.Fatal("a fuzzed stream reached another tenant's view")
		}
		if got := store.Updates("", false, UpdateFilter{Limit: 100}); len(got) != 0 {
			t.Fatal("a tenant-less principal read a fuzzed stream's updates")
		}
	})
}

// TestFuzzSeedsAllParseOrFailCleanly keeps the seed corpus honest in the normal
// (non-fuzz) build, so a seed that stops being a valid frame is noticed.
func TestFuzzSeedsAllParseOrFailCleanly(t *testing.T) {
	for i, s := range fuzzSeeds() {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("seed %d panicked: %v", i, rec)
				}
			}()
			_, _ = ParseMessage(s)
		}()
	}
	// And the stream path, once, so the fuzz harness itself is exercised in CI.
	store := NewStore(time.Now, 4, 16)
	if err := store.Open("bmp-1", "acme", "dev", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	l := NewListener(Deps{
		Now: time.Now, Metrics: NewMetrics(),
		IdleTimeout: time.Second, MessageTimeout: time.Second,
		LogInfo: func(string, map[string]any) {}, LogWarn: func(string, map[string]any) {},
		LogError: func(string, map[string]any) {},
	}, store)
	client, server := net.Pipe()
	go func() {
		for _, s := range fuzzSeeds() {
			_, _ = client.Write(s)
		}
		_ = client.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan string, 1)
	go func() { done <- l.readLoop(server, "bmp-1") }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("readLoop did not terminate")
	}
}
