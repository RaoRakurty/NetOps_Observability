// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// wire_test.go — the RFC 7854 frame parser against hand-built frames and
// against every malformation a hostile router can produce.
//
// The property under test is not "the happy path decodes". It is: NOTHING
// PANICS, and every failure is a distinguishable error value the caller can
// count.

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestParseHeaderAcceptsAWellFormedFrame(t *testing.T) {
	h, err := ParseHeader(frame(MsgInitiation, nil))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Version != 3 || h.Type != MsgInitiation || h.Length != 6 {
		t.Fatalf("header = %+v, want version 3 / initiation / length 6", h)
	}
}

func TestParseHeaderRejectsTheImpossible(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShort},
		{"one byte", []byte{3}, ErrShort},
		{"five bytes", []byte{3, 0, 0, 0, 6}, ErrShort},
		{"version 0", []byte{0, 0, 0, 0, 6, 4}, ErrVersion},
		{"version 4", []byte{4, 0, 0, 0, 6, 4}, ErrVersion},
		{"length below the header", []byte{3, 0, 0, 0, 5, 4}, ErrLength},
		{"length zero", []byte{3, 0, 0, 0, 0, 4}, ErrLength},
		{"length above the ceiling", []byte{3, 0xFF, 0xFF, 0xFF, 0xFF, 4}, ErrLength},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseHeader(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParseHeader(%v) = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

func TestParseMessageRefusesALengthThatDisagreesWithTheBuffer(t *testing.T) {
	f := frame(MsgInitiation, []byte{1, 2, 3, 4})
	// Declare four more octets than are present. A parser that trusted the
	// header here would read into whatever followed in memory.
	f[4] += 4
	if _, err := ParseMessage(f); !errors.Is(err, ErrLength) {
		t.Fatalf("err = %v, want ErrLength", err)
	}
	// And the reverse: a buffer longer than the declared length.
	g := append(frame(MsgInitiation, []byte{1, 2, 3, 4}), 0xAA, 0xBB)
	if _, err := ParseMessage(g); !errors.Is(err, ErrLength) {
		t.Fatalf("err = %v, want ErrLength", err)
	}
}

func TestParseInitiationCarriesTheRouterIdentity(t *testing.T) {
	m := mustParse(t, initiation("core-rtr-1", "IOS-XR 7.9.2"))
	if m.Initiation == nil {
		t.Fatal("no initiation payload")
	}
	if m.Initiation.SysName != "core-rtr-1" || m.Initiation.SysDesc != "IOS-XR 7.9.2" {
		t.Fatalf("initiation = %+v", m.Initiation)
	}
	if m.Peer != nil {
		t.Fatal("initiation must NOT carry a per-peer header")
	}
}

func TestInitiationTextIsSanitizedAndBounded(t *testing.T) {
	long := strings.Repeat("A", maxTLVValue+200)
	payload := append([]byte{}, tlv(tlvSysName, "rtr\x00\x1b[31mred")...)
	payload = append(payload, tlv(tlvSysDesc, long)...)
	m := mustParse(t, frame(MsgInitiation, payload))
	if strings.ContainsAny(m.Initiation.SysName, "\x00\x1b") {
		t.Fatalf("control bytes survived sanitisation: %q", m.Initiation.SysName)
	}
	if len(m.Initiation.SysDesc) > maxTLVValue {
		t.Fatalf("sysDescr not bounded: %d bytes", len(m.Initiation.SysDesc))
	}
}

func TestInitiationWithTooManyTLVsIsRefused(t *testing.T) {
	var payload []byte
	for i := 0; i < maxTLVs+5; i++ {
		payload = append(payload, tlv(tlvString, "x")...)
	}
	if _, err := ParseMessage(frame(MsgInitiation, payload)); !errors.Is(err, ErrLength) {
		t.Fatalf("err = %v, want ErrLength", err)
	}
}

func TestParseTerminationReadsTheReasonCode(t *testing.T) {
	m := mustParse(t, termination(2))
	if m.Termination == nil || !m.Termination.HasReason || m.Termination.ReasonCode != 2 {
		t.Fatalf("termination = %+v", m.Termination)
	}
	if got := terminationReason(m.Termination); !strings.Contains(got, "out of resources") {
		t.Fatalf("reason text = %q", got)
	}
}

func TestTerminationReasonOfTheWrongWidthIsMalformed(t *testing.T) {
	payload := append([]byte{}, be16(tlvReason)...)
	payload = append(payload, be16(1)...)
	payload = append(payload, 0x02)
	if _, err := ParseMessage(frame(MsgTermination, payload)); !errors.Is(err, ErrLength) {
		t.Fatalf("err = %v, want ErrLength", err)
	}
}

func TestParsePeerHeaderDecodesBothAddressFamilies(t *testing.T) {
	v4 := mustParse(t, peerUp(0, "192.0.2.10", 64512))
	if v4.Peer == nil || v4.Peer.Address != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("v4 peer = %+v", v4.Peer)
	}
	if v4.Peer.AS != 64512 {
		t.Fatalf("peer AS = %d", v4.Peer.AS)
	}
	v6 := mustParse(t, peerUp(peerFlagV, "2001:db8::1", 65001))
	if v6.Peer == nil || v6.Peer.Address != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("v6 peer = %+v", v6.Peer)
	}
}

func TestPeerHeaderIgnoresTheV4PaddingRatherThanTrustingIt(t *testing.T) {
	// A peer that declares IPv4 but fills the leading twelve octets must NOT be
	// read as v6 — the V flag is the authority.
	payload := peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")
	for i := 2 + 8; i < 2+8+12; i++ {
		payload[i] = 0xEE
	}
	payload = append(payload, 1) // peer-down reason 1 needs a NOTIFICATION
	payload = append(payload, bgpMessage(3, []byte{6, 2})...)
	m := mustParse(t, frame(MsgPeerDown, payload))
	if m.Peer.Address != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("address = %v, want 192.0.2.10", m.Peer.Address)
	}
}

func TestPeerFlagsAreDecoded(t *testing.T) {
	m := mustParse(t, peerUp(peerFlagL|peerFlagA, "192.0.2.10", 64512))
	if !m.Peer.PostPolicy() || !m.Peer.LegacyASPath() || m.Peer.IPv6() || m.Peer.AdjRIBOut() {
		t.Fatalf("flags decoded wrong: %+v", m.Peer)
	}
	if got := ribFor(m.Peer); got != ribInPost {
		t.Fatalf("rib = %q, want %q", got, ribInPost)
	}
	out := mustParse(t, peerUp(peerFlagO, "192.0.2.10", 64512))
	if got := ribFor(out.Peer); got != ribOut {
		t.Fatalf("rib = %q, want %q", got, ribOut)
	}
}

func TestParsePeerUpSkipsBothOpenMessages(t *testing.T) {
	m := mustParse(t, peerUp(0, "192.0.2.10", 64512))
	if m.PeerUp == nil {
		t.Fatal("no peer-up payload")
	}
	if m.PeerUp.LocalPort != 179 || m.PeerUp.RemotePort != 45000 {
		t.Fatalf("ports = %d/%d", m.PeerUp.LocalPort, m.PeerUp.RemotePort)
	}
	if m.PeerUp.LocalAddress != netip.MustParseAddr("10.255.0.1") {
		t.Fatalf("local address = %v", m.PeerUp.LocalAddress)
	}
}

func TestPeerUpWithAnUnderlongOpenIsRefused(t *testing.T) {
	payload := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	payload = append(payload, make([]byte, 16)...)
	payload = append(payload, be16(179)...)
	payload = append(payload, be16(45000)...)
	// A BGP message declaring a length below its own 19-octet header.
	bad := append([]byte{}, make([]byte, 16)...)
	bad = append(bad, be16(5)...)
	bad = append(bad, 1)
	payload = append(payload, bad...)
	if _, err := ParseMessage(frame(MsgPeerUp, payload)); err == nil {
		t.Fatal("an under-long OPEN must be refused")
	}
}

func TestParsePeerDownAcrossEveryReason(t *testing.T) {
	m := mustParse(t, peerDownNotification("192.0.2.10", 64512, 6, 2))
	if m.PeerDown == nil || !m.PeerDown.HasNotification {
		t.Fatalf("peer down = %+v", m.PeerDown)
	}
	if m.PeerDown.NotificationCode != 6 || m.PeerDown.NotificationSubcode != 2 {
		t.Fatalf("notification = %d/%d", m.PeerDown.NotificationCode, m.PeerDown.NotificationSubcode)
	}
	if got := m.PeerDown.ReasonText(); got != "local_notification" {
		t.Fatalf("reason = %q", got)
	}

	fsm := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	fsm = append(fsm, 2)
	fsm = append(fsm, be16(5)...)
	m2 := mustParse(t, frame(MsgPeerDown, fsm))
	if !m2.PeerDown.HasFSMCode || m2.PeerDown.FSMCode != 5 {
		t.Fatalf("fsm = %+v", m2.PeerDown)
	}

	for _, reason := range []byte{4, 5, 6} {
		body := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
		body = append(body, reason)
		if _, err := ParseMessage(frame(MsgPeerDown, body)); err != nil {
			t.Fatalf("reason %d: %v", reason, err)
		}
	}
	// An unassigned reason is UNSUPPORTED, not silently accepted.
	body := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	body = append(body, 99)
	if _, err := ParseMessage(frame(MsgPeerDown, body)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestParseStatsReport(t *testing.T) {
	m := mustParse(t, statsReport("192.0.2.10", map[uint16]uint32{0: 7, 1: 3, 11: 42}))
	if m.Stats == nil || len(m.Stats.Stats) != 3 {
		t.Fatalf("stats = %+v", m.Stats)
	}
	byType := map[uint16]uint64{}
	for _, s := range m.Stats.Stats {
		byType[s.Type] = s.Value
	}
	if byType[0] != 7 || byType[1] != 3 || byType[11] != 42 {
		t.Fatalf("decoded = %+v", byType)
	}
}

func TestStatsWithAnAbsurdDeclaredCountIsRefusedNotAllocated(t *testing.T) {
	payload := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	payload = append(payload, be32(0xFFFFFFFF)...) // "four billion entries"
	if _, err := ParseMessage(frame(MsgStatisticsReport, payload)); !errors.Is(err, ErrLength) {
		t.Fatalf("err = %v, want ErrLength", err)
	}
}

func TestStatsWithAnUndecodableWidthIsSkippedNotGuessed(t *testing.T) {
	payload := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	payload = append(payload, be32(2)...)
	payload = append(payload, be16(0)...)
	payload = append(payload, be16(3)...) // a 3-octet counter: not a width we know
	payload = append(payload, 1, 2, 3)
	payload = append(payload, be16(1)...)
	payload = append(payload, be16(4)...)
	payload = append(payload, be32(9)...)
	m := mustParse(t, frame(MsgStatisticsReport, payload))
	if len(m.Stats.Stats) != 1 || m.Stats.Stats[0].Type != 1 || m.Stats.Stats[0].Value != 9 {
		t.Fatalf("stats = %+v — the unknown width must be skipped, never guessed", m.Stats.Stats)
	}
}

func TestStatsEightOctetGaugeIsDecoded(t *testing.T) {
	payload := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	payload = append(payload, be32(1)...)
	payload = append(payload, be16(7)...)
	payload = append(payload, be16(8)...)
	payload = append(payload, be32(0)...)
	payload = append(payload, be32(123456)...)
	m := mustParse(t, frame(MsgStatisticsReport, payload))
	if len(m.Stats.Stats) != 1 || m.Stats.Stats[0].Value != 123456 {
		t.Fatalf("stats = %+v", m.Stats.Stats)
	}
}

func TestUnknownMessageTypeIsFramedNotDecoded(t *testing.T) {
	// Route Mirroring (6) carries a per-peer header and a body we do not decode.
	payload := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	payload = append(payload, 0xDE, 0xAD, 0xBE, 0xEF)
	m := mustParse(t, frame(MsgRouteMirroring, payload))
	if m.Peer == nil {
		t.Fatal("route mirroring carries a per-peer header")
	}
	if m.Update != nil || m.Stats != nil || m.PeerUp != nil {
		t.Fatal("an undecoded type must not be half-decoded into another")
	}
	if decodable(MsgRouteMirroring) {
		t.Fatal("route mirroring must be reported as not decoded")
	}
	// An unassigned type: framed, not decoded, and named "unknown" for metrics.
	if got := MsgType(200).String(); got != "unknown" {
		t.Fatalf("MsgType(200) = %q, want a closed-vocabulary label", got)
	}
	if _, err := ParseMessage(frame(MsgType(200), []byte{1, 2, 3})); err != nil {
		t.Fatalf("an unassigned type must parse as framed-but-undecoded: %v", err)
	}
}

func TestTruncationAtEveryOffsetIsAnErrorNeverAPanic(t *testing.T) {
	corpus := [][]byte{
		initiation("r1", "d"),
		termination(1),
		peerUp(0, "192.0.2.10", 64512),
		peerUp(peerFlagV, "2001:db8::1", 64512),
		peerDownNotification("192.0.2.10", 64512, 6, 2),
		statsReport("192.0.2.10", map[uint16]uint32{0: 1, 2: 2}),
		routeMonitoring(0, "192.0.2.10", 64512, updateBody(nil,
			append(attr(0x40, attrOrigin, []byte{0}), attr(0x40, attrNextHop, []byte{10, 0, 0, 1})...),
			nlri("10.1.0.0/24"))),
	}
	for ci, full := range corpus {
		for n := 0; n < len(full); n++ {
			cut := append([]byte(nil), full[:n]...)
			if len(cut) >= 5 {
				// Keep the declared length consistent with the truncated buffer
				// so the failure is found INSIDE a field, not by the length
				// cross-check — that is the deeper path.
				cut[1], cut[2], cut[3], cut[4] = byte(len(cut)>>24), byte(len(cut)>>16), byte(len(cut)>>8), byte(len(cut))
			}
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						t.Fatalf("corpus %d truncated to %d bytes PANICKED: %v", ci, n, rec)
					}
				}()
				_, _ = ParseMessage(cut)
			}()
		}
	}
}

func TestGarbageBytesNeverPanic(t *testing.T) {
	seeds := [][]byte{
		{3, 0, 0, 0, 6, 0},
		{3, 0, 0, 0, 48, 0},
		{3, 0, 0, 0, 60, 3},
		{3, 0, 0, 1, 0, 1},
	}
	for _, s := range seeds {
		for b := 0; b < 256; b++ {
			buf := append(append([]byte(nil), s...), byte(b))
			buf[1], buf[2], buf[3], buf[4] = 0, 0, byte(len(buf)>>8), byte(len(buf))
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						t.Fatalf("garbage %v PANICKED: %v", buf, rec)
					}
				}()
				_, _ = ParseMessage(buf)
			}()
		}
	}
}

func TestCursorCannotReadPastItsSlice(t *testing.T) {
	c := &cursor{b: []byte{1, 2, 3}}
	if _, err := c.u32(); !errors.Is(err, ErrShort) {
		t.Fatalf("u32 over 3 bytes = %v, want ErrShort", err)
	}
	if _, err := c.take(-1); !errors.Is(err, ErrShort) {
		t.Fatalf("take(-1) = %v, want ErrShort", err)
	}
	if _, err := c.sub(4); !errors.Is(err, ErrShort) {
		t.Fatalf("sub(4) over 3 bytes = %v, want ErrShort", err)
	}
	if got, err := c.u8(); err != nil || got != 1 {
		t.Fatalf("u8 = %d, %v", got, err)
	}
	if got, err := c.u16(); err != nil || got != 0x0203 {
		t.Fatalf("u16 = %#x, %v", got, err)
	}
	if c.remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", c.remaining())
	}
}

func TestMsgTypeLabelsAreAClosedVocabulary(t *testing.T) {
	want := map[MsgType]string{
		MsgRouteMonitoring:  "route_monitoring",
		MsgStatisticsReport: "statistics_report",
		MsgPeerDown:         "peer_down",
		MsgPeerUp:           "peer_up",
		MsgInitiation:       "initiation",
		MsgTermination:      "termination",
		MsgRouteMirroring:   "route_mirroring",
	}
	for typ, label := range want {
		if got := typ.String(); got != label {
			t.Errorf("MsgType(%d) = %q, want %q", typ, got, label)
		}
	}
	// Every other value must collapse to ONE label, or a hostile peer could
	// drive unbounded metric cardinality.
	for i := 7; i < 256; i++ {
		if got := MsgType(i).String(); got != "unknown" {
			t.Fatalf("MsgType(%d) = %q, want \"unknown\"", i, got)
		}
	}
}
