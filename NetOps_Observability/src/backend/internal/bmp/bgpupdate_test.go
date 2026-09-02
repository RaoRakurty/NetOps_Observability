package bmp

// bgpupdate_test.go — the BGP UPDATE parser.
//
// Two classes of assertion, and the second matters more:
//   * a real update decodes to the right prefixes and attributes;
//   * an update carrying something we do NOT support is COUNTED and skipped,
//     never partially decoded into plausible-looking routes.

import (
	"errors"
	"net/netip"
	"testing"
)

// attrs concatenates path attributes.
func attrs(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// asPathSeq builds an AS_PATH with one AS_SEQUENCE segment.
func asPathSeq(fourByte bool, asns ...uint32) []byte {
	out := []byte{asSegSequence, byte(len(asns))}
	for _, a := range asns {
		if fourByte {
			out = append(out, be32(a)...)
		} else {
			out = append(out, be16(uint16(a))...)
		}
	}
	return out
}

func TestUpdateDecodesIPv4AnnounceWithFullAttributes(t *testing.T) {
	body := updateBody(nil, attrs(
		attr(0x40, attrOrigin, []byte{0}),
		attr(0x40, attrASPath, asPathSeq(true, 64512, 65001, 15169)),
		attr(0x40, attrNextHop, []byte{192, 0, 2, 1}),
		attr(0x80, attrMED, be32(50)),
		attr(0x40, attrLocalPref, be32(200)),
		attr(0xC0, attrCommunities, append(be32(65000<<16|100), be32(0xFFFFFF01)...)),
		attr(0xC0, attrLargeCommunity, attrs(be32(64512), be32(1), be32(2))),
	), attrs(nlri("10.1.0.0/24"), nlri("10.2.0.0/16")))

	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	u := m.Update
	if u == nil {
		t.Fatal("no update")
	}
	if len(u.Announced) != 2 || u.Announced[0].String() != "10.1.0.0/24" || u.Announced[1].String() != "10.2.0.0/16" {
		t.Fatalf("announced = %v", u.Announced)
	}
	if u.Origin != "igp" || !u.HasOrigin {
		t.Fatalf("origin = %q", u.Origin)
	}
	if len(u.ASPath) != 3 || u.ASPath[2] != 15169 {
		t.Fatalf("as_path = %v", u.ASPath)
	}
	if u.NextHop != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("next hop = %v", u.NextHop)
	}
	if !u.HasMED || u.MED != 50 || !u.HasLocalPref || u.LocalPref != 200 {
		t.Fatalf("med/localpref = %d/%d", u.MED, u.LocalPref)
	}
	if len(u.Communities) != 2 || u.Communities[0] != "65000:100" || u.Communities[1] != "no-export" {
		t.Fatalf("communities = %v", u.Communities)
	}
	if len(u.LargeCommunities) != 1 || u.LargeCommunities[0] != "64512:1:2" {
		t.Fatalf("large communities = %v", u.LargeCommunities)
	}
}

func TestUpdateDecodesWithdrawnRoutes(t *testing.T) {
	body := updateBody(attrs(nlri("10.9.0.0/24"), nlri("172.16.0.0/12")), nil, nil)
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if len(m.Update.Withdrawn) != 2 {
		t.Fatalf("withdrawn = %v", m.Update.Withdrawn)
	}
	if m.Update.Withdrawn[1].String() != "172.16.0.0/12" {
		t.Fatalf("withdrawn[1] = %v", m.Update.Withdrawn[1])
	}
	if len(m.Update.Announced) != 0 {
		t.Fatalf("a withdraw-only update must announce nothing: %v", m.Update.Announced)
	}
}

func TestLegacyTwoByteASPathIsReadFromThePeerFlag(t *testing.T) {
	// The A flag says AS_PATH is 2-octet. A parser that guessed from the
	// attribute length instead would read 64512,65001 as one 32-bit ASN.
	body := updateBody(nil, attr(0x40, attrASPath, asPathSeq(false, 64512, 65001)), nlri("10.0.0.0/8"))
	m := mustParse(t, routeMonitoring(peerFlagA, "192.0.2.10", 64512, body))
	if len(m.Update.ASPath) != 2 || m.Update.ASPath[0] != 64512 || m.Update.ASPath[1] != 65001 {
		t.Fatalf("as_path = %v, want [64512 65001]", m.Update.ASPath)
	}
	// Without the flag the SAME bytes are read as 4-octet ASNs and run off the
	// end of the segment — proving the FLAG, not the byte pattern, is what
	// decides the encoding, and that a wrong reading surfaces as an error
	// rather than as a plausible-looking path.
	if _, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, body)); !errors.Is(err, ErrShort) {
		t.Fatalf("4-byte reading of a 2-byte AS_PATH = %v, want ErrShort", err)
	}
}

func TestAS4PathIsMergedPerRFC6793(t *testing.T) {
	// A 2-octet session: AS_PATH holds AS_TRANS(23456) where a 4-byte ASN sits,
	// and AS4_PATH carries the real value.
	body := updateBody(nil, attrs(
		attr(0x40, attrASPath, asPathSeq(false, 64512, 23456, 23456)),
		attr(0xC0, attrAS4Path, asPathSeq(true, 196618, 262145)),
	), nlri("10.0.0.0/8"))
	m := mustParse(t, routeMonitoring(peerFlagA, "192.0.2.10", 64512, body))
	u := m.Update
	if !u.AS4Merged {
		t.Fatal("AS4_PATH present but not merged")
	}
	want := []uint32{64512, 196618, 262145}
	if len(u.ASPath) != len(want) {
		t.Fatalf("merged path = %v, want %v", u.ASPath, want)
	}
	for i := range want {
		if u.ASPath[i] != want[i] {
			t.Fatalf("merged path = %v, want %v", u.ASPath, want)
		}
	}
}

func TestAS4PathLongerThanASPathIsIgnored(t *testing.T) {
	// RFC 6793 §4.2.3: splicing a longer 4-byte path onto a shorter 2-byte one
	// would invent hops, so the AS4_PATH is discarded.
	got := mergeAS4Path([]uint32{1, 2}, []uint32{10, 11, 12})
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("merge = %v, want the original AS_PATH untouched", got)
	}
}

func TestASSetIsFlattenedButFlagged(t *testing.T) {
	seg := []byte{asSegSet, 2}
	seg = append(seg, be32(64512)...)
	seg = append(seg, be32(64513)...)
	body := updateBody(nil, attr(0x40, attrASPath, seg), nlri("10.0.0.0/8"))
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if !m.Update.ASPathHasSet {
		t.Fatal("an AS_SET was flattened without being flagged — the record would read as an ordered path")
	}
}

func TestUnknownASPathSegmentTypeIsRefused(t *testing.T) {
	seg := []byte{9, 1}
	seg = append(seg, be32(64512)...)
	body := updateBody(nil, attr(0x40, attrASPath, seg), nil)
	_, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, body))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestMPReachIPv6UnicastIsDecoded(t *testing.T) {
	val := append([]byte{}, be16(afiIPv6)...)
	val = append(val, safiUnicast)
	nh := netip.MustParseAddr("2001:db8::1").As16()
	val = append(val, 16)
	val = append(val, nh[:]...)
	val = append(val, 0) // reserved
	val = append(val, nlri("2001:db8:1::/48")...)
	val = append(val, nlri("2001:db8:2::/64")...)

	body := updateBody(nil, attrs(
		attr(0x40, attrOrigin, []byte{2}),
		attrExt(0x80, attrMPReachNLRI, val),
	), nil)
	m := mustParse(t, routeMonitoring(peerFlagV, "2001:db8::99", 65001, body))
	u := m.Update
	if len(u.Announced) != 2 {
		t.Fatalf("announced = %v", u.Announced)
	}
	if u.Announced[0].String() != "2001:db8:1::/48" {
		t.Fatalf("announced[0] = %v", u.Announced[0])
	}
	if u.NextHop != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("next hop = %v", u.NextHop)
	}
	if u.Origin != "incomplete" {
		t.Fatalf("origin = %q", u.Origin)
	}
}

func TestMPReachIPv6GlobalPlusLinkLocalNextHopTakesTheGlobal(t *testing.T) {
	val := append([]byte{}, be16(afiIPv6)...)
	val = append(val, safiUnicast)
	global := netip.MustParseAddr("2001:db8::1").As16()
	ll := netip.MustParseAddr("fe80::1").As16()
	val = append(val, 32)
	val = append(val, global[:]...)
	val = append(val, ll[:]...)
	val = append(val, 0)
	val = append(val, nlri("2001:db8:5::/48")...)
	body := updateBody(nil, attrExt(0x80, attrMPReachNLRI, val), nil)
	m := mustParse(t, routeMonitoring(peerFlagV, "2001:db8::99", 65001, body))
	if m.Update.NextHop != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("next hop = %v, want the GLOBAL address", m.Update.NextHop)
	}
}

func TestMPUnreachIPv6IsDecoded(t *testing.T) {
	val := append([]byte{}, be16(afiIPv6)...)
	val = append(val, safiUnicast)
	val = append(val, nlri("2001:db8:9::/48")...)
	body := updateBody(nil, attrExt(0x80, attrMPUnreachNLRI, val), nil)
	m := mustParse(t, routeMonitoring(peerFlagV, "2001:db8::99", 65001, body))
	if len(m.Update.Withdrawn) != 1 || m.Update.Withdrawn[0].String() != "2001:db8:9::/48" {
		t.Fatalf("withdrawn = %v", m.Update.Withdrawn)
	}
}

func TestUnsupportedAddressFamilyIsCountedAndSkippedWhole(t *testing.T) {
	// A VPNv4 (AFI 1 / SAFI 128) MP_REACH. Its NLRI is label+RD+prefix — read as
	// plain IPv4 it would produce garbage prefixes, so it must be skipped.
	val := append([]byte{}, be16(afiIPv4)...)
	val = append(val, 128) // SAFI: MPLS-labeled VPN
	val = append(val, 12)
	val = append(val, make([]byte, 12)...)
	val = append(val, 0)
	val = append(val, 0x70, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 10, 1, 0)
	body := updateBody(nil, attrExt(0x80, attrMPReachNLRI, val), nil)
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if len(m.Update.Announced) != 0 {
		t.Fatalf("a VPNv4 update must produce NO prefixes, got %v", m.Update.Announced)
	}
	if m.Update.UnsupportedFamilies != 1 {
		t.Fatalf("UnsupportedFamilies = %d, want 1 — an unread family must be COUNTED", m.Update.UnsupportedFamilies)
	}
}

func TestUnknownPathAttributeIsCountedAndSkipped(t *testing.T) {
	body := updateBody(nil, attrs(
		attr(0xC0, 16, []byte{0, 2, 0, 0, 0, 0, 0, 1}), // extended communities
		attr(0xC0, 200, []byte{9, 9, 9}),               // unassigned
		attr(0x40, attrOrigin, []byte{0}),
	), nlri("10.0.0.0/8"))
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if m.Update.UnknownAttributes != 2 {
		t.Fatalf("UnknownAttributes = %d, want 2", m.Update.UnknownAttributes)
	}
	// The attributes AFTER the unknown ones must still decode: skipping is by
	// declared length, so the walk stays aligned.
	if m.Update.Origin != "igp" || len(m.Update.Announced) != 1 {
		t.Fatalf("the walk lost alignment after an unknown attribute: %+v", m.Update)
	}
}

func TestExtendedLengthAttributeIsRead(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = 0xAB
	}
	body := updateBody(nil, attrs(
		attrExt(0xC0, 201, long),
		attr(0x40, attrOrigin, []byte{1}),
	), nlri("10.0.0.0/8"))
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if m.Update.Origin != "egp" {
		t.Fatalf("origin after a 300-octet extended-length attribute = %q", m.Update.Origin)
	}
}

func TestPrefixLengthBeyondTheFamilyIsRefused(t *testing.T) {
	body := updateBody(nil, nil, []byte{33, 10, 0, 0, 0, 0})
	_, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, body))
	if !errors.Is(err, ErrLength) {
		t.Fatalf("err = %v, want ErrLength for a /33 IPv4 prefix", err)
	}
	// The same field is what an ADD-PATH stream trips over: its 4-octet path id
	// lands where the prefix length belongs.
	addPath := updateBody(nil, nil, append(be32(1), nlri("10.0.0.0/8")...))
	if _, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, addPath)); err == nil {
		t.Fatal("ADD-PATH-encoded NLRI must surface as an error, never as shifted prefixes")
	}
}

func TestHostBitsBeyondThePrefixLengthAreMasked(t *testing.T) {
	// A peer sending 10.1.2.3 with length /24 must be stored as 10.1.2.0/24.
	body := updateBody(nil, nil, []byte{24, 10, 1, 2})
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if m.Update.Announced[0].String() != "10.1.2.0/24" {
		t.Fatalf("prefix = %v", m.Update.Announced[0])
	}
}

func TestDefaultRouteIsAValidZeroLengthPrefix(t *testing.T) {
	body := updateBody(nil, attr(0x40, attrNextHop, []byte{192, 0, 2, 1}), []byte{0})
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if len(m.Update.Announced) != 1 || m.Update.Announced[0].String() != "0.0.0.0/0" {
		t.Fatalf("announced = %v, want the default route", m.Update.Announced)
	}
}

func TestRouteMonitoringCarryingSomethingOtherThanAnUpdateIsRefused(t *testing.T) {
	payload := append([]byte{}, peerHeader(0, "192.0.2.10", 64512, "10.0.0.1")...)
	payload = append(payload, bgpMessage(4, nil)...) // KEEPALIVE
	_, err := ParseMessage(frame(MsgRouteMonitoring, payload))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestOverlongASPathIsRefused(t *testing.T) {
	seg := []byte{asSegSequence, 255}
	for i := 0; i < 255; i++ {
		seg = append(seg, be32(uint32(i))...)
	}
	var val []byte
	for i := 0; i < 3; i++ { // 765 hops, past maxASPathLength
		val = append(val, seg...)
	}
	body := updateBody(nil, attrExt(0x40, attrASPath, val), nil)
	if _, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, body)); !errors.Is(err, ErrLength) {
		t.Fatalf("err = %v, want ErrLength", err)
	}
}

func TestParseUpdateIsReachableDirectly(t *testing.T) {
	body := updateBody(nil, attr(0x40, attrOrigin, []byte{0}), nlri("10.0.0.0/8"))
	u, err := ParseUpdate(body, true)
	if err != nil {
		t.Fatalf("ParseUpdate: %v", err)
	}
	if len(u.Announced) != 1 {
		t.Fatalf("announced = %v", u.Announced)
	}
	if _, err := ParseUpdate([]byte{0xFF}, true); err == nil {
		t.Fatal("a one-byte update body must not parse")
	}
}

func TestAggregatorAttributes(t *testing.T) {
	four := append(be32(196618), []byte{192, 0, 2, 9}...)
	body := updateBody(nil, attr(0xC0, attrAggregator, four), nil)
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if !m.Update.HasAggregator || m.Update.AggregatorAS != 196618 {
		t.Fatalf("aggregator = %+v", m.Update)
	}
	// A 2-octet session: AS4_AGGREGATOR is authoritative over AGGREGATOR.
	two := append(be16(23456), []byte{192, 0, 2, 9}...)
	body2 := updateBody(nil, attrs(
		attr(0xC0, attrAS4Aggregator, four),
		attr(0xC0, attrAggregator, two),
	), nil)
	m2 := mustParse(t, routeMonitoring(peerFlagA, "192.0.2.10", 64512, body2))
	if m2.Update.AggregatorAS != 196618 {
		t.Fatalf("aggregator AS = %d, want the AS4 value", m2.Update.AggregatorAS)
	}
}

func TestAtomicAggregateIsRecorded(t *testing.T) {
	body := updateBody(nil, attr(0x40, attrAtomicAggregate, nil), nil)
	m := mustParse(t, routeMonitoring(0, "192.0.2.10", 64512, body))
	if !m.Update.AtomicAggregate {
		t.Fatal("ATOMIC_AGGREGATE not recorded")
	}
}

func TestWellKnownCommunityNames(t *testing.T) {
	cases := map[uint32]string{
		0xFFFFFF01:    "no-export",
		0xFFFFFF02:    "no-advertise",
		0xFFFFFF03:    "no-export-subconfed",
		0xFFFFFF04:    "no-peer",
		65000<<16 | 7: "65000:7",
	}
	for v, want := range cases {
		if got := communityText(v); got != want {
			t.Errorf("communityText(%#x) = %q, want %q", v, got, want)
		}
	}
}

func TestTruncatedCommunityAttributeIsRefused(t *testing.T) {
	body := updateBody(nil, attr(0xC0, attrCommunities, []byte{0, 1, 2}), nil)
	if _, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, body)); !errors.Is(err, ErrShort) {
		t.Fatalf("err = %v, want ErrShort", err)
	}
	body2 := updateBody(nil, attr(0xC0, attrLargeCommunity, make([]byte, 11)), nil)
	if _, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, body2)); !errors.Is(err, ErrShort) {
		t.Fatalf("large community err = %v, want ErrShort", err)
	}
}

func TestAttributeLengthPastTheRegionIsRefused(t *testing.T) {
	// An attribute declaring 200 octets inside a 10-octet attribute region.
	bad := []byte{0x40, attrASPath, 200, 1, 2, 3}
	body := updateBody(nil, bad, nil)
	if _, err := ParseMessage(routeMonitoring(0, "192.0.2.10", 64512, body)); !errors.Is(err, ErrShort) {
		t.Fatalf("err = %v, want ErrShort", err)
	}
}

func TestOriginTextIsHonestAboutUnknownValues(t *testing.T) {
	if got := originText(9); got != "unknown" {
		t.Fatalf("originText(9) = %q — an unassigned ORIGIN must never default to igp", got)
	}
}
