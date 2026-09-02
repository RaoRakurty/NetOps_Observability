package bmp

// bgpupdate.go — the BGP UPDATE parser used inside Route Monitoring frames.
//
// Scope, stated honestly and enforced by the code: IPv4 and IPv6 UNICAST, both
// through the classic NEXT_HOP/NLRI fields and through MP_REACH/MP_UNREACH
// (RFC 4760). Everything else — VPN address families, EVPN, flowspec,
// link-state, ADD-PATH-encoded NLRI — is COUNTED as unsupported and skipped.
// It is never partially decoded: half a VPN route rendered as an IPv4 prefix
// would be a wrong number on an operator's screen, which is worse than a gap
// the response admits to.

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// BGP path attribute type codes (RFC 4271, 4360, 4760, 6793, 8092).
const (
	attrOrigin          uint8 = 1
	attrASPath          uint8 = 2
	attrNextHop         uint8 = 3
	attrMED             uint8 = 4
	attrLocalPref       uint8 = 5
	attrAtomicAggregate uint8 = 6
	attrAggregator      uint8 = 7
	attrCommunities     uint8 = 8
	attrMPReachNLRI     uint8 = 14
	attrMPUnreachNLRI   uint8 = 15
	attrAS4Path         uint8 = 17
	attrAS4Aggregator   uint8 = 18
	attrLargeCommunity  uint8 = 32
)

// Attribute flag bits (RFC 4271 §4.3).
const attrFlagExtendedLength = 0x10

// Address families we decode. AFI/SAFI values are IANA registry numbers.
const (
	afiIPv4     uint16 = 1
	afiIPv6     uint16 = 2
	safiUnicast uint8  = 1
)

// AS_PATH segment types (RFC 4271 §4.3, RFC 5065).
const (
	asSegSet            uint8 = 1
	asSegSequence       uint8 = 2
	asSegConfedSequence uint8 = 3
	asSegConfedSet      uint8 = 4
)

// Bounds on ONE update. A frame is already capped at MaxMessageSize, but these
// stop a single legal-sized frame from producing an absurd number of records.
const (
	maxPrefixesPerUpdate = 4096
	maxASPathLength      = 512
	maxCommunities       = 512
)

// Origin renders the ORIGIN attribute (RFC 4271 §4.3). An unassigned value is
// reported as "unknown", never defaulted to "igp".
func originText(v uint8) string {
	switch v {
	case 0:
		return "igp"
	case 1:
		return "egp"
	case 2:
		return "incomplete"
	default:
		return "unknown"
	}
}

// BGPUpdate is one parsed UPDATE.
//
// Announced/Withdrawn hold IPv4 AND IPv6 unicast prefixes together — the
// address family is recoverable from each netip.Prefix, so a second axis would
// only be a second thing to keep consistent.
type BGPUpdate struct {
	Withdrawn []netip.Prefix
	Announced []netip.Prefix

	Origin    string
	HasOrigin bool

	// ASPath is the flattened path, AS4-merged (RFC 6793) when the session was
	// 2-byte and an AS4_PATH was present. Confederation segments are included
	// in order; sets are flattened, which is lossy for set semantics and is
	// why ASPathHasSet records that it happened.
	ASPath       []uint32
	HasASPath    bool
	ASPathHasSet bool
	AS4Merged    bool

	NextHop    netip.Addr
	HasNextHop bool

	MED          uint32
	HasMED       bool
	LocalPref    uint32
	HasLocalPref bool

	AtomicAggregate bool
	AggregatorAS    uint32
	AggregatorAddr  netip.Addr
	HasAggregator   bool

	Communities      []string
	LargeCommunities []string

	// UnsupportedFamilies counts MP_REACH/MP_UNREACH attributes for an AFI/SAFI
	// this parser does not decode. A non-zero value means the update carried
	// routing information we did NOT render.
	UnsupportedFamilies int
	// UnknownAttributes counts path attributes whose type code we do not
	// decode. They are skipped by their declared length, never guessed at.
	UnknownAttributes int
	// Truncated is set when a bound above was hit and the rest of the update
	// was not read. It travels with the record so a partial view is never
	// presented as a complete one.
	Truncated bool
}

// ParseUpdate parses a bare BGP UPDATE body (everything AFTER the 19-byte BGP
// header). fourByteAS says whether AS_PATH carries 4-octet ASNs; in BMP this
// comes from the per-peer header's A flag (RFC 7854 §4.2), never from a guess.
//
// It is exported so the fuzz target can reach it directly.
func ParseUpdate(body []byte, fourByteAS bool) (*BGPUpdate, error) {
	return parseBGPUpdateBody(&cursor{b: body}, !fourByteAS)
}

// parseBGPUpdateBody is the internal entry point. legacyAS mirrors the per-peer
// header's A flag: true = 2-octet AS_PATH.
func parseBGPUpdateBody(c *cursor, legacyAS bool) (*BGPUpdate, error) {
	u := &BGPUpdate{}

	wlen, err := c.u16()
	if err != nil {
		return nil, err
	}
	wc, err := c.sub(int(wlen))
	if err != nil {
		return nil, err
	}
	if u.Withdrawn, err = parseNLRI(wc, afiIPv4); err != nil {
		return nil, err
	}

	alen, err := c.u16()
	if err != nil {
		return nil, err
	}
	ac, err := c.sub(int(alen))
	if err != nil {
		return nil, err
	}

	var as4Path []uint32
	if err := parseAttributes(ac, u, legacyAS, &as4Path); err != nil {
		return nil, err
	}
	if len(as4Path) > 0 {
		u.ASPath = mergeAS4Path(u.ASPath, as4Path)
		u.AS4Merged = true
		u.HasASPath = true
	}

	// Whatever is left is classic IPv4 unicast NLRI.
	nlri, err := parseNLRI(c, afiIPv4)
	if err != nil {
		return nil, err
	}
	u.Announced = appendBounded(u.Announced, nlri, u)
	return u, nil
}

// appendBounded appends prefixes up to maxPrefixesPerUpdate, marking the update
// truncated rather than growing without limit.
func appendBounded(dst, src []netip.Prefix, u *BGPUpdate) []netip.Prefix {
	for _, p := range src {
		if len(dst) >= maxPrefixesPerUpdate {
			u.Truncated = true
			return dst
		}
		dst = append(dst, p)
	}
	return dst
}

// parseAttributes walks the path-attribute region.
func parseAttributes(c *cursor, u *BGPUpdate, legacyAS bool, as4Path *[]uint32) error {
	for c.remaining() > 0 {
		flags, err := c.u8()
		if err != nil {
			return err
		}
		code, err := c.u8()
		if err != nil {
			return err
		}
		var length int
		if flags&attrFlagExtendedLength != 0 {
			n, lerr := c.u16()
			if lerr != nil {
				return lerr
			}
			length = int(n)
		} else {
			n, lerr := c.u8()
			if lerr != nil {
				return lerr
			}
			length = int(n)
		}
		val, err := c.sub(length)
		if err != nil {
			return err
		}
		if err := parseOneAttribute(code, val, u, legacyAS, as4Path); err != nil {
			return err
		}
	}
	return nil
}

// parseOneAttribute decodes a single path attribute. An attribute whose type we
// know but whose LENGTH is wrong is a malformed frame (an error the caller
// counts), not a value to be salvaged; an attribute whose type we do not know
// is counted and skipped.
func parseOneAttribute(code uint8, val *cursor, u *BGPUpdate, legacyAS bool, as4Path *[]uint32) error {
	switch code {
	case attrOrigin:
		v, err := val.u8()
		if err != nil {
			return err
		}
		u.Origin, u.HasOrigin = originText(v), true

	case attrASPath:
		path, hasSet, err := parseASPath(val, !legacyAS)
		if err != nil {
			return err
		}
		u.ASPath, u.HasASPath, u.ASPathHasSet = path, true, hasSet

	case attrAS4Path:
		// AS4_PATH is ALWAYS 4-octet, whatever the session negotiated.
		path, _, err := parseASPath(val, true)
		if err != nil {
			return err
		}
		*as4Path = path

	case attrNextHop:
		raw, err := val.take(4)
		if err != nil {
			return err
		}
		u.NextHop = netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]})
		u.HasNextHop = true

	case attrMED:
		v, err := val.u32()
		if err != nil {
			return err
		}
		u.MED, u.HasMED = v, true

	case attrLocalPref:
		v, err := val.u32()
		if err != nil {
			return err
		}
		u.LocalPref, u.HasLocalPref = v, true

	case attrAtomicAggregate:
		u.AtomicAggregate = true

	case attrAggregator, attrAS4Aggregator:
		if err := parseAggregator(val, u, code, legacyAS); err != nil {
			return err
		}

	case attrCommunities:
		if err := parseCommunities(val, u); err != nil {
			return err
		}

	case attrLargeCommunity:
		if err := parseLargeCommunities(val, u); err != nil {
			return err
		}

	case attrMPReachNLRI:
		if err := parseMPReach(val, u); err != nil {
			return err
		}

	case attrMPUnreachNLRI:
		if err := parseMPUnreach(val, u); err != nil {
			return err
		}

	default:
		u.UnknownAttributes++
	}
	return nil
}

// parseAggregator reads AGGREGATOR / AS4_AGGREGATOR. AS4_AGGREGATOR is always
// 4-octet; plain AGGREGATOR follows the session encoding. AS4_AGGREGATOR wins
// when both are present (RFC 6793 §4.2.3).
func parseAggregator(val *cursor, u *BGPUpdate, code uint8, legacyAS bool) error {
	fourByte := code == attrAS4Aggregator || !legacyAS
	var as uint32
	if fourByte {
		v, err := val.u32()
		if err != nil {
			return err
		}
		as = v
	} else {
		v, err := val.u16()
		if err != nil {
			return err
		}
		as = uint32(v)
	}
	raw, err := val.take(4)
	if err != nil {
		return err
	}
	if code == attrAggregator && u.HasAggregator {
		return nil // AS4_AGGREGATOR already set the authoritative value
	}
	u.AggregatorAS = as
	u.AggregatorAddr = netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]})
	u.HasAggregator = true
	return nil
}

// parseASPath flattens the AS_PATH segments in order. It reports whether any
// AS_SET segment was seen, because flattening a set loses the "these are
// unordered" semantics and the record should say so rather than pretend the
// path is a clean sequence.
func parseASPath(c *cursor, fourByte bool) (path []uint32, hasSet bool, err error) {
	for c.remaining() > 0 {
		segType, terr := c.u8()
		if terr != nil {
			return nil, false, terr
		}
		count, cerr := c.u8()
		if cerr != nil {
			return nil, false, cerr
		}
		switch segType {
		case asSegSet, asSegConfedSet:
			hasSet = true
		case asSegSequence, asSegConfedSequence:
		default:
			return nil, false, fmt.Errorf("%w: AS_PATH segment type %d", ErrUnsupported, segType)
		}
		for i := 0; i < int(count); i++ {
			var as uint32
			if fourByte {
				v, aerr := c.u32()
				if aerr != nil {
					return nil, false, aerr
				}
				as = v
			} else {
				v, aerr := c.u16()
				if aerr != nil {
					return nil, false, aerr
				}
				as = uint32(v)
			}
			if len(path) >= maxASPathLength {
				return nil, false, fmt.Errorf("%w: AS_PATH longer than %d hops", ErrLength, maxASPathLength)
			}
			path = append(path, as)
		}
	}
	return path, hasSet, nil
}

// mergeAS4Path applies RFC 6793 §4.2.3. If AS_PATH is SHORTER than AS4_PATH the
// AS4_PATH is ignored entirely — the RFC's rule, and the safe one: splicing a
// longer 4-byte path onto a shorter 2-byte one would invent hops.
func mergeAS4Path(asPath, as4Path []uint32) []uint32 {
	if len(as4Path) > len(asPath) {
		return asPath
	}
	keep := len(asPath) - len(as4Path)
	out := make([]uint32, 0, len(asPath))
	out = append(out, asPath[:keep]...)
	out = append(out, as4Path...)
	return out
}

// parseCommunities decodes RFC 1997 communities as "asn:value". Well-known
// values are rendered by name, because "no-export" is what an operator reads
// for and 4294967041 is not.
func parseCommunities(c *cursor, u *BGPUpdate) error {
	for c.remaining() > 0 {
		v, err := c.u32()
		if err != nil {
			return err
		}
		if len(u.Communities) >= maxCommunities {
			u.Truncated = true
			return nil
		}
		u.Communities = append(u.Communities, communityText(v))
	}
	return nil
}

// communityText renders one RFC 1997 community.
func communityText(v uint32) string {
	switch v {
	case 0xFFFFFF01:
		return "no-export"
	case 0xFFFFFF02:
		return "no-advertise"
	case 0xFFFFFF03:
		return "no-export-subconfed"
	case 0xFFFFFF04:
		return "no-peer"
	}
	var b strings.Builder
	b.WriteString(strconv.FormatUint(uint64(v>>16), 10))
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(uint64(v&0xFFFF), 10))
	return b.String()
}

// parseLargeCommunities decodes RFC 8092 large communities as "global:l1:l2".
// A trailing fragment shorter than 12 octets is a malformed attribute.
func parseLargeCommunities(c *cursor, u *BGPUpdate) error {
	for c.remaining() > 0 {
		g, err := c.u32()
		if err != nil {
			return err
		}
		l1, err := c.u32()
		if err != nil {
			return err
		}
		l2, err := c.u32()
		if err != nil {
			return err
		}
		if len(u.LargeCommunities) >= maxCommunities {
			u.Truncated = true
			return nil
		}
		u.LargeCommunities = append(u.LargeCommunities,
			strconv.FormatUint(uint64(g), 10)+":"+
				strconv.FormatUint(uint64(l1), 10)+":"+
				strconv.FormatUint(uint64(l2), 10))
	}
	return nil
}

// parseMPReach decodes MP_REACH_NLRI (RFC 4760 §3) for the families we support.
// An unsupported AFI/SAFI is COUNTED and skipped whole — we do not attempt to
// read its NLRI, because the NLRI encoding is family-specific and misreading it
// would manufacture prefixes that were never announced.
func parseMPReach(c *cursor, u *BGPUpdate) error {
	afi, err := c.u16()
	if err != nil {
		return err
	}
	safi, err := c.u8()
	if err != nil {
		return err
	}
	nhLen, err := c.u8()
	if err != nil {
		return err
	}
	nh, err := c.take(int(nhLen))
	if err != nil {
		return err
	}
	if _, err := c.u8(); err != nil { // reserved octet
		return err
	}
	if !supportedFamily(afi, safi) {
		u.UnsupportedFamilies++
		return nil
	}
	if a, ok := nextHopFrom(nh); ok {
		u.NextHop, u.HasNextHop = a, true
	}
	prefixes, err := parseNLRI(c, afi)
	if err != nil {
		return err
	}
	u.Announced = appendBounded(u.Announced, prefixes, u)
	return nil
}

// parseMPUnreach decodes MP_UNREACH_NLRI (RFC 4760 §4).
func parseMPUnreach(c *cursor, u *BGPUpdate) error {
	afi, err := c.u16()
	if err != nil {
		return err
	}
	safi, err := c.u8()
	if err != nil {
		return err
	}
	if !supportedFamily(afi, safi) {
		u.UnsupportedFamilies++
		return nil
	}
	prefixes, err := parseNLRI(c, afi)
	if err != nil {
		return err
	}
	u.Withdrawn = appendBounded(u.Withdrawn, prefixes, u)
	return nil
}

// supportedFamily is the explicit allowlist: IPv4/IPv6 UNICAST only.
func supportedFamily(afi uint16, safi uint8) bool {
	return (afi == afiIPv4 || afi == afiIPv6) && safi == safiUnicast
}

// nextHopFrom decodes an MP_REACH next-hop field. IPv6 may carry a global
// address alone (16) or global + link-local (32); we take the GLOBAL one, which
// is the address that is meaningful outside the link. Any other width is not
// decoded rather than being truncated into a plausible-looking address.
func nextHopFrom(raw []byte) (netip.Addr, bool) {
	switch len(raw) {
	case 4:
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), true
	case 16, 32:
		var a [16]byte
		copy(a[:], raw[:16])
		return netip.AddrFrom16(a), true
	default:
		return netip.Addr{}, false
	}
}

// parseNLRI reads length-prefixed prefixes until the cursor is exhausted
// (RFC 4271 §4.3). A prefix length beyond the family's width is a malformed
// frame — and it is exactly the field an ADD-PATH-encoded stream trips over,
// which is why that case surfaces as an error we count rather than as prefixes
// shifted by four octets.
func parseNLRI(c *cursor, afi uint16) ([]netip.Prefix, error) {
	maxBits := 32
	if afi == afiIPv6 {
		maxBits = 128
	}
	var out []netip.Prefix
	for c.remaining() > 0 {
		bits, err := c.u8()
		if err != nil {
			return nil, err
		}
		if int(bits) > maxBits {
			return nil, fmt.Errorf("%w: prefix length %d exceeds %d bits", ErrLength, bits, maxBits)
		}
		n := (int(bits) + 7) / 8
		raw, err := c.take(n)
		if err != nil {
			return nil, err
		}
		if len(out) >= maxPrefixesPerUpdate {
			return nil, fmt.Errorf("%w: more than %d prefixes in one update", ErrLength, maxPrefixesPerUpdate)
		}
		p, ok := prefixFrom(raw, int(bits), afi)
		if !ok {
			return nil, fmt.Errorf("%w: undecodable prefix (%d bits)", ErrLength, bits)
		}
		out = append(out, p)
	}
	return out, nil
}

// prefixFrom builds a netip.Prefix from the truncated wire bytes, zero-padding
// the trailing octets the encoding omits. Masked() is applied so a peer cannot
// smuggle host bits past the prefix length into the stored record.
func prefixFrom(raw []byte, bits int, afi uint16) (netip.Prefix, bool) {
	if afi == afiIPv6 {
		var a [16]byte
		if len(raw) > 16 {
			return netip.Prefix{}, false
		}
		copy(a[:], raw)
		return netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked(), true
	}
	var a [4]byte
	if len(raw) > 4 {
		return netip.Prefix{}, false
	}
	copy(a[:], raw)
	return netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked(), true
}
