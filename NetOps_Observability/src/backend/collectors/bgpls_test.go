package collectors

import (
	"encoding/binary"
	"testing"
)

// ---- byte-fixture builders (mirror RFC 7752 wire layout) -------------------

// tlv16 builds a 2-byte-type / 2-byte-length TLV (the Link-State NLRI + attribute
// TLV shape).
func tlv16(typ uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[4:], val)
	return b
}

func u32b(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// isisNodeDescSubs: AS (512) + IGP Router-ID (515 = 6-byte ISO System-ID).
func isisNodeDescSubs(asn uint32, sysID []byte) []byte {
	return append(tlv16(subTLVAutonomousSystem, u32b(asn)), tlv16(subTLVIGPRouterID, sysID)...)
}

// nodeNLRIValue: Protocol-ID(1) Identifier(8) Local-Node-Descriptors(256).
func nodeNLRIValue(proto byte, descSubs []byte) []byte {
	v := []byte{proto, 0, 0, 0, 0, 0, 0, 0, 0} // proto + 8-byte identifier
	return append(v, tlv16(tlvLocalNodeDesc, descSubs)...)
}

// linkNLRIValue: Protocol-ID Identifier Local(256) Remote(257) + link descriptors.
func linkNLRIValue(proto byte, localSubs, remoteSubs, localIP, remIP []byte) []byte {
	v := []byte{proto, 0, 0, 0, 0, 0, 0, 0, 0}
	v = append(v, tlv16(tlvLocalNodeDesc, localSubs)...)
	v = append(v, tlv16(tlvRemoteNodeDesc, remoteSubs)...)
	v = append(v, tlv16(tlvIPv4IfaceAddr, localIP)...)
	v = append(v, tlv16(tlvIPv4NeighborAddr, remIP)...)
	return v
}

// prefixNLRIValue: Protocol-ID Identifier Local(256) + IP-Reachability(265).
func prefixNLRIValue(proto byte, localSubs []byte, prefixLen byte, packed []byte) []byte {
	v := []byte{proto, 0, 0, 0, 0, 0, 0, 0, 0}
	v = append(v, tlv16(tlvLocalNodeDesc, localSubs)...)
	v = append(v, tlv16(tlvIPReachability, append([]byte{prefixLen}, packed...))...)
	return v
}

// lsNLRIWrap prepends the NLRI Type(2) + Total-Length(2) header.
func lsNLRIWrap(typ uint16, val []byte) []byte { return tlv16(typ, val) }

// updateBody builds a BGP UPDATE message body carrying Link-State NLRI in
// MP_REACH (or MP_UNREACH when reach=false) plus an optional BGP-LS attribute.
func updateBody(nlri, lsAttr []byte, reach bool) []byte {
	var mp []byte
	mp = appendU16(mp, afiBGPLS)
	if reach {
		mp = append(mp, safiBGPLS, 0 /*nexthop len*/, 0 /*reserved*/)
	} else {
		mp = append(mp, safiBGPLS)
	}
	mp = append(mp, nlri...)

	attrType := byte(attrMPReachNLRI)
	if !reach {
		attrType = attrMPUnreachNLRI
	}
	attrs := pathAttrExt(attrType, mp)
	if lsAttr != nil {
		attrs = append(attrs, pathAttrExt(attrBGPLS, lsAttr)...)
	}
	body := []byte{0, 0} // withdrawn-routes length = 0
	body = appendU16(body, uint16(len(attrs)))
	return append(body, attrs...)
}

// pathAttrExt builds an optional + extended-length (2-byte) path attribute.
func pathAttrExt(typ byte, val []byte) []byte {
	b := []byte{0x90, typ} // flags: optional(0x80) | extended-length(0x10)
	b = appendU16(b, uint16(len(val)))
	return append(b, val...)
}

// ---- tests -----------------------------------------------------------------

func TestRenderIGPRouterID(t *testing.T) {
	isis := []byte{0x00, 0x20, 0x90, 0x00, 0x00, 0x03}
	if got := renderIGPRouterID(isis, "isis-l2"); got != "0020.9000.0003" {
		t.Errorf("IS-IS System-ID = %q, want 0020.9000.0003", got)
	}
	psn := []byte{0x00, 0x20, 0x90, 0x00, 0x00, 0x03, 0x05}
	if got := renderIGPRouterID(psn, "isis-l1"); got != "0020.9000.0003.05" {
		t.Errorf("IS-IS pseudonode = %q, want 0020.9000.0003.05", got)
	}
	if got := renderIGPRouterID([]byte{10, 0, 0, 9}, "ospfv2"); got != "10.0.0.9" {
		t.Errorf("OSPF Router-ID = %q, want 10.0.0.9", got)
	}
}

func TestProtocolIDLabels(t *testing.T) {
	for proto, want := range map[byte]string{1: "isis-l1", 2: "isis-l2", 3: "ospfv2", 6: "ospfv3", 99: "igp"} {
		if got := bgplsProtocolID(proto); got != want {
			t.Errorf("protocol %d = %q, want %q", proto, got, want)
		}
	}
}

// A Node and a Link NLRI that reference the SAME node descriptor must hash to the
// SAME key, so the node↔link join (hostname enrichment) works.
func TestNodeDescriptorKeyStable(t *testing.T) {
	sys := []byte{0, 0, 0, 0, 0, 1}
	subs := isisNodeDescSubs(65000, sys)
	node, ok := parseNodeNLRI(nodeNLRIValue(2, subs))
	if !ok {
		t.Fatal("node NLRI failed to parse")
	}
	link, ok := parseLinkNLRI(linkNLRIValue(2, subs, isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 2}), []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}))
	if !ok {
		t.Fatal("link NLRI failed to parse")
	}
	if node.localKey != link.localKey {
		t.Errorf("node key %q != link local key %q — join would break", node.localKey, link.localKey)
	}
}

func TestParseLinkNLRI(t *testing.T) {
	local := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})
	remote := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 2})
	n, ok := parseLinkNLRI(linkNLRIValue(2, local, remote, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}))
	if !ok {
		t.Fatal("parse failed")
	}
	if n.kind != nlriTypeLink || n.igp != "isis-l2" {
		t.Errorf("kind/igp = %d/%q", n.kind, n.igp)
	}
	if n.localIface != "10.0.0.1" || n.remIface != "10.0.0.2" {
		t.Errorf("ifaces = %q/%q, want 10.0.0.1/10.0.0.2", n.localIface, n.remIface)
	}
	if n.localKey == n.remoteKey {
		t.Error("local and remote node keys must differ")
	}
}

func TestParsePrefixNLRI(t *testing.T) {
	local := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})
	// 10.0.0.0/24 → prefix-length 24, packed left-justified to ceil(24/8)=3 octets.
	n, ok := parsePrefixNLRI(prefixNLRIValue(2, local, 24, []byte{10, 0, 0}), nlriTypeIPv4Prefix)
	if !ok {
		t.Fatal("prefix parse failed")
	}
	if n.prefix != "10.0.0.0/24" {
		t.Errorf("prefix = %q, want 10.0.0.0/24", n.prefix)
	}
}

// splitLSAttributes must strip the MP_REACH AFI/SAFI/next-hop/reserved header and
// surface the raw Link-State NLRI bytes + the BGP-LS attribute.
func TestSplitLSAttributes(t *testing.T) {
	nlri := lsNLRIWrap(nlriTypeNode, nodeNLRIValue(2, isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})))
	attr := tlv16(tlvNodeName, []byte("spine1"))
	body := updateBody(nlri, attr, true)

	// re-derive the attribute block from the body (mirror applyUpdate's framing).
	taLen := int(binary.BigEndian.Uint16(body[2:4]))
	attrs := body[4 : 4+taLen]
	reach, unreach, ls := splitLSAttributes(attrs)
	if len(unreach) != 0 {
		t.Errorf("expected no unreach NLRI, got %d bytes", len(unreach))
	}
	if string(reach) != string(nlri) {
		t.Errorf("reach NLRI bytes mismatch:\n got %x\nwant %x", reach, nlri)
	}
	if string(ls) != string(attr) {
		t.Errorf("bgp-ls attr bytes mismatch:\n got %x\nwant %x", ls, attr)
	}
}

// End-to-end: feed Node + Link UPDATEs into the collector, then buildLinks must
// emit one bgp_ls adjacency enriched with the node hostname from the attribute.
func TestApplyUpdateAndBuildLinks(t *testing.T) {
	c := NewBGPLS().(*bgplsCollector)
	peer := "10.0.0.9:179"

	localSubs := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})
	remoteSubs := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 2})

	// Node NLRIs carry the hostnames (BGP-LS Node Name attribute).
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeNode, nodeNLRIValue(2, localSubs)), tlv16(tlvNodeName, []byte("spine1")), true))
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeNode, nodeNLRIValue(2, remoteSubs)), tlv16(tlvNodeName, []byte("leaf1")), true))
	// Link NLRI A→B.
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeLink, linkNLRIValue(2, localSubs, remoteSubs, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2})), nil, true))

	c.mu.RLock()
	links := c.buildLinks()
	c.mu.RUnlock()
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d: %+v", len(links), links)
	}
	l := links[0]
	if l.Proto != "bgp_ls" || l.IGP != "isis-l2" {
		t.Errorf("proto/igp = %q/%q", l.Proto, l.IGP)
	}
	if l.LocalName != "spine1" || l.RemSysName != "leaf1" {
		t.Errorf("hostnames = %q/%q, want spine1/leaf1 (node↔link join)", l.LocalName, l.RemSysName)
	}
	if l.LocalPort != "10.0.0.1" || l.RemPort != "10.0.0.2" {
		t.Errorf("ifaces = %q/%q", l.LocalPort, l.RemPort)
	}

	// Withdraw the link → it disappears from the built set.
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeLink, linkNLRIValue(2, localSubs, remoteSubs, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2})), nil, false))
	c.mu.RLock()
	links = c.buildLinks()
	c.mu.RUnlock()
	if len(links) != 0 {
		t.Fatalf("withdraw should remove the link; got %+v", links)
	}
}

// OSPF parity: a customer not running IS-IS gets the same graph. Protocol-ID 3
// (OSPFv2) with a 4-octet Router-ID renders a dotted name and igp=ospfv2, with no
// Node NLRI required (System-ID falls back from the link descriptors).
func TestApplyUpdate_OSPF(t *testing.T) {
	c := NewBGPLS().(*bgplsCollector)
	peer := "10.0.0.9:179"
	local := append(tlv16(subTLVAutonomousSystem, u32b(65001)), tlv16(subTLVIGPRouterID, []byte{10, 0, 0, 1})...)
	remote := append(tlv16(subTLVAutonomousSystem, u32b(65001)), tlv16(subTLVIGPRouterID, []byte{10, 0, 0, 2})...)
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeLink, linkNLRIValue(3, local, remote, []byte{172, 16, 0, 1}, []byte{172, 16, 0, 2})), nil, true))

	c.mu.RLock()
	links := c.buildLinks()
	c.mu.RUnlock()
	if len(links) != 1 {
		t.Fatalf("want 1 OSPF link, got %d: %+v", len(links), links)
	}
	if links[0].IGP != "ospfv2" {
		t.Errorf("igp = %q, want ospfv2", links[0].IGP)
	}
	if links[0].LocalName != "10.0.0.1" || links[0].RemSysName != "10.0.0.2" {
		t.Errorf("OSPF endpoints = %q/%q, want dotted Router-IDs (System-ID fallback)", links[0].LocalName, links[0].RemSysName)
	}
}

// buildOpen must advertise BGP-LS multiprotocol + 4-octet-AS and parse back its
// own hold time.
func TestBuildOpen(t *testing.T) {
	open := buildOpen(65000, [4]byte{10, 0, 0, 1}, 90)
	if open[0] != bgpVersion {
		t.Errorf("version = %d, want 4", open[0])
	}
	if hold, ok := parseOpenHoldTime(open); !ok || hold != 90 {
		t.Errorf("hold-time round-trip = %d,%v", hold, ok)
	}
	// the optional-parameter block should contain the LS AFI (16388) somewhere.
	found := false
	for i := 0; i+1 < len(open); i++ {
		if binary.BigEndian.Uint16(open[i:i+2]) == afiBGPLS {
			found = true
			break
		}
	}
	if !found {
		t.Error("OPEN must advertise the BGP-LS AFI 16388 capability")
	}
}

// A malformed (truncated) NLRI must never panic and must yield nothing.
func TestParseLSNLRIs_Truncated(t *testing.T) {
	if got := parseLSNLRIs([]byte{0x00, 0x02, 0x00, 0xff, 0x01}); len(got) != 0 {
		t.Errorf("truncated NLRI should parse to nothing; got %+v", got)
	}
}
