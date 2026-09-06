// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// u24b packs a 24-bit value big-endian (SRGB range / 3-octet MPLS label).
func u24b(v uint32) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

// srCapsTLV builds an SR Capabilities (1034) BGP-LS attribute TLV (RFC 9085
// §2.1.2): Flags(1) Reserved(1) Range(3) + SID/Label sub-TLV(1161). idxOrLabel
// is the SRGB base; pass a 4-byte value for an index, 3-byte for a label.
func srCapsTLV(rangeSize uint32, baseSID []byte) []byte {
	v := []byte{0x00, 0x00} // flags + reserved
	v = append(v, u24b(rangeSize)...)
	v = append(v, tlv16(subTLVSIDLabel, baseSID)...)
	return tlv16(tlvSRCapabilities, v)
}

// srAlgoTLV builds an SR Algorithm (1035) TLV: one octet per algorithm.
func srAlgoTLV(algos ...byte) []byte { return tlv16(tlvSRAlgorithm, algos) }

// sidFlaggedTLV builds a Prefix-SID / Adjacency-SID value: two leading octets
// (Flags + Algorithm/Weight) + Reserved(2) + SID/Index/Label. sid 4 bytes = index.
func sidFlaggedTLV(typ uint16, sid []byte) []byte {
	v := []byte{0x00, 0x00, 0x00, 0x00} // flags + algo/weight + reserved(2)
	v = append(v, sid...)
	return tlv16(typ, v)
}

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

// ---- TASK 1: origin-node → prefix join (NODE metadata, never a link) --------

// A prefix NLRI must bind to its ORIGIN node by the descriptor key, appear in the
// node's published OriginatedPrefixes, survive on a node that is present, be
// removed on withdraw, and NEVER show up as an adjacency/link.
func TestPrefixBindsToOriginNode(t *testing.T) {
	c := NewBGPLS().(*bgplsCollector)
	peer := "10.0.0.9:179"
	subs := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})

	// Origin node (spine1) + a prefix it originates (10.0.0.0/24).
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeNode, nodeNLRIValue(2, subs)), tlv16(tlvNodeName, []byte("spine1")), true))
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeIPv4Prefix, prefixNLRIValue(2, subs, 24, []byte{10, 0, 0})), nil, true))

	c.mu.RLock()
	nodes := c.buildNodes()
	links := c.buildLinks()
	c.mu.RUnlock()

	// HARD CONSTRAINT: a prefix must NEVER become a link.
	if len(links) != 0 {
		t.Fatalf("prefix must not create any adjacency/link; got %d: %+v", len(links), links)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Name != "spine1" {
		t.Errorf("node name = %q, want spine1 (descriptor-key join)", nodes[0].Name)
	}
	if len(nodes[0].OriginatedPrefixes) != 1 || nodes[0].OriginatedPrefixes[0] != "10.0.0.0/24" {
		t.Fatalf("origin prefixes = %v, want [10.0.0.0/24]", nodes[0].OriginatedPrefixes)
	}

	// Withdraw the prefix → it leaves the origin node; the node remains; still no links.
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeIPv4Prefix, prefixNLRIValue(2, subs, 24, []byte{10, 0, 0})), nil, false))
	c.mu.RLock()
	nodes = c.buildNodes()
	links = c.buildLinks()
	c.mu.RUnlock()
	if len(links) != 0 {
		t.Fatalf("withdraw of a prefix must not touch links; got %+v", links)
	}
	if len(nodes) != 1 {
		t.Fatalf("origin node must survive prefix withdraw; got %d nodes", len(nodes))
	}
	if len(nodes[0].OriginatedPrefixes) != 0 {
		t.Errorf("withdrawn prefix must be removed from origin node; got %v", nodes[0].OriginatedPrefixes)
	}
}

// ---- TASK 2: Segment-Routing BGP-LS attribute decode (RFC 9085) -------------

// SR Capabilities (1034) + SR Algorithm (1035) on the NODE attribute decode to
// SRGB base + range and the first algorithm.
func TestSRNodeAttributes(t *testing.T) {
	c := NewBGPLS().(*bgplsCollector)
	peer := "10.0.0.9:179"
	subs := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})

	// SRGB base index 16000, range 8000; SR Algorithm 0 (SPF).
	attr := tlv16(tlvNodeName, []byte("spine1"))
	attr = append(attr, srCapsTLV(8000, u32b(16000))...)
	attr = append(attr, srAlgoTLV(0)...)
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeNode, nodeNLRIValue(2, subs)), attr, true))

	c.mu.RLock()
	rib := c.ribs[peer]
	var n *lsNode
	for _, node := range rib.nodes {
		n = node
	}
	c.mu.RUnlock()
	if n == nil {
		t.Fatal("node not present")
	}
	if n.srgbBase != 16000 || n.srgbRange != 8000 {
		t.Errorf("SRGB = base %d range %d, want base 16000 range 8000", n.srgbBase, n.srgbRange)
	}
	if n.srAlgo != 0 {
		t.Errorf("SR algorithm = %d, want 0 (SPF)", n.srAlgo)
	}
}

// Prefix-SID (1158) on the PREFIX attribute decodes the SID index.
func TestSRPrefixSID(t *testing.T) {
	c := NewBGPLS().(*bgplsCollector)
	peer := "10.0.0.9:179"
	subs := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})

	attr := sidFlaggedTLV(tlvPrefixSID, u32b(101)) // Prefix-SID index 101
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeIPv4Prefix, prefixNLRIValue(2, subs, 32, []byte{10, 1, 1, 1})), attr, true))

	c.mu.RLock()
	rib := c.ribs[peer]
	var p *lsPrefix
	for _, pf := range rib.prefixes {
		p = pf
	}
	c.mu.RUnlock()
	if p == nil {
		t.Fatal("prefix not present")
	}
	if p.prefixSID != 101 {
		t.Errorf("Prefix-SID = %d, want 101", p.prefixSID)
	}
}

// Adjacency-SID (1099) on the LINK attribute decodes the SID.
func TestSRAdjacencySID(t *testing.T) {
	c := NewBGPLS().(*bgplsCollector)
	peer := "10.0.0.9:179"
	local := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 1})
	remote := isisNodeDescSubs(65000, []byte{0, 0, 0, 0, 0, 2})

	attr := sidFlaggedTLV(tlvAdjSID, u32b(24001)) // Adjacency-SID 24001
	c.applyUpdate(peer, updateBody(lsNLRIWrap(nlriTypeLink, linkNLRIValue(2, local, remote, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2})), attr, true))

	c.mu.RLock()
	rib := c.ribs[peer]
	var l *lsLink
	for _, lk := range rib.links {
		l = lk
	}
	c.mu.RUnlock()
	if l == nil {
		t.Fatal("link not present")
	}
	if l.adjSID != 24001 {
		t.Errorf("Adjacency-SID = %d, want 24001", l.adjSID)
	}
}

// A 3-octet MPLS-label SRGB base decodes (masked to 20 bits), exercising the
// label encoding path alongside the index path above.
func TestSRCapabilitiesLabelEncoding(t *testing.T) {
	base, rng, ok := parseSRCapabilities(append([]byte{0x00, 0x00}, append(u24b(1000), tlv16(subTLVSIDLabel, u24b(16000))...)...))
	if !ok {
		t.Fatal("SR Capabilities (label encoding) failed to parse")
	}
	if base != 16000 || rng != 1000 {
		t.Errorf("SRGB label-encoded = base %d range %d, want base 16000 range 1000", base, rng)
	}
}

// Truncation safety: a short/truncated SR TLV must not panic, must be skipped,
// and the rest of the attribute (here the Node Name) must still parse.
func TestSRTruncationSafe(t *testing.T) {
	// SR Capabilities TLV truncated to 1 byte (claims a longer body), followed by a
	// valid Node Name TLV. applyNodeAttr must skip the SR TLV but read the name.
	truncSR := tlv16(tlvSRCapabilities, []byte{0x00}) // too short for flags+reserved+range
	attr := append(truncSR, tlv16(tlvNodeName, []byte("leaf9"))...)

	n := &lsNode{srAlgo: -1}
	applyNodeAttr(n, attr) // must not panic
	if n.srgbBase != 0 || n.srgbRange != 0 {
		t.Errorf("truncated SR Caps must yield no SRGB; got base %d range %d", n.srgbBase, n.srgbRange)
	}
	if n.hostname != "leaf9" {
		t.Errorf("attribute walk must continue past a truncated SR TLV; hostname = %q, want leaf9", n.hostname)
	}

	// A short Prefix-SID / Adjacency-SID value must be skipped, not panic.
	p := &lsPrefix{}
	applyPrefixAttr(p, tlv16(tlvPrefixSID, []byte{0x00, 0x00})) // < 4 leading octets
	if p.prefixSID != 0 {
		t.Errorf("short Prefix-SID must be skipped; got %d", p.prefixSID)
	}
	l := &lsLink{}
	applyLinkAttr(l, tlv16(tlvAdjSID, []byte{0x00, 0x00, 0x00})) // 3 octets, no SID
	if l.adjSID != 0 {
		t.Errorf("short Adjacency-SID must be skipped; got %d", l.adjSID)
	}
}
