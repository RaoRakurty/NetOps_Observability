package collectors

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// bgpls.go — BGP Link-State (BGP-LS, RFC 7752 / RFC 9552) topology discovery.
//
// Unlike LLDP/CDP (per-device SNMP MIB walks of an adjacency table), the IGP
// link-state database — the actual "who connects to whom" graph — has no useful
// SNMP MIB. The standard way to ship it to a central collector is BGP-LS: a
// router (typically a route-reflector or a single export speaker) is told to
// `distribute link-state`, which redistributes its IS-IS (or OSPF) LSDB into the
// BGP Link-State address family (AFI 16388 / SAFI 71), and advertises it to us
// over a normal iBGP session. We therefore run a **receive-only BGP speaker**:
// open a TCP/179 session, negotiate the Link-State capability, and decode the
// Node + Link NLRI we receive into the same topology link shape LLDP/CDP publish
// (Proto="bgp_ls"), so the API merges all three sources transparently.
//
// Receive-only / zero-trust: we never advertise NLRI (no RIB-out, no UPDATE with
// reachable routes), we treat every byte from the peer as untrusted (bounded
// reads, length-checked TLV walks that never run past the slice), and the whole
// collector is dormant unless ENABLE_BGPLS_DISCOVERY=true with BGPLS_PEERS set.
// Stdlib only: net.DialTimeout over TCP + hand-rolled BGP framing. No GoBGP, no
// gRPC, no new module (keeps go.mod dependency-free per CLAUDE.md §6).
//
// IS-IS LSDB specifics (the lab's IGP): the IGP Router-ID node-descriptor sub-TLV
// (515) carries the 6-octet ISO System-ID (7 with a pseudonode PSN byte), which
// we render canonically as "0000.0000.0001"; Protocol-ID 1/2 distinguishes
// IS-IS Level-1/Level-2; the node Hostname TLV (1026) in the BGP-LS attribute
// gives the display name we resolve against inventory.

const (
	bgpPort      = 179
	bgpMarkerLen = 16
	bgpHeaderLen = 19    // 16 marker + 2 length + 1 type
	bgpMaxMsg    = 65535 // BGP message length ceiling (RFC 4271 §4.1)
	bgpVersion   = 4

	// BGP message types (RFC 4271 §4.1).
	msgOpen         = 1
	msgUpdate       = 2
	msgNotification = 3
	msgKeepalive    = 4

	// Path-attribute type codes.
	attrMPReachNLRI   = 14 // RFC 4760
	attrMPUnreachNLRI = 15 // RFC 4760
	attrBGPLS         = 29 // RFC 7752/9552 BGP-LS Attribute (IANA-confirmed; NOT 40)

	// Address family for Link-State (RFC 7752 §3.1).
	afiBGPLS  = 16388
	safiBGPLS = 71

	// OPEN optional-parameter + capability codes.
	optParamCapability = 2
	capMultiprotocol   = 1  // RFC 4760
	capFourOctetAS     = 65 // RFC 6793
	asTrans            = 23456

	// Link-State NLRI types (RFC 7752 §3.2).
	nlriTypeNode       = 1
	nlriTypeLink       = 2
	nlriTypeIPv4Prefix = 3
	nlriTypeIPv6Prefix = 4

	// Node / link descriptor TLVs (RFC 7752 §3.2.1).
	tlvLocalNodeDesc  = 256
	tlvRemoteNodeDesc = 257
	// Node-descriptor sub-TLVs.
	subTLVAutonomousSystem = 512
	subTLVBGPLSID          = 513
	subTLVOSPFAreaID       = 514
	subTLVIGPRouterID      = 515
	// Link-descriptor TLVs.
	tlvLinkLocalRemoteID = 258
	tlvIPv4IfaceAddr     = 259
	tlvIPv4NeighborAddr  = 260
	tlvIPv6IfaceAddr     = 261
	tlvIPv6NeighborAddr  = 262
	// Prefix-descriptor TLV (RFC 7752 §3.2.3): IP Reachability Information.
	tlvIPReachability = 265

	// BGP-LS attribute TLVs (RFC 7752 §3.3).
	tlvNodeName        = 1026
	tlvISISAreaID      = 1027
	tlvIPv4RouterIDLoc = 1028
)

// bgplsProtocolID maps the Link-State NLRI Protocol-ID byte to a label
// (RFC 7752 §3.2). IS-IS levels are the lab's case; OSPF/direct/static rounded out.
func bgplsProtocolID(p byte) string {
	switch p {
	case 1:
		return "isis-l1"
	case 2:
		return "isis-l2"
	case 3:
		return "ospfv2"
	case 4:
		return "direct"
	case 5:
		return "static"
	case 6:
		return "ospfv3"
	default:
		return "igp"
	}
}

type bgplsCollector struct {
	publishEvery time.Duration

	mu     sync.RWMutex
	status Status
	ribs   map[string]*lsRIB // peer addr → that peer's link-state RIB
}

// lsRIB is one peer's accumulated link-state database (kept across UPDATEs;
// withdraws delete; cleared on session loss so a dead peer's topology self-heals).
// Nodes + links build the displayed graph today; prefixes (origin node → prefix)
// are retained for the flow/probe overlay join (which node owns a flow's dst) and
// the forthcoming /api/topology/graph — counted + observable now, not yet surfaced
// as links (the topology link contract is adjacency-only).
type lsRIB struct {
	nodes    map[string]*lsNode   // nodeKey → node
	links    map[string]*lsLink   // linkKey → link
	prefixes map[string]*lsPrefix // prefixKey → prefix
}

type lsPrefix struct {
	key      string
	igp      string
	localKey string // origin node descriptor key
	prefix   string // CIDR (e.g. 10.0.0.0/24)
}

type lsNode struct {
	key      string
	igp      string // isis-l2 / ospfv2 / …
	systemID string // rendered IGP Router-ID (IS-IS "0020.9000.0003" / OSPF dotted)
	area     string
	hostname string // BGP-LS Node Name TLV (1026)
	routerV4 string // IPv4 Router-ID of local node (TLV 1028)
}

type lsLink struct {
	key        string
	igp        string
	localKey   string
	remoteKey  string
	localSysID string // rendered IGP Router-ID of the local endpoint (node-NLRI-independent fallback)
	remSysID   string // rendered IGP Router-ID of the remote endpoint
	localIface string // IPv4 interface address / link-local id
	remIface   string // IPv4 neighbor address / link-remote id
	ts         int64
}

// NewBGPLS builds the receive-only BGP-LS topology collector.
func NewBGPLS() Collector {
	return &bgplsCollector{
		publishEvery: 30 * time.Second,
		status:       Status{Name: "bgpls", Healthy: true, Kind: "discovery"},
		ribs:         map[string]*lsRIB{},
	}
}

func (c *bgplsCollector) Name() string { return "bgpls" }

func (c *bgplsCollector) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// bgplsPeer is one configured BGP-LS exporter to peer with.
type bgplsPeer struct {
	addr   string // host:port
	peerAS uint32
}

// bgplsPeers parses BGPLS_PEERS: comma-separated "host[:port][@peerAS]". Default
// port 179, default peerAS = BGPLS_LOCAL_AS (iBGP to a route-reflector — the
// common BGP-LS deployment, matching the article's peer-as==local-as).
func bgplsPeers() []bgplsPeer {
	raw := strings.TrimSpace(os.Getenv("BGPLS_PEERS"))
	if raw == "" {
		return nil
	}
	localAS := bgplsLocalAS()
	var out []bgplsPeer
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		peerAS := localAS
		if at := strings.LastIndexByte(p, '@'); at >= 0 {
			if v, err := strconv.ParseUint(strings.TrimSpace(p[at+1:]), 10, 32); err == nil {
				peerAS = uint32(v)
			}
			p = strings.TrimSpace(p[:at])
		}
		if p == "" {
			continue
		}
		out = append(out, bgplsPeer{addr: withPort(p, bgpPort), peerAS: peerAS})
	}
	return out
}

func bgplsLocalAS() uint32 {
	if v, err := strconv.ParseUint(strings.TrimSpace(os.Getenv("BGPLS_LOCAL_AS")), 10, 32); err == nil && v > 0 {
		return uint32(v)
	}
	return 65000
}

// bgplsRouterID returns our BGP Identifier as 4 octets (BGPLS_ROUTER_ID dotted
// IPv4; defaults to a stable non-zero id so a peer accepts the OPEN).
func bgplsRouterID() [4]byte {
	if ip := net.ParseIP(strings.TrimSpace(os.Getenv("BGPLS_ROUTER_ID"))); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return [4]byte{v4[0], v4[1], v4[2], v4[3]}
		}
	}
	return [4]byte{169, 254, 0, 1} // link-local sentinel; operators should set a real id
}

func bgplsHoldTime() uint16 {
	if v, err := strconv.ParseUint(strings.TrimSpace(os.Getenv("BGPLS_HOLD_TIME")), 10, 16); err == nil && v >= 3 {
		return uint16(v)
	}
	return 90 // RFC 4271 default
}

func (c *bgplsCollector) Run(ctx context.Context) error {
	peers := bgplsPeers()
	if len(peers) == 0 {
		// Enabled but unconfigured: stay alive + report idle, don't spin.
		c.mu.Lock()
		c.status.Healthy = true
		c.status.LastError = "no BGPLS_PEERS configured"
		c.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	// One session goroutine per peer; a ticker publishes the merged RIB.
	for _, p := range peers {
		go c.runPeer(ctx, p)
	}
	t := time.NewTicker(c.publishEvery)
	defer t.Stop()
	c.publish(ctx, len(peers))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.publish(ctx, len(peers))
		}
	}
}

// runPeer maintains one peer session with reconnect + capped backoff + jitter
// (CLAUDE.md §9). On disconnect the peer's RIB is dropped so stale topology from
// a dead exporter cannot linger.
func (c *bgplsCollector) runPeer(ctx context.Context, p bgplsPeer) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.session(ctx, p)
		c.dropRIB(p.addr)
		if ctx.Err() != nil {
			return
		}
		attempt++
		if err != nil {
			c.setPeerError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(bgplsBackoff(attempt)):
		}
	}
}

// bgplsBackoff is exponential (1→30s) with up to 1s of deterministic jitter
// derived from the clock, so reconnect storms across peers desynchronize without
// pulling in math/rand global state.
func bgplsBackoff(attempt int) time.Duration {
	base := time.Duration(1<<min(attempt, 5)) * time.Second
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	jitter := time.Duration(time.Now().UnixNano()%1000) * time.Millisecond
	return base + jitter
}

// session dials the peer, performs the OPEN/KEEPALIVE handshake, then reads
// UPDATEs into the peer's RIB until the connection drops or the hold timer fires.
func (c *bgplsCollector) session(ctx context.Context, p bgplsPeer) error {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", p.addr)
	cancel()
	if err != nil {
		return fmt.Errorf("dial %s: %w", p.addr, err)
	}
	defer conn.Close()

	hold := bgplsHoldTime()
	if err := writeBGP(conn, msgOpen, buildOpen(bgplsLocalAS(), bgplsRouterID(), hold)); err != nil {
		return err
	}

	// Expect the peer's OPEN; adopt the smaller hold time.
	typ, body, err := readBGP(conn, hold)
	if err != nil {
		return err
	}
	if typ != msgOpen {
		return fmt.Errorf("expected OPEN, got msg type %d", typ)
	}
	if peerHold, ok := parseOpenHoldTime(body); ok && peerHold < hold {
		hold = peerHold
	}
	if err := writeBGP(conn, msgKeepalive, nil); err != nil {
		return err
	}

	// Keepalive sender (the only writer once established → safe alongside reads).
	keepCtx, stopKeep := context.WithCancel(ctx)
	defer stopKeep()
	if hold > 0 {
		go func() {
			t := time.NewTicker(time.Duration(hold/3) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-keepCtx.Done():
					return
				case <-t.C:
					if writeBGP(conn, msgKeepalive, nil) != nil {
						return
					}
				}
			}
		}()
	}

	c.markEstablished(p.addr)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		typ, body, err := readBGP(conn, hold)
		if err != nil {
			return err
		}
		switch typ {
		case msgUpdate:
			c.applyUpdate(p.addr, body)
		case msgNotification:
			return fmt.Errorf("peer NOTIFICATION: %s", notifText(body))
		case msgKeepalive, msgOpen:
			// keepalive resets the read deadline implicitly; ignore late OPEN.
		}
	}
}

// ---- BGP framing -----------------------------------------------------------

// writeBGP frames and sends one BGP message (marker + length + type + body).
func writeBGP(conn net.Conn, typ byte, body []byte) error {
	total := bgpHeaderLen + len(body)
	if total > bgpMaxMsg {
		return errors.New("bgp message too large")
	}
	buf := make([]byte, bgpHeaderLen, total)
	for i := 0; i < bgpMarkerLen; i++ {
		buf[i] = 0xff
	}
	binary.BigEndian.PutUint16(buf[16:18], uint16(total))
	buf[18] = typ
	buf = append(buf, body...)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := conn.Write(buf)
	return err
}

// readBGP reads exactly one BGP message, enforcing the hold-time read deadline
// (0 ⇒ a generous fixed cap so a silent peer can't hang us forever). Validates
// the marker + length bounds before allocating the body.
func readBGP(conn net.Conn, hold uint16) (byte, []byte, error) {
	deadline := 4 * time.Minute
	if hold > 0 {
		deadline = time.Duration(hold) * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(deadline))

	hdr := make([]byte, bgpHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	for i := 0; i < bgpMarkerLen; i++ {
		if hdr[i] != 0xff {
			return 0, nil, errors.New("bad BGP marker")
		}
	}
	length := int(binary.BigEndian.Uint16(hdr[16:18]))
	if length < bgpHeaderLen || length > bgpMaxMsg {
		return 0, nil, fmt.Errorf("bad BGP length %d", length)
	}
	typ := hdr[18]
	body := make([]byte, length-bgpHeaderLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return typ, body, nil
}

// buildOpen encodes an OPEN advertising the Link-State multiprotocol capability
// and 4-octet ASN support. AS_TRANS (23456) goes in the legacy My-AS field when
// the real ASN exceeds 16 bits (RFC 6793).
func buildOpen(localAS uint32, routerID [4]byte, hold uint16) []byte {
	myAS := uint16(localAS)
	if localAS > 0xffff {
		myAS = asTrans
	}

	// Capability: Multiprotocol (AFI 16388 / SAFI 71): AFI(2) res(1) SAFI(1).
	mp := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint16(mp[0:2], afiBGPLS)
	mp[3] = safiBGPLS
	capMP := tlv8(capMultiprotocol, mp)

	// Capability: 4-octet ASN.
	as4 := make([]byte, 4)
	binary.BigEndian.PutUint32(as4, localAS)
	capAS4 := tlv8(capFourOctetAS, as4)

	caps := append(capMP, capAS4...)
	optParam := tlv8(optParamCapability, caps) // optional-parameter wrapping the capabilities

	b := make([]byte, 0, 10+len(optParam))
	b = append(b, bgpVersion)
	b = appendU16(b, myAS)
	b = appendU16(b, hold)
	b = append(b, routerID[0], routerID[1], routerID[2], routerID[3])
	b = append(b, byte(len(optParam)))
	b = append(b, optParam...)
	return b
}

// tlv8 builds a 1-byte-type, 1-byte-length TLV (BGP capability / opt-param shape).
func tlv8(typ byte, val []byte) []byte {
	out := make([]byte, 0, 2+len(val))
	out = append(out, typ, byte(len(val)))
	return append(out, val...)
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// parseOpenHoldTime extracts the hold-time from a peer OPEN body. version(1)
// myAS(2) hold(2) bgpid(4) optlen(1) …
func parseOpenHoldTime(b []byte) (uint16, bool) {
	if len(b) < 10 {
		return 0, false
	}
	return binary.BigEndian.Uint16(b[3:5]), true
}

func notifText(b []byte) string {
	if len(b) < 2 {
		return "malformed"
	}
	return fmt.Sprintf("code=%d subcode=%d", b[0], b[1])
}

// ---- UPDATE / Link-State NLRI parsing --------------------------------------

// applyUpdate parses one UPDATE and folds its reachable Link-State NLRI into the
// peer's RIB (and removes withdrawn NLRI). Wholly defensive: any malformed
// length stops the walk for that structure without panicking.
func (c *bgplsCollector) applyUpdate(peer string, body []byte) {
	if len(body) < 4 {
		return
	}
	wrLen := int(binary.BigEndian.Uint16(body[0:2]))
	off := 2 + wrLen // skip IPv4 withdrawn routes (none expected on an LS-only session)
	if off+2 > len(body) {
		return
	}
	taLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+taLen > len(body) {
		return
	}
	attrs := body[off : off+taLen]

	reach, unreach, lsAttr := splitLSAttributes(attrs)
	now := time.Now().UnixMilli()

	c.mu.Lock()
	defer c.mu.Unlock()
	rib := c.ribs[peer]
	if rib == nil {
		rib = &lsRIB{nodes: map[string]*lsNode{}, links: map[string]*lsLink{}, prefixes: map[string]*lsPrefix{}}
		c.ribs[peer] = rib
	}
	for _, n := range parseLSNLRIs(reach) {
		switch n.kind {
		case nlriTypeNode:
			node := &lsNode{key: n.localKey, igp: n.igp, systemID: n.localSysID, area: n.area}
			applyNodeAttr(node, lsAttr)
			rib.nodes[node.key] = node
		case nlriTypeLink:
			rib.links[n.linkKey] = &lsLink{
				key: n.linkKey, igp: n.igp,
				localKey: n.localKey, remoteKey: n.remoteKey,
				localSysID: n.localSysID, remSysID: n.remoteSysID,
				localIface: n.localIface, remIface: n.remIface, ts: now,
			}
		case nlriTypeIPv4Prefix, nlriTypeIPv6Prefix:
			rib.prefixes[n.prefixKey] = &lsPrefix{
				key: n.prefixKey, igp: n.igp, localKey: n.localKey, prefix: n.prefix,
			}
		}
	}
	for _, n := range parseLSNLRIs(unreach) {
		switch n.kind {
		case nlriTypeNode:
			delete(rib.nodes, n.localKey)
		case nlriTypeLink:
			delete(rib.links, n.linkKey)
		case nlriTypeIPv4Prefix, nlriTypeIPv6Prefix:
			delete(rib.prefixes, n.prefixKey)
		}
	}
}

// splitLSAttributes walks the path-attribute block and returns the Link-State
// NLRI bytes from MP_REACH (14) and MP_UNREACH (15) plus the BGP-LS attribute
// (29) TLV bytes. It strips the MP_REACH/UNREACH AFI/SAFI (+ next-hop) headers.
func splitLSAttributes(attrs []byte) (reach, unreach, lsAttr []byte) {
	i := 0
	for i+2 <= len(attrs) {
		flags := attrs[i]
		typ := attrs[i+1]
		i += 2
		var alen int
		if flags&0x10 != 0 { // Extended-Length
			if i+2 > len(attrs) {
				return
			}
			alen = int(binary.BigEndian.Uint16(attrs[i : i+2]))
			i += 2
		} else {
			if i+1 > len(attrs) {
				return
			}
			alen = int(attrs[i])
			i++
		}
		if i+alen > len(attrs) {
			return
		}
		val := attrs[i : i+alen]
		i += alen
		switch typ {
		case attrMPReachNLRI:
			// AFI(2) SAFI(1) nexthoplen(1) nexthop(n) reserved(1) NLRI…
			if len(val) >= 5 {
				nhLen := int(val[3])
				p := 4 + nhLen + 1 // + reserved byte
				if p <= len(val) {
					reach = val[p:]
				}
			}
		case attrMPUnreachNLRI:
			// AFI(2) SAFI(1) NLRI…
			if len(val) >= 3 {
				unreach = val[3:]
			}
		case attrBGPLS:
			lsAttr = val
		}
	}
	return
}

// lsNLRI is a decoded Link-State NLRI (node, link, or prefix).
type lsNLRI struct {
	kind        int
	igp         string
	localKey    string
	remoteKey   string
	localSysID  string
	remoteSysID string
	area        string
	localIface  string
	remIface    string
	linkKey     string
	prefix      string // CIDR (prefix NLRI)
	prefixKey   string
}

// parseLSNLRIs walks a sequence of Link-State NLRIs: Type(2) Length(2) Value.
func parseLSNLRIs(b []byte) []lsNLRI {
	var out []lsNLRI
	i := 0
	for i+4 <= len(b) {
		typ := int(binary.BigEndian.Uint16(b[i : i+2]))
		l := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+l > len(b) {
			break
		}
		val := b[i : i+l]
		i += l
		switch typ {
		case nlriTypeNode:
			if n, ok := parseNodeNLRI(val); ok {
				out = append(out, n)
			}
		case nlriTypeLink:
			if n, ok := parseLinkNLRI(val); ok {
				out = append(out, n)
			}
		case nlriTypeIPv4Prefix, nlriTypeIPv6Prefix:
			if n, ok := parsePrefixNLRI(val, typ); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// parsePrefixNLRI: Protocol-ID(1) Identifier(8) Local-Node-Descriptors(256)
// Prefix-Descriptors. We extract the originating node + the IP Reachability TLV
// (265): prefix-length(1) + ceil(len/8) packed address octets → CIDR.
func parsePrefixNLRI(val []byte, nlriType int) (lsNLRI, bool) {
	if len(val) < 9 {
		return lsNLRI{}, false
	}
	igp := bgplsProtocolID(val[0])
	rest := val[9:]
	local, after, ok := readTLV16(rest, tlvLocalNodeDesc)
	if !ok {
		return lsNLRI{}, false
	}
	ln := parseNodeDescriptor(local, igp)
	cidr := parsePrefixReach(after, nlriType)
	if cidr == "" {
		return lsNLRI{}, false
	}
	return lsNLRI{
		kind: nlriType, igp: igp, localKey: ln.key,
		prefix: cidr, prefixKey: ln.key + "|" + cidr,
	}, true
}

// parsePrefixReach finds the IP Reachability TLV (265) in the prefix-descriptors
// and renders it as a CIDR. v4 vs v6 follows the NLRI type.
func parsePrefixReach(b []byte, nlriType int) string {
	i := 0
	for i+4 <= len(b) {
		t := int(binary.BigEndian.Uint16(b[i : i+2]))
		l := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+l > len(b) {
			break
		}
		v := b[i : i+l]
		i += l
		if t != tlvIPReachability || len(v) < 1 {
			continue
		}
		bits := int(v[0])
		packed := v[1:]
		size := 4
		if nlriType == nlriTypeIPv6Prefix {
			size = 16
		}
		if bits < 0 || bits > size*8 || len(packed) > size {
			return ""
		}
		full := make([]byte, size)
		copy(full, packed) // left-justified, trailing zeros (RFC 7752 §3.2.3.2)
		return fmt.Sprintf("%s/%d", net.IP(full).String(), bits)
	}
	return ""
}

// parseNodeNLRI: Protocol-ID(1) Identifier(8) Local-Node-Descriptors TLV(256).
func parseNodeNLRI(val []byte) (lsNLRI, bool) {
	if len(val) < 9 {
		return lsNLRI{}, false
	}
	igp := bgplsProtocolID(val[0])
	rest := val[9:]
	local, _, ok := readTLV16(rest, tlvLocalNodeDesc)
	if !ok {
		return lsNLRI{}, false
	}
	nd := parseNodeDescriptor(local, igp)
	return lsNLRI{
		kind: nlriTypeNode, igp: igp,
		localKey: nd.key, localSysID: nd.sysID, area: nd.area,
	}, true
}

// parseLinkNLRI: Protocol-ID(1) Identifier(8) Local(256) Remote(257) Link-descriptors.
func parseLinkNLRI(val []byte) (lsNLRI, bool) {
	if len(val) < 9 {
		return lsNLRI{}, false
	}
	igp := bgplsProtocolID(val[0])
	rest := val[9:]
	local, after, ok := readTLV16(rest, tlvLocalNodeDesc)
	if !ok {
		return lsNLRI{}, false
	}
	remote, after2, ok := readTLV16(after, tlvRemoteNodeDesc)
	if !ok {
		return lsNLRI{}, false
	}
	ln := parseNodeDescriptor(local, igp)
	rn := parseNodeDescriptor(remote, igp)
	li, ri := parseLinkDescriptors(after2)
	return lsNLRI{
		kind: nlriTypeLink, igp: igp,
		localKey: ln.key, remoteKey: rn.key,
		localSysID: ln.sysID, remoteSysID: rn.sysID,
		localIface: li, remIface: ri,
		linkKey: ln.key + "|" + rn.key + "|" + li + "|" + ri,
	}, true
}

type nodeDescriptor struct {
	key   string // canonical identity (proto + descriptor bytes)
	sysID string // rendered IGP Router-ID
	area  string
}

// parseNodeDescriptor walks node-descriptor sub-TLVs and builds a canonical key.
// The key includes the IGP plus a stable hex of the sorted sub-TLVs, so the same
// node referenced from a Node NLRI and from a Link NLRI's local/remote descriptor
// hashes identically (enabling the node↔link join).
func parseNodeDescriptor(b []byte, igp string) nodeDescriptor {
	var sysID, area string
	type kv struct {
		t int
		v []byte
	}
	var subs []kv
	i := 0
	for i+4 <= len(b) {
		t := int(binary.BigEndian.Uint16(b[i : i+2]))
		l := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+l > len(b) {
			break
		}
		v := b[i : i+l]
		i += l
		subs = append(subs, kv{t, v})
		switch t {
		case subTLVIGPRouterID:
			sysID = renderIGPRouterID(v, igp)
		case subTLVOSPFAreaID:
			if len(v) == 4 {
				area = net.IP(v).String()
			}
		}
	}
	sort.Slice(subs, func(a, c int) bool {
		if subs[a].t != subs[c].t {
			return subs[a].t < subs[c].t
		}
		return string(subs[a].v) < string(subs[c].v)
	})
	var sb strings.Builder
	sb.WriteString(igp)
	for _, s := range subs {
		fmt.Fprintf(&sb, "|%d:%s", s.t, hex.EncodeToString(s.v))
	}
	return nodeDescriptor{key: sb.String(), sysID: sysID, area: area}
}

// renderIGPRouterID formats the IGP Router-ID sub-TLV per the protocol
// (RFC 7752 §3.2.1.4). IS-IS: 6-octet System-ID "0020.9000.0003" (7th PSN octet
// appended as ".NN" for a pseudonode). OSPF: 4-octet dotted Router-ID.
func renderIGPRouterID(v []byte, igp string) string {
	switch {
	case strings.HasPrefix(igp, "isis"):
		if len(v) >= 6 {
			id := fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x", v[0], v[1], v[2], v[3], v[4], v[5])
			if len(v) >= 7 && v[6] != 0 {
				id += fmt.Sprintf(".%02d", v[6])
			}
			return id
		}
	case len(v) == 4: // OSPFv2 Router-ID
		return net.IP(v).String()
	case len(v) == 8: // OSPF pseudonode: Router-ID + DR interface
		return net.IP(v[0:4]).String() + ":" + net.IP(v[4:8]).String()
	}
	return hex.EncodeToString(v)
}

// parseLinkDescriptors pulls the most useful interface identifiers from the
// link-descriptor TLVs: IPv4 interface/neighbor address, else link-local/remote id.
func parseLinkDescriptors(b []byte) (localIface, remIface string) {
	i := 0
	for i+4 <= len(b) {
		t := int(binary.BigEndian.Uint16(b[i : i+2]))
		l := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+l > len(b) {
			break
		}
		v := b[i : i+l]
		i += l
		switch t {
		case tlvIPv4IfaceAddr:
			if len(v) == 4 {
				localIface = net.IP(v).String()
			}
		case tlvIPv4NeighborAddr:
			if len(v) == 4 {
				remIface = net.IP(v).String()
			}
		case tlvLinkLocalRemoteID:
			if len(v) == 8 {
				if localIface == "" {
					localIface = "link " + strconv.FormatUint(uint64(binary.BigEndian.Uint32(v[0:4])), 10)
				}
				if remIface == "" {
					remIface = "link " + strconv.FormatUint(uint64(binary.BigEndian.Uint32(v[4:8])), 10)
				}
			}
		}
	}
	return
}

// applyNodeAttr enriches a node from the BGP-LS attribute TLVs (hostname, IS-IS
// area, IPv4 Router-ID).
func applyNodeAttr(n *lsNode, attr []byte) {
	i := 0
	for i+4 <= len(attr) {
		t := int(binary.BigEndian.Uint16(attr[i : i+2]))
		l := int(binary.BigEndian.Uint16(attr[i+2 : i+4]))
		i += 4
		if i+l > len(attr) {
			break
		}
		v := attr[i : i+l]
		i += l
		switch t {
		case tlvNodeName:
			if s := strings.TrimSpace(string(v)); s != "" {
				n.hostname = s
			}
		case tlvISISAreaID:
			if n.area == "" && len(v) > 0 {
				n.area = hex.EncodeToString(v)
			}
		case tlvIPv4RouterIDLoc:
			if len(v) == 4 {
				n.routerV4 = net.IP(v).String()
			}
		}
	}
}

// readTLV16 reads a 2-byte-type/2-byte-length TLV at the head of b, requiring it
// to be of wantType. Returns (value, remaining-after-tlv, ok).
func readTLV16(b []byte, wantType int) (val, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, b, false
	}
	t := int(binary.BigEndian.Uint16(b[0:2]))
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if t != wantType || 4+l > len(b) {
		return nil, b, false
	}
	return b[4 : 4+l], b[4+l:], true
}

// ---- RIB → topology links + publish ----------------------------------------

func (c *bgplsCollector) dropRIB(peer string) {
	c.mu.Lock()
	delete(c.ribs, peer)
	c.mu.Unlock()
}

func (c *bgplsCollector) markEstablished(peer string) {
	c.mu.Lock()
	c.status.LastError = ""
	c.status.Healthy = true
	c.mu.Unlock()
	_ = peer
}

func (c *bgplsCollector) setPeerError(err error) {
	c.mu.Lock()
	c.status.LastError = err.Error()
	c.mu.Unlock()
}

// publish merges every peer's RIB into the shared topology link shape and writes
// it to Redis (replace, TTL-expiring — ADR 0001 share-via-Redis, same as LLDP).
func (c *bgplsCollector) publish(ctx context.Context, peerCount int) {
	c.mu.RLock()
	links := c.buildLinks()
	established, nodeCount, prefixCount := 0, 0, 0
	for _, rib := range c.ribs {
		established++
		nodeCount += len(rib.nodes)
		prefixCount += len(rib.prefixes)
	}
	c.mu.RUnlock()

	if links == nil {
		links = []LLDPNeighbor{} // store "[]" not "null"
	}
	if b, err := json.Marshal(links); err == nil {
		_ = redisSetEX(ctx, topoLinksKeyBGPLS, string(b), 1800)
	}
	// C7.5: directed forwarding pairs from SPF over the LSDB → the routing-direction
	// source. Computed under the same read lock as buildLinks (no re-lock).
	c.mu.RLock()
	pairs := c.buildRoutingPairs()
	c.mu.RUnlock()
	if pairs == nil {
		pairs = []RoutingPair{}
	}
	if b, err := json.Marshal(pairs); err == nil {
		_ = redisSetEX(ctx, routingDirKey, string(b), 1800)
	}

	now := time.Now().UnixMilli()
	emitMetrics(ctx, strings.Join([]string{
		fmt.Sprintf(`collector_up{collector="bgpls"} 1 %d`, now),
		fmt.Sprintf(`collector_targets{collector="bgpls"} %d %d`, peerCount, now),
		fmt.Sprintf(`collector_targets_reachable{collector="bgpls"} %d %d`, established, now),
		fmt.Sprintf(`collector_bgpls_links{collector="bgpls"} %d %d`, len(links), now),
		fmt.Sprintf(`collector_bgpls_nodes{collector="bgpls"} %d %d`, nodeCount, now),
		fmt.Sprintf(`collector_bgpls_prefixes{collector="bgpls"} %d %d`, prefixCount, now),
	}, "\n"))

	c.mu.Lock()
	c.status.LastTick = time.Now().UTC()
	c.status.Targets = peerCount
	c.status.Reachable = established
	c.status.Healthy = true
	c.mu.Unlock()
}

// buildRoutingPairs builds the undirected node-name graph from every peer RIB and
// runs SPF (forwardingPairs) to derive DIRECTED forwarding pairs for the C7.5
// routing-direction source. Caller holds the read lock. Node names are resolved the
// same way as buildLinks (bgplsNodeName: hostname → system-id), so they match the
// correlation device entities. No I/O. Empty graph → no pairs (source abstains).
func (c *bgplsCollector) buildRoutingPairs() []RoutingPair {
	nodes := map[string]*lsNode{}
	for _, rib := range c.ribs {
		for k, n := range rib.nodes {
			nodes[k] = n
		}
	}
	adj := map[string][]string{}
	nameSet := map[string]bool{}
	seenEdge := map[string]bool{}
	for _, rib := range c.ribs {
		for _, l := range rib.links {
			ln := bgplsNodeName(nodes[l.localKey], l.localKey, l.localSysID)
			rn := bgplsNodeName(nodes[l.remoteKey], l.remoteKey, l.remSysID)
			if ln == "" || rn == "" || ln == rn {
				continue
			}
			if seenEdge[ln+"\x00"+rn] || seenEdge[rn+"\x00"+ln] {
				continue // undirected dedup (each link is advertised from both ends)
			}
			seenEdge[ln+"\x00"+rn] = true
			adj[ln] = append(adj[ln], rn)
			adj[rn] = append(adj[rn], ln)
			nameSet[ln], nameSet[rn] = true, true
		}
	}
	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	return forwardingPairs(names, adj)
}

// buildLinks joins links to nodes (for hostnames/router-ids) across all peer
// RIBs and emits one LLDPNeighbor per link. Caller holds the read lock. Pure of
// I/O; the node-name resolution to managed devices happens API-side.
func (c *bgplsCollector) buildLinks() []LLDPNeighbor {
	// Union nodes across peers (last writer wins; topology is global).
	nodes := map[string]*lsNode{}
	for _, rib := range c.ribs {
		for k, n := range rib.nodes {
			nodes[k] = n
		}
	}
	seen := map[string]bool{}
	var out []LLDPNeighbor
	for _, rib := range c.ribs {
		for _, l := range rib.links {
			if seen[l.key] {
				continue
			}
			seen[l.key] = true
			ln := nodes[l.localKey]
			rn := nodes[l.remoteKey]
			out = append(out, LLDPNeighbor{
				LocalName:  bgplsNodeName(ln, l.localKey, l.localSysID),
				LocalAddr:  nodeAddr(ln),
				LocalPort:  l.localIface,
				RemSysName: bgplsNodeName(rn, l.remoteKey, l.remSysID),
				RemChassis: nodeAddr(rn),
				RemPort:    l.remIface,
				Proto:      "bgp_ls",
				IGP:        l.igp,
				Area:       nodeArea(ln),
				TS:         l.ts,
			})
		}
	}
	return out
}

// bgplsNodeName prefers the BGP-LS hostname, then the node's rendered System-ID,
// then the System-ID carried on the link itself (when the Node NLRI hasn't been
// received yet), then a short hash of the descriptor key so a link is never
// anonymous.
func bgplsNodeName(n *lsNode, key, fallbackSysID string) string {
	if n != nil {
		if n.hostname != "" {
			return n.hostname
		}
		if n.systemID != "" {
			return n.systemID
		}
	}
	if fallbackSysID != "" {
		return fallbackSysID
	}
	if i := strings.LastIndexByte(key, ':'); i >= 0 && i+1 < len(key) {
		return "node-" + key[i+1:]
	}
	return "node-" + key
}

func nodeAddr(n *lsNode) string {
	if n != nil {
		return n.routerV4
	}
	return ""
}

func nodeArea(n *lsNode) string {
	if n != nil {
		return n.area
	}
	return ""
}
