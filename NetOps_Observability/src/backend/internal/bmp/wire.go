package bmp

// wire.go — the RFC 7854 frame parser.
//
// Every function here is PURE: bytes in, a value or an error out. There is no
// IO, no clock and no state, which is what makes the fuzz targets meaningful —
// a crash found by the fuzzer is a crash a router could cause.
//
// The single safety primitive is `cursor`, a read head over a fixed slice that
// cannot advance past its end. Nothing in this file indexes a slice directly,
// so there is no path to an out-of-range panic on hostile input, and no length
// field a peer sends is ever used to allocate.

import (
	"errors"
	"fmt"
	"net/netip"
)

// Wire layout constants (RFC 7854 §4).
const (
	// Version is the only BMP version this receiver speaks (RFC 7854).
	Version = 3

	// CommonHeaderLen is version(1) + length(4) + type(1).
	CommonHeaderLen = 6

	// PerPeerHeaderLen is peer type(1) + flags(1) + distinguisher(8) +
	// address(16) + AS(4) + BGP ID(4) + timestamp sec(4) + usec(4).
	PerPeerHeaderLen = 42

	// bgpMarkerLen / bgpHeaderLen are the BGP message framing (RFC 4271 §4.1).
	bgpMarkerLen = 16
	bgpHeaderLen = 19
)

// MsgType is the BMP message type (RFC 7854 §4.1).
type MsgType uint8

// The message types this receiver knows. Anything else is counted as unknown
// and skipped — never guessed at.
const (
	MsgRouteMonitoring  MsgType = 0
	MsgStatisticsReport MsgType = 1
	MsgPeerDown         MsgType = 2
	MsgPeerUp           MsgType = 3
	MsgInitiation       MsgType = 4
	MsgTermination      MsgType = 5
	MsgRouteMirroring   MsgType = 6
)

// String names a message type for metrics labels and logs. An unknown type
// renders as "unknown" rather than a raw number so a hostile peer cannot
// inject unbounded label cardinality into the metrics surface.
func (t MsgType) String() string {
	switch t {
	case MsgRouteMonitoring:
		return "route_monitoring"
	case MsgStatisticsReport:
		return "statistics_report"
	case MsgPeerDown:
		return "peer_down"
	case MsgPeerUp:
		return "peer_up"
	case MsgInitiation:
		return "initiation"
	case MsgTermination:
		return "termination"
	case MsgRouteMirroring:
		return "route_mirroring"
	default:
		return "unknown"
	}
}

// hasPerPeerHeader reports whether a message type is followed by the 42-byte
// per-peer header (RFC 7854 §4.2). Initiation and Termination are not.
func (t MsgType) hasPerPeerHeader() bool {
	switch t {
	case MsgRouteMonitoring, MsgStatisticsReport, MsgPeerDown, MsgPeerUp, MsgRouteMirroring:
		return true
	default:
		return false
	}
}

// Parse errors. They are values, not panics, and each one is COUNTED by the
// caller — a frame we could not read must never look like a frame that said
// "nothing happened".
var (
	// ErrShort means the frame ended inside a field.
	ErrShort = errors.New("bmp: truncated message")
	// ErrVersion means the peer is not speaking BMP version 3.
	ErrVersion = errors.New("bmp: unsupported version")
	// ErrLength means the declared message length is impossible.
	ErrLength = errors.New("bmp: invalid message length")
	// ErrUnsupported means the frame is well-formed but carries something this
	// receiver deliberately does not decode (unknown AFI/SAFI, ADD-PATH NLRI).
	ErrUnsupported = errors.New("bmp: unsupported encoding")
)

// ── the bounded read head ───────────────────────────────────────────────────

// cursor is a read head over a fixed slice. Every accessor checks the bound
// FIRST and returns ErrShort rather than slicing past the end, which is the
// whole reason this parser cannot panic on hostile input.
type cursor struct {
	b []byte
	i int
}

func (c *cursor) remaining() int { return len(c.b) - c.i }

func (c *cursor) u8() (uint8, error) {
	if c.remaining() < 1 {
		return 0, ErrShort
	}
	v := c.b[c.i]
	c.i++
	return v, nil
}

func (c *cursor) u16() (uint16, error) {
	if c.remaining() < 2 {
		return 0, ErrShort
	}
	v := uint16(c.b[c.i])<<8 | uint16(c.b[c.i+1])
	c.i += 2
	return v, nil
}

func (c *cursor) u32() (uint32, error) {
	if c.remaining() < 4 {
		return 0, ErrShort
	}
	v := uint32(c.b[c.i])<<24 | uint32(c.b[c.i+1])<<16 | uint32(c.b[c.i+2])<<8 | uint32(c.b[c.i+3])
	c.i += 4
	return v, nil
}

// take returns the next n bytes as a SUBSLICE of the frame buffer. Callers
// must not retain it beyond the parse (the connection loop reuses the buffer);
// every value that escapes into the store is copied at construction.
func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, ErrShort
	}
	v := c.b[c.i : c.i+n]
	c.i += n
	return v, nil
}

// sub returns a cursor over the next n bytes, advancing the parent past them.
// It is how a length-delimited region is parsed without the inner parser ever
// being able to read into its successor.
func (c *cursor) sub(n int) (*cursor, error) {
	b, err := c.take(n)
	if err != nil {
		return nil, err
	}
	return &cursor{b: b}, nil
}

// ── common header ───────────────────────────────────────────────────────────

// Header is the RFC 7854 §4.1 common header.
type Header struct {
	Version uint8
	Length  uint32 // total frame length INCLUDING these 6 bytes
	Type    MsgType
}

// ParseHeader reads the 6-byte common header and validates it hard enough that
// the caller can trust Length as a read budget.
//
// A bad version or an impossible length is NOT recoverable: the byte stream is
// desynchronized, and reading on would be reading garbage as routing data. The
// connection loop treats this as a disconnect, not a skip.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < CommonHeaderLen {
		return Header{}, ErrShort
	}
	c := &cursor{b: b}
	ver, err := c.u8()
	if err != nil {
		return Header{}, err
	}
	if ver != Version {
		return Header{}, fmt.Errorf("%w: %d (want %d)", ErrVersion, ver, Version)
	}
	length, err := c.u32()
	if err != nil {
		return Header{}, err
	}
	if length < CommonHeaderLen || length > MaxMessageSize {
		return Header{}, fmt.Errorf("%w: %d (accepted %d..%d)", ErrLength, length, CommonHeaderLen, MaxMessageSize)
	}
	typ, err := c.u8()
	if err != nil {
		return Header{}, err
	}
	return Header{Version: ver, Length: length, Type: MsgType(typ)}, nil
}

// ── per-peer header ─────────────────────────────────────────────────────────

// PeerHeader is the RFC 7854 §4.2 per-peer header.
type PeerHeader struct {
	PeerType      uint8
	Flags         uint8
	Distinguisher uint64
	Address       netip.Addr
	AS            uint32
	BGPID         netip.Addr
	TimestampSec  uint32
	TimestampUsec uint32
}

// Peer flag bits (RFC 7854 §4.2).
const (
	peerFlagV = 0x80 // address is IPv6
	peerFlagL = 0x40 // post-policy Adj-RIB-In
	peerFlagA = 0x20 // AS_PATH is in legacy 2-byte format
	peerFlagO = 0x10 // RFC 8671 Adj-RIB-Out
)

// IPv6 reports whether the peer address is v6 (the V flag).
func (p PeerHeader) IPv6() bool { return p.Flags&peerFlagV != 0 }

// PostPolicy reports whether the feed is post-policy Adj-RIB-In (the L flag).
func (p PeerHeader) PostPolicy() bool { return p.Flags&peerFlagL != 0 }

// LegacyASPath reports whether AS_PATH uses 2-byte ASNs (the A flag). RFC 7854
// §4.2 makes this the authority for the encoding, which is why the UPDATE
// parser takes it as an argument rather than guessing from attribute lengths.
func (p PeerHeader) LegacyASPath() bool { return p.Flags&peerFlagA != 0 }

// AdjRIBOut reports whether the feed is Adj-RIB-Out (RFC 8671, the O flag).
// We decode the frame but MARK it, because an Adj-RIB-Out prefix is what we
// advertise, not what we learned — presenting the two as one feed would be a
// quiet lie about which direction the routing information flows.
func (p PeerHeader) AdjRIBOut() bool { return p.Flags&peerFlagO != 0 }

// parsePeerHeader reads the 42-byte per-peer header from c.
func parsePeerHeader(c *cursor) (PeerHeader, error) {
	var p PeerHeader
	var err error
	if p.PeerType, err = c.u8(); err != nil {
		return PeerHeader{}, err
	}
	if p.Flags, err = c.u8(); err != nil {
		return PeerHeader{}, err
	}
	hi, err := c.u32()
	if err != nil {
		return PeerHeader{}, err
	}
	lo, err := c.u32()
	if err != nil {
		return PeerHeader{}, err
	}
	p.Distinguisher = uint64(hi)<<32 | uint64(lo)
	raw, err := c.take(16)
	if err != nil {
		return PeerHeader{}, err
	}
	p.Address = addrFrom16(raw, p.Flags&peerFlagV != 0)
	if p.AS, err = c.u32(); err != nil {
		return PeerHeader{}, err
	}
	id, err := c.take(4)
	if err != nil {
		return PeerHeader{}, err
	}
	p.BGPID = netip.AddrFrom4([4]byte{id[0], id[1], id[2], id[3]})
	if p.TimestampSec, err = c.u32(); err != nil {
		return PeerHeader{}, err
	}
	if p.TimestampUsec, err = c.u32(); err != nil {
		return PeerHeader{}, err
	}
	return p, nil
}

// addrFrom16 decodes the 16-byte address field. When the V flag is clear the
// address is IPv4 carried in the LAST four octets (RFC 7854 §4.2); the leading
// twelve are ignored rather than trusted, so a peer cannot smuggle a v6 address
// past a v4 declaration.
func addrFrom16(raw []byte, v6 bool) netip.Addr {
	if len(raw) != 16 {
		return netip.Addr{}
	}
	if v6 {
		var a [16]byte
		copy(a[:], raw)
		return netip.AddrFrom16(a)
	}
	return netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
}

// ── TLVs (Initiation / Termination / Peer Up information) ───────────────────

// TLV is one information element: a 2-byte type, a 2-byte length, and a value.
type TLV struct {
	Type  uint16
	Value string
}

// Information TLV types used by Initiation and Termination (RFC 7854 §4.3/§4.5).
const (
	tlvString  uint16 = 0
	tlvSysDesc uint16 = 1
	tlvSysName uint16 = 2
	tlvReason  uint16 = 1 // Termination reuses type 1 as a 2-byte reason code
)

// maxTLVs bounds how many information elements one frame may carry. A frame is
// already bounded by MaxMessageSize, but a million 4-byte empty TLVs inside a
// legal frame would still be a million slice appends; this ends that.
const maxTLVs = 64

// maxTLVValue bounds ONE rendered TLV string. Router sysDescr is a banner, not
// a payload channel — a peer that sends 900 KiB of "description" gets it
// truncated, and the truncation is visible in the value.
const maxTLVValue = 512

// parseTLVs reads information TLVs until the cursor is exhausted. A truncated
// TLV ends the list with an error; TLVs already parsed are returned so a
// partially-readable Initiation still identifies its router.
func parseTLVs(c *cursor) ([]TLV, error) {
	out := make([]TLV, 0, 4)
	for c.remaining() > 0 {
		if len(out) >= maxTLVs {
			return out, fmt.Errorf("%w: more than %d information TLVs", ErrLength, maxTLVs)
		}
		typ, err := c.u16()
		if err != nil {
			return out, err
		}
		n, err := c.u16()
		if err != nil {
			return out, err
		}
		raw, err := c.take(int(n))
		if err != nil {
			return out, err
		}
		out = append(out, TLV{Type: typ, Value: sanitizeText(raw, maxTLVValue)})
	}
	return out, nil
}

// sanitizeText renders a router-supplied byte string as safe, bounded text.
// Control bytes become '.', invalid UTF-8 is dropped, and the result is capped
// — a banner is display data and must not carry terminal escapes into a log
// line or a JSON body (§8, sanitize all logs).
func sanitizeText(raw []byte, max int) string {
	if len(raw) > max {
		raw = raw[:max]
	}
	out := make([]rune, 0, len(raw))
	for _, r := range string(raw) {
		switch {
		case r == 0xFFFD:
			continue // invalid UTF-8
		case r < 0x20 || r == 0x7F:
			out = append(out, '.')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

// ── messages ────────────────────────────────────────────────────────────────

// Initiation is RFC 7854 §4.3 — the router's identity, sent once per session.
type Initiation struct {
	SysName string
	SysDesc string
	Info    []string
}

// Termination is RFC 7854 §4.5 — why the router is closing the session.
type Termination struct {
	ReasonCode uint16
	HasReason  bool
	Info       []string
}

// PeerUp is RFC 7854 §4.4 — a BGP session came up on the monitored router.
type PeerUp struct {
	LocalAddress netip.Addr
	LocalPort    uint16
	RemotePort   uint16
	Info         []TLV
}

// PeerDown is RFC 7854 §4.9 — a BGP session went down, and why.
type PeerDown struct {
	Reason uint8
	// NotificationCode/Subcode are set only for the two reasons that carry a
	// BGP NOTIFICATION (1 and 3). HasNotification says which.
	NotificationCode    uint8
	NotificationSubcode uint8
	HasNotification     bool
	// FSMCode is set only for reason 2 (local system closed with an FSM event).
	FSMCode    uint16
	HasFSMCode bool
}

// ReasonText names a Peer Down reason (RFC 7854 §4.9, RFC 9069 §5).
func (p PeerDown) ReasonText() string {
	switch p.Reason {
	case 1:
		return "local_notification"
	case 2:
		return "local_fsm"
	case 3:
		return "remote_notification"
	case 4:
		return "remote_no_notification"
	case 5:
		return "peer_deconfigured"
	case 6:
		return "local_system_closed"
	default:
		return "unknown"
	}
}

// Stat is one counter from a Statistics Report.
type Stat struct {
	Type  uint16
	Value uint64
}

// StatsReport is RFC 7854 §4.8.
type StatsReport struct {
	Stats []Stat
}

// maxStats bounds the entries a single Statistics Report may declare. The
// declared count is a peer-supplied number and is NEVER used to size a slice.
const maxStats = 256

// Message is one parsed BMP frame. Exactly one of the pointer fields is set,
// selected by Type; Peer is set for the types that carry a per-peer header.
type Message struct {
	Header      Header
	Peer        *PeerHeader
	Initiation  *Initiation
	Termination *Termination
	PeerUp      *PeerUp
	PeerDown    *PeerDown
	Stats       *StatsReport
	Update      *BGPUpdate
}

// ParseMessage parses ONE complete BMP frame — common header included — from
// b. len(b) must equal the header's declared Length; the connection loop
// guarantees that, and ParseMessage re-checks rather than trusting it.
//
// A frame of a type this receiver does not decode (Route Mirroring, or any
// unassigned type) parses to a Message with only Header and, where the type
// carries one, Peer set. That is deliberate: the CALLER counts it as
// unsupported and moves on, and an unknown type never aborts a session.
func ParseMessage(b []byte) (*Message, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	// Compared in int space: h.Length was already bounded to MaxMessageSize by
	// ParseHeader, so widening it is exact — whereas narrowing len(b) to uint32
	// would be the conversion that can wrap.
	if len(b) != int(h.Length) {
		return nil, fmt.Errorf("%w: header declares %d, buffer holds %d", ErrLength, h.Length, len(b))
	}
	c := &cursor{b: b, i: CommonHeaderLen}
	msg := &Message{Header: h}

	if h.Type.hasPerPeerHeader() {
		ph, perr := parsePeerHeader(c)
		if perr != nil {
			return nil, perr
		}
		msg.Peer = &ph
	}

	switch h.Type {
	case MsgInitiation:
		init, ierr := parseInitiation(c)
		if ierr != nil {
			return nil, ierr
		}
		msg.Initiation = init
	case MsgTermination:
		term, terr := parseTermination(c)
		if terr != nil {
			return nil, terr
		}
		msg.Termination = term
	case MsgPeerUp:
		up, uerr := parsePeerUp(c, msg.Peer)
		if uerr != nil {
			return nil, uerr
		}
		msg.PeerUp = up
	case MsgPeerDown:
		down, derr := parsePeerDown(c)
		if derr != nil {
			return nil, derr
		}
		msg.PeerDown = down
	case MsgStatisticsReport:
		st, serr := parseStats(c)
		if serr != nil {
			return nil, serr
		}
		msg.Stats = st
	case MsgRouteMonitoring:
		up, uerr := parseRouteMonitoring(c, msg.Peer)
		if uerr != nil {
			return nil, uerr
		}
		msg.Update = up
	default:
		// Route Mirroring and every unassigned type: well-framed, not decoded.
		// The caller counts it; we do not guess at its contents.
	}
	return msg, nil
}

func parseInitiation(c *cursor) (*Initiation, error) {
	tlvs, err := parseTLVs(c)
	if err != nil {
		return nil, err
	}
	out := &Initiation{}
	for _, t := range tlvs {
		switch t.Type {
		case tlvSysName:
			out.SysName = t.Value
		case tlvSysDesc:
			out.SysDesc = t.Value
		case tlvString:
			out.Info = append(out.Info, t.Value)
		}
	}
	return out, nil
}

func parseTermination(c *cursor) (*Termination, error) {
	out := &Termination{}
	for c.remaining() > 0 {
		if len(out.Info) >= maxTLVs {
			return out, fmt.Errorf("%w: more than %d information TLVs", ErrLength, maxTLVs)
		}
		typ, err := c.u16()
		if err != nil {
			return nil, err
		}
		n, err := c.u16()
		if err != nil {
			return nil, err
		}
		raw, err := c.take(int(n))
		if err != nil {
			return nil, err
		}
		switch typ {
		case tlvReason:
			// A reason TLV is exactly two octets. A different length is a
			// malformed frame, not a reason we should half-read.
			if len(raw) != 2 {
				return nil, fmt.Errorf("%w: termination reason TLV is %d octets, want 2", ErrLength, len(raw))
			}
			out.ReasonCode = uint16(raw[0])<<8 | uint16(raw[1])
			out.HasReason = true
		case tlvString:
			out.Info = append(out.Info, sanitizeText(raw, maxTLVValue))
		}
	}
	return out, nil
}

func parsePeerUp(c *cursor, ph *PeerHeader) (*PeerUp, error) {
	raw, err := c.take(16)
	if err != nil {
		return nil, err
	}
	v6 := ph != nil && ph.IPv6()
	out := &PeerUp{LocalAddress: addrFrom16(raw, v6)}
	if out.LocalPort, err = c.u16(); err != nil {
		return nil, err
	}
	if out.RemotePort, err = c.u16(); err != nil {
		return nil, err
	}
	// Two BGP OPEN messages follow (sent, then received). We skip over them by
	// their own length field rather than parsing them: nothing in the read API
	// is derived from OPEN, and a parser we do not need is attack surface we
	// do not need. Skipping is still BOUNDED — a bad length is an error.
	for i := 0; i < 2; i++ {
		if err := skipBGPMessage(c); err != nil {
			return nil, err
		}
	}
	if c.remaining() > 0 {
		tlvs, terr := parseTLVs(c)
		if terr != nil {
			// The OPENs were readable; keep the session facts and report the
			// tail as an error for the caller to count.
			return nil, terr
		}
		out.Info = tlvs
	}
	return out, nil
}

// skipBGPMessage advances past one BGP message using its own 19-byte header.
// The marker is NOT verified (RFC 4271 deprecated its use for authentication
// and some implementations vary); the LENGTH is, because that is the field
// that decides how far we move.
func skipBGPMessage(c *cursor) error {
	if c.remaining() < bgpHeaderLen {
		return ErrShort
	}
	if _, err := c.take(bgpMarkerLen); err != nil {
		return err
	}
	n, err := c.u16()
	if err != nil {
		return err
	}
	if int(n) < bgpHeaderLen {
		return fmt.Errorf("%w: BGP message length %d is below the %d-octet header", ErrLength, n, bgpHeaderLen)
	}
	if _, err := c.u8(); err != nil { // type octet
		return err
	}
	_, err = c.take(int(n) - bgpHeaderLen)
	return err
}

func parsePeerDown(c *cursor) (*PeerDown, error) {
	reason, err := c.u8()
	if err != nil {
		return nil, err
	}
	out := &PeerDown{Reason: reason}
	switch reason {
	case 1, 3:
		// A BGP NOTIFICATION follows. We read only its code/subcode — the pair
		// that actually tells an operator why the session dropped.
		if c.remaining() < bgpHeaderLen+2 {
			return nil, ErrShort
		}
		if _, err := c.take(bgpMarkerLen); err != nil {
			return nil, err
		}
		if _, err := c.u16(); err != nil { // length
			return nil, err
		}
		if _, err := c.u8(); err != nil { // type
			return nil, err
		}
		if out.NotificationCode, err = c.u8(); err != nil {
			return nil, err
		}
		if out.NotificationSubcode, err = c.u8(); err != nil {
			return nil, err
		}
		out.HasNotification = true
	case 2:
		if out.FSMCode, err = c.u16(); err != nil {
			return nil, err
		}
		out.HasFSMCode = true
	case 4, 5, 6:
		// No further data we decode (reason 6 carries RFC 9069 TLVs).
	default:
		return nil, fmt.Errorf("%w: peer-down reason %d", ErrUnsupported, reason)
	}
	return out, nil
}

func parseStats(c *cursor) (*StatsReport, error) {
	count, err := c.u32()
	if err != nil {
		return nil, err
	}
	if count > maxStats {
		return nil, fmt.Errorf("%w: %d statistics entries (max %d)", ErrLength, count, maxStats)
	}
	// The declared count sizes nothing: the slice grows as entries are ACTUALLY
	// read, so a peer declaring 256 entries in a 10-byte frame allocates one
	// header, not 256 structs.
	out := &StatsReport{}
	for i := uint32(0); i < count; i++ {
		typ, terr := c.u16()
		if terr != nil {
			return nil, terr
		}
		n, nerr := c.u16()
		if nerr != nil {
			return nil, nerr
		}
		raw, rerr := c.take(int(n))
		if rerr != nil {
			return nil, rerr
		}
		v, ok := statValue(raw)
		if !ok {
			// A width we do not know is skipped, not guessed at: reporting a
			// wrong counter is worse than reporting none.
			continue
		}
		out.Stats = append(out.Stats, Stat{Type: typ, Value: v})
	}
	return out, nil
}

// statValue decodes a stat payload. RFC 7854 §4.8 defines 4-octet counters and
// 8-octet gauges; anything else is not decoded.
func statValue(raw []byte) (uint64, bool) {
	switch len(raw) {
	case 4:
		return uint64(raw[0])<<24 | uint64(raw[1])<<16 | uint64(raw[2])<<8 | uint64(raw[3]), true
	case 8:
		var v uint64
		for _, b := range raw {
			v = v<<8 | uint64(b)
		}
		return v, true
	default:
		return 0, false
	}
}

// parseRouteMonitoring reads the BGP UPDATE PDU carried in a Route Monitoring
// message (RFC 7854 §4.6).
func parseRouteMonitoring(c *cursor, ph *PeerHeader) (*BGPUpdate, error) {
	if c.remaining() < bgpHeaderLen {
		return nil, ErrShort
	}
	if _, err := c.take(bgpMarkerLen); err != nil {
		return nil, err
	}
	n, err := c.u16()
	if err != nil {
		return nil, err
	}
	typ, err := c.u8()
	if err != nil {
		return nil, err
	}
	if int(n) < bgpHeaderLen {
		return nil, fmt.Errorf("%w: BGP message length %d is below the %d-octet header", ErrLength, n, bgpHeaderLen)
	}
	body, err := c.sub(int(n) - bgpHeaderLen)
	if err != nil {
		return nil, err
	}
	const bgpUpdateType = 2
	if typ != bgpUpdateType {
		return nil, fmt.Errorf("%w: route monitoring carried BGP message type %d, want UPDATE(2)", ErrUnsupported, typ)
	}
	legacyAS := ph != nil && ph.LegacyASPath()
	return parseBGPUpdateBody(body, legacyAS)
}
