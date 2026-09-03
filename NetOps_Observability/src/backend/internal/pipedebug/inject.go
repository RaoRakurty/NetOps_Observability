package pipedebug

// inject.go — building and sending the ONE marked synthetic record a trace
// follows (design §2).
//
// TWO SAFETY RULES, enforced here rather than documented elsewhere:
//
//  1. NOTHING IS EVER WRITTEN TO A DEVICE. The syslog frame goes to the STACK's
//     own syslog ingress and the trap PDU to the STACK's own trap receiver. The
//     `--device` argument only decides which device the record CLAIMS to come
//     from, so the pipeline's device→tenant attribution is exercised for real.
//     gNMI has no injectable form at all and is passive-only (W2).
//  2. EVERY INJECTED RECORD IS TAGGED SYNTHETIC. `cx_synthetic=true` travels in
//     the same free-text field as the marker, and the UI-facing log query
//     excludes it (logsScope in package backend), so a debug trace can never
//     show up in a customer's log search as if it were device traffic.
//
// The encoders are pure functions over (marker, device, now) so the wire format
// is unit-testable without a socket.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	// EnvSyslogTarget names the stack's syslog ingress (host:port, UDP).
	EnvSyslogTarget = "DEBUG_SYSLOG_TARGET"
	// EnvTrapTarget names the stack's SNMP trap receiver (host:port, UDP).
	EnvTrapTarget = "DEBUG_TRAP_TARGET"

	// DefaultSyslogTarget is syslog-ng inside the compose network.
	DefaultSyslogTarget = "syslog-ng:514"
	// DefaultTrapTarget is the API's own in-container trap receiver
	// (collectors.NewTrapReceiver listens on :1162).
	DefaultTrapTarget = "127.0.0.1:1162"

	// injectAppName is the RFC5424 APP-NAME every injected syslog frame carries,
	// so an operator grepping the store can find every probe ever sent.
	injectAppName = "correlix-debug"

	// maxDeviceKey bounds the untrusted device string before it is written into
	// a syslog HOSTNAME field or an SNMP varbind.
	maxDeviceKey = 128
)

// ValidDeviceKey bounds and validates the device identity a synthetic record
// claims. It is a CLOSED grammar (hostname characters only) because the value
// is written into a syslog HOSTNAME field and an SNMP OCTET STRING: a space or
// a newline there would let a caller forge extra structure in the frame.
func ValidDeviceKey(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("device is required")
	}
	if len(s) > maxDeviceKey {
		return fmt.Errorf("device must be at most %d characters", maxDeviceKey)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return fmt.Errorf("device may contain only letters, digits and -_.: (got %q)", r)
		}
	}
	return nil
}

// MarkerPayload is the text the marker and the synthetic tag travel in. Both
// kinds carry the identical string, so one grep finds a probe in any store.
func MarkerPayload(marker string) string {
	return SyntheticTag + " " + MarkerTag(marker) + " correlix pipeline debug probe"
}

// BuildSyslogFrame renders the RFC5424 frame for a syslog-kind probe.
//
// PRI 134 = facility local0 (16) severity informational (6): an informational
// local-facility message is the least alarming thing that can be put on a
// syslog bus, which matters because this frame is going into a REAL pipeline.
func BuildSyslogFrame(marker, device string, now time.Time) string {
	return fmt.Sprintf("<134>1 %s %s %s - - - %s",
		now.UTC().Format("2006-01-02T15:04:05.000000Z"),
		device, injectAppName, MarkerPayload(marker))
}

// BuildTrapPDU renders an SNMPv2c SNMPv2-Trap-PDU carrying the marker.
//
// The trap OID sits under the EXPERIMENTAL arc (1.3.6.1.3), never under a real
// notification OID: a debug probe must not be decodable as coldStart, linkDown
// or any other event the correlation engine would reason about. sysName carries
// the claimed device so the receiver's normal attribution path runs; the marker
// travels in its own string varbind next to it (design §2).
func BuildTrapPDU(marker, device, community string, now time.Time) ([]byte, error) {
	if err := ValidDeviceKey(device); err != nil {
		return nil, err
	}
	if !ValidMarker(marker) {
		return nil, errors.New("invalid marker")
	}
	if community == "" {
		community = "correlix-debug"
	}
	uptime := uint32(now.UTC().Unix()%4294967) * 100 // #nosec G115 -- modulo-bounded below 2^32; sysUpTime is decorative here

	varbinds := [][]byte{}
	vb, err := berVarbind(oidSysUpTime, berTimeTicks(uptime))
	if err != nil {
		return nil, err
	}
	varbinds = append(varbinds, vb)

	trapOID, err := berOID(oidExperimentalDebugTrap)
	if err != nil {
		return nil, err
	}
	vb, err = berVarbind(oidSnmpTrapOID, trapOID)
	if err != nil {
		return nil, err
	}
	varbinds = append(varbinds, vb)

	vb, err = berVarbind(oidSysName, berOctetString([]byte(device)))
	if err != nil {
		return nil, err
	}
	varbinds = append(varbinds, vb)

	vb, err = berVarbind(oidExperimentalDebugMarker, berOctetString([]byte(MarkerPayload(marker))))
	if err != nil {
		return nil, err
	}
	varbinds = append(varbinds, vb)

	body := berSequence(concat(varbinds...))
	// request-id is derived from the marker's entropy tail so a peek can tie a
	// PDU on the wire back to the trace without a second identifier.
	reqID := int64(binary.BigEndian.Uint32([]byte(marker[len(marker)-4:])) & 0x7fffffff)
	pdu := berTagged(0xA7, concat( // [7] IMPLICIT — SNMPv2-Trap-PDU
		berInteger(reqID),
		berInteger(0), // error-status
		berInteger(0), // error-index
		body,
	))
	return berSequence(concat(
		berInteger(1), // version 1 == SNMPv2c
		berOctetString([]byte(community)),
		pdu,
	)), nil
}

// Well-known OIDs the probe uses.
var (
	oidSysUpTime   = []uint64{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSnmpTrapOID = []uint64{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	oidSysName     = []uint64{1, 3, 6, 1, 2, 1, 1, 5, 0}
	// 1.3.6.1.3 is the IANA "experimental" arc — deliberately not a real
	// notification OID (see BuildTrapPDU).
	oidExperimentalDebugTrap   = []uint64{1, 3, 6, 1, 3, 9999, 1, 0}
	oidExperimentalDebugMarker = []uint64{1, 3, 6, 1, 3, 9999, 2, 0}
)

// SendUDP writes one datagram to target with a bounded dial and write deadline.
// UDP gives no delivery confirmation — the RETURN of this function means "the
// datagram left this process", nothing more, and the trace's ingress stage is
// what actually proves arrival. Saying so here is the point: a debugger that
// reported "injected" as "received" would be lying at step one.
func SendUDP(target string, payload []byte, timeout time.Duration) error {
	if strings.TrimSpace(target) == "" {
		return errors.New("no injection target configured")
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("udp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }() // a UDP socket close cannot fail meaningfully; nothing to report
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	n, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	if n != len(payload) {
		return fmt.Errorf("short write to %s: %d of %d bytes", target, n, len(payload))
	}
	return nil
}

// ── minimal BER encoders ────────────────────────────────────────────────────
//
// The stdlib's encoding/asn1 cannot emit SNMP's application-tagged types
// (TimeTicks) or the context-tagged trap PDU, so the four primitives the probe
// needs are encoded here. They are small, total, and unit-tested against a
// decoder — not a general ASN.1 implementation, and not to be used as one.

func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v & 0xff)}, b...)
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func berTagged(tag byte, body []byte) []byte {
	out := []byte{tag}
	out = append(out, berLength(len(body))...)
	return append(out, body...)
}

func berSequence(body []byte) []byte { return berTagged(0x30, body) }

func berOctetString(b []byte) []byte { return berTagged(0x04, b) }

func berInteger(v int64) []byte {
	// big.Int gives the minimal two's-complement form ASN.1 requires without a
	// hand-rolled sign/leading-byte dance.
	b := big.NewInt(v).Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return berTagged(0x02, b)
}

// berTimeTicks encodes SNMP's APPLICATION 3 unsigned type.
func berTimeTicks(v uint32) []byte {
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x & 0xff)}, b...)
	}
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return berTagged(0x43, b)
}

func berOID(arcs []uint64) ([]byte, error) {
	if len(arcs) < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
		return nil, fmt.Errorf("not an encodable OID: %v", arcs)
	}
	body := []byte{byte(arcs[0]*40 + arcs[1])}
	for _, a := range arcs[2:] {
		body = append(body, base128(a)...)
	}
	return berTagged(0x06, body), nil
}

func base128(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0x7f)}, out...)
		v >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func berVarbind(oid []uint64, value []byte) ([]byte, error) {
	name, err := berOID(oid)
	if err != nil {
		return nil, err
	}
	return berSequence(concat(name, value)), nil
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
