package collectors

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// snmptrap.go — the SNMP trap/inform receiver. Unlike the pollers (which GET
// over UDP/161), this is a passive listener on UDP/162 that decodes the
// asynchronous notifications devices PUSH (linkDown, authenticationFailure,
// coldStart, vendor-specific). Traps are log/event-shaped, not metrics, so the
// receiver normalizes each one to a structured event and forwards it onto the
// EXISTING log bus (an HTTP source on the Vector aggregator → Redpanda
// netops.snmptrap → vector-router → OpenSearch netops-snmptrap-*), where it
// inherits the same per-tenant stamping, retention and export as syslog/flows.
// Displayed as the "SNMP traps" signal in Explore → Logs.
//
// Full SNMP: v1 Trap-PDU (RFC 1157), v2c SNMPv2-Trap-PDU and v3 trap/inform with
// USM auth+priv — reusing the package's stdlib BER decoders (tunnels.go) and the
// v3 USM engine (snmpv3.go: localizeKey/authHash/parseV3SecurityParams/decrypt).
// Zero-trust: untrusted UDP, so packets are size-bounded, malformed PDUs are
// dropped, and an authPriv v3 trap that fails HMAC verification is refused
// rather than indexed.

// TrapVarbind is one decoded variable-binding (OID + rendered value). Name is the
// resolved object name (e.g. ifOperStatus) when the OID is well-known, so the UI
// shows "ifOperStatus=down(2)" instead of a raw 1.3.6.1.2.1.2.2.1.8.x.
type TrapVarbind struct {
	OID   string `json:"oid"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value"`
}

// TrapEvent is the normalized, transport-agnostic trap, JSON-emitted to the bus.
type TrapEvent struct {
	Signal        string        `json:"_signal"` // always "snmptrap" — Vector routes on this
	Timestamp     string        `json:"timestamp"`
	Host          string        `json:"host"`   // source IP (vector-router maps → tenant)
	Device        string        `json:"device"` // inventory device id if the source is known
	Version       string        `json:"snmp_version"`
	User          string        `json:"snmp_user,omitempty"`      // v3 securityName
	Community     string        `json:"snmp_community,omitempty"` // v1/v2c (kept for audit; not a secret)
	TrapOID       string        `json:"trap_oid"`
	TrapName      string        `json:"trap_name,omitempty"`
	Severity      string        `json:"severity"`
	Authenticated bool          `json:"authenticated"` // v3 auth verified (v1/v2c are spoofable → false)
	Message       string        `json:"message"`
	Varbinds      []TrapVarbind `json:"varbinds,omitempty"`

	// NormalizedEvent envelope (#32) — vendor-agnostic structure every trap emits,
	// so Events/Correlation read parsed fields instead of re-decoding raw OIDs.
	// Design: docs/design/research/telemetry-normalization-architecture.md §3.
	Vendor           string `json:"vendor,omitempty"`            // from the enterprise OID arc
	EventType        string `json:"event_type,omitempty"`        // normalized leaf (trap name → snake)
	MessageKey       string `json:"message_key,omitempty"`       // stable dedup identity (never raw text)
	ParserStatus     string `json:"parser_status,omitempty"`     // decoded | partial | raw_only
	EnrichmentStatus string `json:"enrichment_status,omitempty"` // inventory_matched | inventory_missing
}

// vendorFromOID returns the vendor for an enterprise OID via the shared
// enterpriseVendor map (vendor.go) — stable identity from the IANA PEN arc, not a
// parse hack. "" for the standard tree or an unknown enterprise number.
func vendorFromOID(oid string) string {
	const p = "1.3.6.1.4.1."
	if !strings.HasPrefix(oid, p) {
		return ""
	}
	ent := oid[len(p):]
	if i := strings.IndexByte(ent, '.'); i >= 0 {
		ent = ent[:i]
	}
	n, err := strconv.Atoi(ent)
	if err != nil {
		return ""
	}
	return enterpriseVendor[n]
}

// camelToSnake normalizes a MIB object name to a stable lower_snake event token
// (aristaBgp4V2BackwardTransitionNotification → arista_bgp4_v2_backward_transition,
// linkDown → link_down), stripping the trailing Notification/Trap noise.
func camelToSnake(s string) string {
	s = strings.TrimSuffix(strings.TrimSuffix(s, "Notification"), "Trap")
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// deriveEnvelope fills the NormalizedEvent envelope from the already-decoded trap.
// Vendor-agnostic: it works for any trap, decoded or raw.
func deriveEnvelope(ev *TrapEvent) {
	ev.Vendor = vendorFromOID(ev.TrapOID)
	if ev.TrapName != "" && ev.TrapName != "enterpriseSpecific" {
		ev.EventType = camelToSnake(ev.TrapName)
		ev.ParserStatus = "decoded"
	} else {
		ev.EventType = "enterprise_specific"
		ev.ParserStatus = "raw_only"
	}
	if ev.Device != "" {
		ev.EnrichmentStatus = "inventory_matched"
	} else {
		ev.EnrichmentStatus = "inventory_missing"
	}
	// message_key: stable identity = signal:device|src:mib:event_type (never raw text)
	who := ev.Device
	if who == "" {
		who = ev.Host
	}
	mib := ""
	if n, _, ok := lookupOID(ev.TrapOID); ok {
		mib = n.MIB
	}
	parts := []string{"snmptrap", who, mib, ev.EventType}
	clean := parts[:0]
	for _, p := range parts {
		if p != "" {
			clean = append(clean, p)
		}
	}
	ev.MessageKey = strings.Join(clean, ":")
}

// snmpTrapOIDPrefix = 1.3.6.1.6.3.1.1.5 — the SNMPv2-MIB generic traps live at
// .1..6; the snmpTrapOID.0 varbind that names a v2/v3 trap is 1.3.6.1.6.3.1.1.4.1.0.
var snmpTrapOIDDot = "1.3.6.1.6.3.1.1.4.1.0"

// trapMeta resolves a trap OID (dotted) to a friendly name + severity via the
// MIB-backed OID index (oidindex.go — generated from a vendored MIB tree). Unknown
// OIDs read as enterpriseSpecific/notice; add the vendor MIB + `make mib-index` to
// decode them (mibs/README.md). Replaces the old hand-curated wellKnownTraps map.
func trapMeta(oid string) (name, severity string) {
	if n, _, ok := lookupOID(oid); ok && n.Name != "" {
		sev := n.SeverityHint
		if sev == "" {
			sev = "notice"
		}
		return n.Name, sev
	}
	return "enterpriseSpecific", "notice"
}

// resolveVarbind returns the object name (or "" if unknown) and a value possibly
// decorated with an enum label, resolved via the MIB-backed OID index. Replaces
// the old hand-curated varbindObjects/varbindExact maps.
func resolveVarbind(oid, value string) (name, dispValue string) {
	n, _, ok := lookupOID(oid)
	if !ok || n.Name == "" {
		return "", value
	}
	if n.Enum != nil {
		if lbl, found := n.Enum[value]; found {
			return n.Name, fmt.Sprintf("%s(%s)", lbl, value)
		}
	}
	return n.Name, value
}

func oidString(arcs []int) string {
	parts := make([]string, len(arcs))
	for i, a := range arcs {
		parts[i] = fmt.Sprintf("%d", a)
	}
	return strings.Join(parts, ".")
}

// valStr renders a BER value by tag into a human/JSON-friendly string.
func valStr(tag byte, raw []byte) string {
	switch tag {
	case 0x02: // INTEGER
		return fmt.Sprintf("%d", decodeInt(raw))
	case 0x06: // OBJECT IDENTIFIER
		return oidString(decodeOID(raw))
	case 0x40: // IpAddress
		return decodeIP(raw)
	case 0x41, 0x42, 0x43, 0x46: // Counter32, Gauge32, TimeTicks, Counter64
		return fmt.Sprintf("%d", decodeUint(raw))
	case 0x04: // OCTET STRING — printable if it is, else hex
		if isPrintable(raw) {
			return string(raw)
		}
		return "0x" + hex.EncodeToString(raw)
	case 0x05: // NULL
		return ""
	default:
		if isPrintable(raw) {
			return string(raw)
		}
		return "0x" + hex.EncodeToString(raw)
	}
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c != '\t' && c != '\n' && c != '\r' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// parseVarbinds walks a VarBindList SEQUENCE content into decoded bindings.
func parseVarbinds(vbList []byte) []TrapVarbind {
	var out []TrapVarbind
	rest := vbList
	for len(rest) > 0 {
		_, vb, r, err := readTLV(rest) // one varbind SEQUENCE
		if err != nil {
			break
		}
		rest = r
		oidTag, oidRaw, after, err := readTLV(vb)
		if err != nil || oidTag != 0x06 {
			continue
		}
		valTag, valRaw, _, err := readTLV(after)
		if err != nil {
			continue
		}
		oid := oidString(decodeOID(oidRaw))
		name, val := resolveVarbind(oid, valStr(valTag, valRaw))
		out = append(out, TrapVarbind{OID: oid, Name: name, Value: val})
	}
	return out
}

// finalizeTrap fills the trap OID / name / severity / message from the varbinds
// (v2/v3: the snmpTrapOID.0 binding names the trap) and trims it out of the list.
func finalizeTrap(ev *TrapEvent, vbs []TrapVarbind) {
	kept := vbs[:0:0]
	for _, vb := range vbs {
		if vb.OID == snmpTrapOIDDot && ev.TrapOID == "" {
			ev.TrapOID = vb.Value
			continue
		}
		kept = append(kept, vb)
	}
	ev.Varbinds = kept
	if ev.TrapOID != "" {
		ev.TrapName, ev.Severity = trapMeta(ev.TrapOID)
	}
	if ev.Severity == "" {
		ev.Severity = "notice"
	}
	parts := []string{}
	if ev.TrapName != "" {
		parts = append(parts, ev.TrapName)
	}
	if ev.TrapOID != "" {
		parts = append(parts, ev.TrapOID)
	}
	for _, vb := range kept {
		key := vb.Name
		if key == "" {
			key = vb.OID
		}
		parts = append(parts, key+"="+vb.Value)
	}
	ev.Message = strings.Join(parts, " ")
}

// decodeV2StylePDU reads request-id, error-status, error-index, then varbinds
// from an SNMPv2-Trap-PDU / Inform-PDU body and returns the varbinds.
func decodeV2StylePDU(pduBody []byte) ([]TrapVarbind, error) {
	_, _, r, err := readTLV(pduBody) // request-id
	if err != nil {
		return nil, err
	}
	_, _, r, err = readTLV(r) // error-status
	if err != nil {
		return nil, err
	}
	_, _, r, err = readTLV(r) // error-index
	if err != nil {
		return nil, err
	}
	_, vbList, _, err := readTLV(r) // variable-bindings SEQUENCE
	if err != nil {
		return nil, err
	}
	return parseVarbinds(vbList), nil
}

// decodeTrapV1 parses an RFC 1157 v1 Trap-PDU body (enterprise, agent-addr,
// generic, specific, timestamp, varbinds) into a normalized event.
func decodeTrapV1(ev *TrapEvent, pduBody []byte) error {
	entTag, entRaw, r, err := readTLV(pduBody) // enterprise OID
	if err != nil || entTag != 0x06 {
		return fmt.Errorf("snmptrap: v1 enterprise oid: %w", err)
	}
	enterprise := oidString(decodeOID(entRaw))
	_, agentRaw, r, err := readTLV(r) // agent-addr (IpAddress)
	if err != nil {
		return err
	}
	if ip := decodeIP(agentRaw); ip != "" && ev.Host == "" {
		ev.Host = ip
	}
	_, genRaw, r, err := readTLV(r) // generic-trap
	if err != nil {
		return err
	}
	_, specRaw, r, err := readTLV(r) // specific-trap
	if err != nil {
		return err
	}
	_, _, r, err = readTLV(r) // time-stamp
	if err != nil {
		return err
	}
	_, vbList, _, err := readTLV(r) // varbinds
	if err != nil {
		return err
	}
	generic := int(decodeInt(genRaw))
	specific := int(decodeInt(specRaw))
	if generic >= 0 && generic < 6 {
		ev.TrapOID = fmt.Sprintf("1.3.6.1.6.3.1.1.5.%d", generic+1)
		ev.TrapName, ev.Severity = trapMeta(ev.TrapOID)
	} else {
		// enterpriseSpecific (RFC 2576 §3.1): enterprise.0.specific
		ev.TrapOID = fmt.Sprintf("%s.0.%d", enterprise, specific)
		ev.TrapName, ev.Severity = "enterpriseSpecific", "notice"
	}
	vbs := parseVarbinds(vbList)
	ev.Varbinds = vbs
	parts := []string{ev.TrapName, ev.TrapOID}
	for _, vb := range vbs {
		parts = append(parts, vb.OID+"="+vb.Value)
	}
	ev.Message = strings.Join(parts, " ")
	return nil
}

// credResolver maps a source IP to its inventory device id and (for v3) creds.
type credResolver func(ip string) (Target, bool)

// decodeTrap dispatches an incoming UDP datagram to the right SNMP-version
// decoder and returns the normalized event. src is the UDP source IP.
func decodeTrap(pkt []byte, srcIP string, resolve credResolver) (*TrapEvent, error) {
	outerTag, body, _, err := readTLV(pkt)
	if err != nil {
		return nil, err
	}
	if outerTag != 0x30 {
		return nil, fmt.Errorf("snmptrap: not a SEQUENCE")
	}
	verTag, verRaw, rest, err := readTLV(body) // version INTEGER
	if err != nil || verTag != 0x02 {
		return nil, fmt.Errorf("snmptrap: bad version field")
	}
	ev := &TrapEvent{Signal: "snmptrap", Host: srcIP, Timestamp: nowRFC3339()}
	if resolve != nil {
		if tg, ok := resolve(srcIP); ok {
			ev.Device = tg.ID
		}
	}
	switch decodeInt(verRaw) {
	case 0: // SNMPv1
		ev.Version = "v1"
		_, _, r, err := readTLV(rest) // community
		if err != nil {
			return nil, err
		}
		pduTag, pduBody, _, err := readTLV(r)
		if err != nil || pduTag != 0xA4 {
			return nil, fmt.Errorf("snmptrap: v1 pdu tag %#x", pduTag)
		}
		if err := decodeTrapV1(ev, pduBody); err != nil {
			return nil, err
		}
		return ev, nil

	case 1: // SNMPv2c
		ev.Version = "v2c"
		commTag, commRaw, r, err := readTLV(rest) // community
		if err != nil || commTag != 0x04 {
			return nil, fmt.Errorf("snmptrap: v2c community")
		}
		ev.Community = string(commRaw)
		pduTag, pduBody, _, err := readTLV(r)
		if err != nil {
			return nil, err
		}
		if pduTag != 0xA7 && pduTag != 0xA6 { // SNMPv2-Trap-PDU / Inform-PDU
			return nil, fmt.Errorf("snmptrap: v2c pdu tag %#x", pduTag)
		}
		vbs, err := decodeV2StylePDU(pduBody)
		if err != nil {
			return nil, err
		}
		finalizeTrap(ev, vbs)
		return ev, nil

	case 3: // SNMPv3
		ev.Version = "v3"
		return decodeTrapV3(ev, pkt, resolve)

	default:
		return nil, fmt.Errorf("snmptrap: unsupported version")
	}
}

// decodeTrapV3 verifies/decrypts a v3 trap using the source device's USM creds
// (resolved by source IP), then decodes the inner SNMPv2-Trap-PDU. A trap whose
// auth can't be verified (when the creds want auth) is refused.
func decodeTrapV3(ev *TrapEvent, pkt []byte, resolve credResolver) (*TrapEvent, error) {
	eid, boots, etime, privParams, err := parseV3SecurityParams(pkt)
	if err != nil {
		return nil, err
	}
	ev.User = usmUserName(pkt)

	var creds snmpCreds
	if resolve != nil {
		if tg, ok := resolve(ev.Host); ok {
			creds = tg.creds()
		}
	}
	// noAuthNoPriv (or unknown sender): decode the cleartext scopedPDU directly.
	if !creds.isV3() || !creds.wantsAuth() {
		priv, msgData, err := v3MsgData(pkt)
		if err != nil {
			return nil, err
		}
		if priv {
			return nil, fmt.Errorf("snmptrap: encrypted v3 trap from %s but no priv creds", ev.Host)
		}
		return finishV3(ev, msgData)
	}

	sess := &v3Session{creds: creds, engineID: eid, boots: boots, etime: etime}
	newHash, macLen := authHash(creds.AuthProto)
	sess.authKeyL = localizeKey(newHash, creds.AuthKey, eid)
	if creds.wantsPriv() {
		sess.privKeyL = localizeKey(newHash, creds.PrivKey, eid)
	}
	if !verifyV3Auth(pkt, sess.authKeyL, newHash, macLen) {
		return nil, fmt.Errorf("snmptrap: v3 auth verification failed from %s", ev.Host)
	}
	ev.Authenticated = true

	priv, msgData, err := v3MsgData(pkt)
	if err != nil {
		return nil, err
	}
	scoped := msgData
	if priv {
		if !creds.wantsPriv() {
			return nil, fmt.Errorf("snmptrap: encrypted v3 trap from %s but no priv creds", ev.Host)
		}
		scoped, err = sess.decrypt(creds, msgData, privParams)
		if err != nil {
			return nil, err
		}
	}
	return finishV3(ev, scoped)
}

// finishV3 reads the inner PDU out of a (decrypted) scopedPDU and normalizes.
func finishV3(ev *TrapEvent, scoped []byte) (*TrapEvent, error) {
	_, body, _, err := readTLV(scoped) // scopedPDU SEQUENCE
	if err != nil {
		return nil, err
	}
	_, _, r, err := readTLV(body) // contextEngineID
	if err != nil {
		return nil, err
	}
	_, _, r, err = readTLV(r) // contextName
	if err != nil {
		return nil, err
	}
	pduTag, pduBody, _, err := readTLV(r) // PDU
	if err != nil {
		return nil, err
	}
	if pduTag != 0xA7 && pduTag != 0xA6 {
		return nil, fmt.Errorf("snmptrap: v3 inner pdu tag %#x", pduTag)
	}
	vbs, err := decodeV2StylePDU(pduBody)
	if err != nil {
		return nil, err
	}
	finalizeTrap(ev, vbs)
	return ev, nil
}

// usmUserName extracts the msgUserName from a v3 message (best-effort).
func usmUserName(pkt []byte) string {
	_, body, _, err := readTLV(pkt) // outer SEQUENCE
	if err != nil {
		return ""
	}
	_, _, r, err := readTLV(body) // version
	if err != nil {
		return ""
	}
	_, _, r, err = readTLV(r) // msgGlobalData
	if err != nil {
		return ""
	}
	_, secOctet, _, err := readTLV(r) // msgSecurityParameters OCTET STRING
	if err != nil {
		return ""
	}
	_, usm, _, err := readTLV(secOctet) // USM SEQUENCE
	if err != nil {
		return ""
	}
	_, _, u, err := readTLV(usm) // engineID
	if err != nil {
		return ""
	}
	_, _, u, err = readTLV(u) // boots
	if err != nil {
		return ""
	}
	_, _, u, err = readTLV(u) // time
	if err != nil {
		return ""
	}
	_, name, _, err := readTLV(u) // userName
	if err != nil {
		return ""
	}
	return string(name)
}

// verifyV3Auth recomputes the USM HMAC over the message with the authParams
// region zeroed and compares it to the received MAC (RFC 3414 §6.3.2).
func verifyV3Auth(pkt, authKeyL []byte, newHash func() hash.Hash, macLen int) bool {
	got, off, ok := usmAuthParamsLoc(pkt)
	if !ok || len(got) != macLen || macLen == 0 || len(authKeyL) == 0 {
		return false
	}
	work := append([]byte(nil), pkt...)
	for i := 0; i < macLen; i++ {
		work[off+i] = 0
	}
	mac := hmac.New(newHash, authKeyL)
	mac.Write(work)
	want := mac.Sum(nil)[:macLen]
	return hmac.Equal(want, got)
}

// tlvAt reads one BER TLV at b, where base is b's absolute offset within the
// original packet. It returns the tag, the absolute offset + length of the
// content, and the absolute offset just past this TLV.
func tlvAt(b []byte, base int) (tag byte, contentOff, contentLen, next int, err error) {
	if len(b) < 2 {
		return 0, 0, 0, 0, fmt.Errorf("snmptrap: truncated TLV")
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, 0, 0, 0, fmt.Errorf("snmptrap: bad length")
		}
		l = 0
		for k := 0; k < n; k++ {
			l = l<<8 | int(b[2+k])
		}
		i = 2 + n
	}
	if len(b) < i+l {
		return 0, 0, 0, 0, fmt.Errorf("snmptrap: content past end")
	}
	return tag, base + i, l, base + i + l, nil
}

// usmAuthParamsLoc locates the USM authParameters within a v3 message, returning
// its content bytes and absolute offset in pkt. Structure (RFC 3412/3414):
// SEQUENCE { version, msgGlobalData, msgSecurityParameters OCTET STRING wrapping
// USM SEQUENCE { engineID, boots, time, userName, authParams, privParams }, msgData }.
func usmAuthParamsLoc(pkt []byte) (params []byte, offset int, ok bool) {
	tag, outOff, _, _, err := tlvAt(pkt, 0) // outer SEQUENCE
	if err != nil || tag != 0x30 {
		return nil, 0, false
	}
	// version
	_, _, _, next, err := tlvAt(pkt[outOff:], outOff)
	if err != nil {
		return nil, 0, false
	}
	// msgGlobalData
	_, _, _, next, err = tlvAt(pkt[next:], next)
	if err != nil {
		return nil, 0, false
	}
	// msgSecurityParameters OCTET STRING
	tag, secOff, _, _, err := tlvAt(pkt[next:], next)
	if err != nil || tag != 0x04 {
		return nil, 0, false
	}
	// USM SEQUENCE inside the OCTET STRING
	tag, usmOff, _, _, err := tlvAt(pkt[secOff:], secOff)
	if err != nil || tag != 0x30 {
		return nil, 0, false
	}
	// engineID, boots, time, userName, authParams
	_, _, _, n2, err := tlvAt(pkt[usmOff:], usmOff) // engineID
	if err != nil {
		return nil, 0, false
	}
	_, _, _, n2, err = tlvAt(pkt[n2:], n2) // boots
	if err != nil {
		return nil, 0, false
	}
	_, _, _, n2, err = tlvAt(pkt[n2:], n2) // time
	if err != nil {
		return nil, 0, false
	}
	_, _, _, n2, err = tlvAt(pkt[n2:], n2) // userName
	if err != nil {
		return nil, 0, false
	}
	tag, apOff, apLen, _, err := tlvAt(pkt[n2:], n2) // authParams OCTET STRING
	if err != nil || tag != 0x04 {
		return nil, 0, false
	}
	return pkt[apOff : apOff+apLen], apOff, true
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// ---- receiver (Collector) --------------------------------------------------

// trapReceiver is the passive UDP/162 listener. It implements the Collector
// interface so the Pool manages its lifecycle and surfaces its health in the
// Collectors view, but unlike the pollers it emits LOG events (onto the bus via
// the Vector HTTP source), not metrics.
type trapReceiver struct {
	addr    string
	sinkURL string
	targets TargetFunc
	events  chan *TrapEvent

	mu       sync.RWMutex
	status   Status
	received uint64
	decoded  uint64
}

// NewTrapReceiver builds the SNMP trap receiver. Listens on SNMP_TRAP_LISTEN
// (default :1162 — an unprivileged port; compose maps host 162→1162 so the
// distroless nonroot API needn't bind a privileged port). Decoded traps are
// POSTed to SNMP_TRAP_SINK_URL (the Vector aggregator's HTTP source).
func NewTrapReceiver(targets TargetFunc) Collector {
	addr := os.Getenv("SNMP_TRAP_LISTEN")
	if addr == "" {
		addr = ":1162"
	}
	sink := os.Getenv("SNMP_TRAP_SINK_URL")
	if sink == "" {
		sink = "http://vector-aggregator:8688/"
	}
	return &trapReceiver{
		addr:    addr,
		sinkURL: sink,
		targets: targets,
		events:  make(chan *TrapEvent, 1024),
		status:  Status{Name: "snmptrap", Kind: "trap", Healthy: true},
	}
}

func (r *trapReceiver) Name() string { return "snmptrap" }

func (r *trapReceiver) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := r.status
	s.Targets = int(r.received)
	s.Reachable = int(r.decoded)
	return s
}

// resolve maps a source IP to its inventory device (for device id + v3 creds).
func (r *trapReceiver) resolve(ip string) (Target, bool) {
	if r.targets == nil {
		return Target{}, false
	}
	for _, t := range r.targets() {
		host := t.Address
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == ip {
			return t, true
		}
	}
	return Target{}, false
}

func (r *trapReceiver) Run(ctx context.Context) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", r.addr)
	if err != nil {
		r.mu.Lock()
		r.status.Healthy = false
		r.status.LastError = err.Error()
		r.mu.Unlock()
		return err
	}
	defer pc.Close()
	go func() { <-ctx.Done(); _ = pc.Close() }()
	go r.forwardLoop(ctx)

	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		srcIP := src.String()
		if h, _, e := net.SplitHostPort(srcIP); e == nil {
			srcIP = h
		}
		r.mu.Lock()
		r.received++
		r.mu.Unlock()

		ev, derr := decodeTrap(pkt, srcIP, r.resolve)
		if derr != nil {
			r.mu.Lock()
			r.status.LastError = derr.Error()
			r.mu.Unlock()
			continue
		}
		r.mu.Lock()
		r.decoded++
		r.status.LastTick = time.Now().UTC()
		r.status.LastError = ""
		r.mu.Unlock()

		select {
		case r.events <- ev:
		default: // bounded queue — drop under flood (backpressure, §9)
		}
	}
}

func (r *trapReceiver) forwardLoop(ctx context.Context) {
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-r.events:
			r.forward(ctx, client, ev)
		}
	}
}

func (r *trapReceiver) forward(ctx context.Context, client *http.Client, ev *TrapEvent) {
	deriveEnvelope(ev) // fill the NormalizedEvent envelope (#32) just before emit
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	// #nosec G704 -- sinkURL is the operator-configured Vector log-bus source, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.sinkURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		r.mu.Lock()
		r.status.LastError = "forward: " + err.Error()
		r.mu.Unlock()
		return
	}
	_ = resp.Body.Close()
}
