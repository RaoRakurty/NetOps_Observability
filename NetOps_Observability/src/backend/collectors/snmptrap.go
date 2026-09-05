package collectors

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/subtle"
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

	"netops/backend/safego"
)

// snmptrap.go — the SNMP trap/inform receiver. Unlike the pollers (which GET
// over UDP/161), this is a passive listener on UDP/162 that decodes the
// asynchronous notifications devices PUSH (linkDown, authenticationFailure,
// coldStart, vendor-specific). Traps are log/event-shaped, not metrics, so the
// receiver normalizes each one to a structured event and forwards it onto the
// EXISTING log bus (an HTTP source on the Vector aggregator → the Kafka bus
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

	// Truncation provenance (audit PIPE-MED-8). A trap is an UNAUTHENTICATED UDP
	// datagram from an untrusted source: v1/v2c are spoofable, and a single 65 KB
	// packet can carry thousands of varbinds or one 64 KB OCTET STRING. We bound
	// it (maxTrapVarbinds / maxVarbindValueChars / maxTrapMessageChars) — but a
	// bounded record must never be indistinguishable from a complete one, so the
	// event CARRIES the fact that it was cut (CLAUDE.md §10, no silent failures).
	VarbindsDropped int  `json:"varbinds_dropped,omitempty"` // varbinds beyond the cap
	Truncated       bool `json:"truncated,omitempty"`        // any cap applied to this trap

	// NormalizedEvent envelope (#32) — vendor-agnostic structure every trap emits,
	// so Events/Correlation read parsed fields instead of re-decoding raw OIDs.
	// Design: docs/design/research/telemetry-normalization-architecture.md §3.
	Vendor           string            `json:"vendor,omitempty"`            // from the enterprise OID arc
	EventType        string            `json:"event_type,omitempty"`        // normalized leaf (trap name → snake)
	Category         string            `json:"category,omitempty"`          // taxonomy tier-1 (layer2/control_plane/…)
	Family           string            `json:"family,omitempty"`            // taxonomy tier-2 (mac_fdb/bgp/…)
	Summary          string            `json:"summary,omitempty"`           // operator-friendly one-liner
	MessageKey       string            `json:"message_key,omitempty"`       // stable dedup identity (never raw text)
	ParserStatus     string            `json:"parser_status,omitempty"`     // decoded | partially_decoded | raw_only
	EnrichmentStatus string            `json:"enrichment_status,omitempty"` // inventory_matched | inventory_missing
	UptimeSeconds    float64           `json:"sys_uptime_seconds,omitempty"`
	UptimeHuman      string            `json:"sys_uptime_human,omitempty"`
	Fields           map[string]string `json:"fields,omitempty"` // extracted typed context (vlan/mac/port…)

	// agentAddr is the v1 Trap-PDU agent-address — the originating device's OWN
	// IP, set inside the PDU by the device, so it SURVIVES NAT (unlike the packet
	// source IP). Unexported: package-internal device attribution only, never
	// serialized. (v2c/v3 traps have no agent-addr; identity comes from sysName.)
	agentAddr string
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
	return vendorForEnterprise(n)
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
// dot1q/dot1d forwarding-DB column prefix — the well-known IETF L2 MAC table.
// Its row index encodes (vlan/fdb-id, 6 MAC bytes), so even when the *trap* OID is
// an undecoded vendor enterprise OID, this standard varbind yields real L2 context.
const fdbColPrefix = "1.3.6.1.2.1.17.7.1.2.2.1." // dot1qTpFdbEntry.<col>.<fdbId>.<mac6>

// extractFDB pulls (vlan/fdb-id, MAC) from a dot1qTpFdb* varbind OID suffix.
func extractFDB(oid string) (vlan, mac string, ok bool) {
	if !strings.HasPrefix(oid, fdbColPrefix) {
		return "", "", false
	}
	arcs := strings.Split(oid[len(fdbColPrefix):], ".") // <col>.<fdbId>.<m1..m6>
	if len(arcs) < 8 {
		return "", "", false
	}
	mb := make([]string, 6)
	for i, a := range arcs[2:8] {
		n, err := strconv.Atoi(a)
		if err != nil || n < 0 || n > 255 {
			return "", "", false
		}
		mb[i] = fmt.Sprintf("%02X", n)
	}
	return arcs[1], strings.Join(mb, ":"), true
}

// uptimeHuman renders sysUpTime seconds as "3d 14h 50m".
func uptimeHuman(sec float64) string {
	s := int64(sec)
	d, h, m := s/86400, (s%86400)/3600, (s%3600)/60
	if d > 0 {
		return fmt.Sprintf("%dd %dh %dm", d, h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// familyFor maps a decoded event_type token to a (category, family) taxonomy pair
// for the high-value families (interim until the shared taxonomy data file lands).
func familyFor(etype string) (category, family string) {
	switch {
	case strings.Contains(etype, "bgp"):
		return "control_plane", "bgp"
	case strings.Contains(etype, "ospf"):
		return "control_plane", "ospf"
	case strings.Contains(etype, "isis"):
		return "control_plane", "isis"
	case strings.Contains(etype, "link"):
		return "data_plane", "link_state"
	case strings.Contains(etype, "coldstart") || strings.Contains(etype, "warmstart") || strings.Contains(etype, "restart"):
		return "platform_health", "restart"
	case strings.Contains(etype, "auth"):
		return "security", "auth_fail"
	case strings.Contains(etype, "mac") || strings.Contains(etype, "fdb") || strings.Contains(etype, "bridge") || strings.Contains(etype, "move"):
		return "layer2", "mac_fdb"
	}
	return "", ""
}

// deriveEnvelope fills the NormalizedEvent envelope from the decoded trap. Vendor-
// agnostic; produces partially_decoded (not raw_only) whenever a standard varbind
// or L2/MAC structure is decodable even if the vendor trap OID itself isn't.
func deriveEnvelope(ev *TrapEvent) {
	ev.Vendor = vendorFromOID(ev.TrapOID)
	decoded := ev.TrapName != "" && ev.TrapName != "enterpriseSpecific"
	if decoded {
		ev.EventType = camelToSnake(ev.TrapName)
		ev.Category, ev.Family = familyFor(ev.EventType)
	} else {
		ev.EventType = "enterprise_specific"
	}

	anyVarbind := false
	for _, vb := range ev.Varbinds {
		if vb.Name != "" {
			anyVarbind = true
		}
		if vb.Name == "sysUpTime" || strings.HasPrefix(vb.OID, "1.3.6.1.2.1.1.3") || strings.HasPrefix(vb.OID, "1.3.6.1.6.3.1.1.4.1") {
			if t, err := strconv.ParseFloat(vb.Value, 64); err == nil && t > 0 {
				ev.UptimeSeconds = t / 100.0
				ev.UptimeHuman = uptimeHuman(ev.UptimeSeconds)
			}
		}
		if vlan, mac, ok := extractFDB(vb.OID); ok {
			if ev.Fields == nil {
				ev.Fields = map[string]string{}
			}
			ev.Fields["vlan"], ev.Fields["mac"], ev.Fields["bridge_port"] = vlan, mac, vb.Value
			ev.Category, ev.Family = "layer2", "mac_fdb"
			anyVarbind = true
			if !decoded {
				ev.EventType = "l2_fdb_event"
			}
		}
	}

	switch {
	case decoded:
		ev.ParserStatus = "decoded"
	case anyVarbind || len(ev.Fields) > 0:
		ev.ParserStatus = "partially_decoded"
	default:
		ev.ParserStatus = "raw_only"
	}
	if ev.Device != "" {
		ev.EnrichmentStatus = "inventory_matched"
	} else {
		ev.EnrichmentStatus = "inventory_missing"
	}

	who := ev.Device
	if who == "" {
		who = ev.Host
	}
	// message_key: stable dedup identity (never raw text). Discriminator keeps
	// distinct L2 objects distinct: snmptrap:<vendor>:<src>:<trap_oid>[:vlanN:mac].
	parts := []string{"snmptrap"}
	for _, p := range []string{ev.Vendor, who, ev.TrapOID} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if ev.Fields["vlan"] != "" && ev.Fields["mac"] != "" {
		parts = append(parts, "vlan"+ev.Fields["vlan"], strings.ToLower(ev.Fields["mac"]))
	}
	ev.MessageKey = strings.Join(parts, ":")

	// operator-friendly summary
	if ev.Family == "mac_fdb" {
		kind := "Layer-2 FDB"
		if strings.Contains(ev.EventType, "move") || strings.Contains(ev.TrapName, "Move") {
			kind = "MAC-move"
		}
		ev.Summary = fmt.Sprintf("%s%s trap for MAC %s on VLAN/FDB %s, bridge port %s",
			vendorTitle(ev.Vendor), kind, ev.Fields["mac"], ev.Fields["vlan"], ev.Fields["bridge_port"])
	} else if decoded {
		ev.Summary = strings.TrimSpace(vendorTitle(ev.Vendor) + ev.TrapName)
	}
}

// vendorLabel returns a capitalized vendor prefix ("Arista ") or "" for use in
// summaries.
func vendorTitle(v string) string {
	if v == "" {
		return ""
	}
	return strings.ToUpper(v[:1]) + v[1:] + " "
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

// Bounds on one trap (audit PIPE-MED-8). A 65 KB UDP datagram from an
// unauthenticated source can hold ~10k two-byte varbinds, or one 64 KB OCTET
// STRING that valStr then DOUBLES to ~131 KB of hex — all of which finalizeTrap
// used to concatenate into a single ev.Message and hand to OpenSearch verbatim.
const (
	// maxTrapVarbinds bounds the varbind COUNT. Real traps carry a handful;
	// SNMPv2-MIB requires 2 (sysUpTime.0 + snmpTrapOID.0) plus the notification's
	// own objects. 64 is far above any legitimate notification and far below the
	// thousands a hostile packet can pack in.
	maxTrapVarbinds = 64
	// maxVarbindValueChars bounds ONE decoded varbind value.
	maxVarbindValueChars = 512
	// maxTrapOIDChars bounds a dotted OID. A real MIB OID is well under 100 chars;
	// this only fires on a hostile OID with hundreds of arcs.
	maxTrapOIDChars = 256
	// maxTrapMessageChars bounds the concatenated human message. With the count and
	// per-value caps this is already implied; it is belt-and-braces so no future
	// change to the message format can reintroduce an unbounded field.
	maxTrapMessageChars = 4096
)

func oidString(arcs []int) string {
	parts := make([]string, len(arcs))
	for i, a := range arcs {
		parts[i] = fmt.Sprintf("%d", a)
	}
	return clampOID(strings.Join(parts, "."))
}

// clampOID bounds a dotted OID, cutting at an ARC boundary. Cutting mid-digit
// would silently rename the object (".9" of a truncated arc is a different OID),
// so the last partial arc is dropped entirely; an over-long OID then simply fails
// the MIB lookup and reads as enterpriseSpecific — honest, not wrong.
func clampOID(s string) string {
	if len(s) <= maxTrapOIDChars {
		return s
	}
	s = s[:maxTrapOIDChars]
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		return s[:i]
	}
	return s
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
		return octetStr(raw)
	case 0x05: // NULL
		return ""
	default:
		return octetStr(raw)
	}
}

// octetStr renders an OCTET STRING (or an unknown tag's payload), BOUNDED. The
// hex branch caps the RAW BYTES first because hex doubles the length — a 64 KB
// varbind rendered as hex is 131 KB, which is what made one trap able to blow up
// an OpenSearch document (audit PIPE-MED-8).
func octetStr(raw []byte) string {
	if isPrintable(raw) {
		return clampRunes(string(raw), maxVarbindValueChars)
	}
	if len(raw) > maxVarbindValueChars/2 {
		raw = raw[:maxVarbindValueChars/2]
	}
	return "0x" + hex.EncodeToString(raw)
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c != '\t' && c != '\n' && c != '\r' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// parseVarbinds walks a VarBindList SEQUENCE content into decoded bindings, at
// most maxTrapVarbinds of them. `dropped` counts the bindings past the cap so the
// caller can stamp the truncation onto the event rather than lose it silently
// (CLAUDE.md §10 / §9 bounded queues — audit PIPE-MED-8).
func parseVarbinds(vbList []byte) (out []TrapVarbind, dropped int) {
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
		if len(out) >= maxTrapVarbinds {
			// Keep walking so the count is HONEST (how many were really sent),
			// but stop accumulating — the memory/document bound is the point.
			dropped++
			continue
		}
		oid := oidString(decodeOID(oidRaw))
		name, val := resolveVarbind(oid, valStr(valTag, valRaw))
		out = append(out, TrapVarbind{OID: oid, Name: sanitizeLabel(name), Value: val})
	}
	return out, dropped
}

// finalizeTrap fills the trap OID / name / severity / message from the varbinds
// (v2/v3: the snmpTrapOID.0 binding names the trap) and trims it out of the list.
func finalizeTrap(ev *TrapEvent, vbs []TrapVarbind, dropped int) {
	if dropped > 0 {
		ev.VarbindsDropped = dropped
		ev.Truncated = true
	}
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
	if dropped > 0 {
		parts = append(parts, fmt.Sprintf("(+%d varbinds dropped: trap exceeded the %d-varbind cap)",
			dropped, maxTrapVarbinds))
	}
	ev.Message = boundMessage(ev, strings.Join(parts, " "))
}

// boundMessage caps the concatenated trap message and RECORDS that it capped —
// a truncated message must not read as a complete one (CLAUDE.md §10).
func boundMessage(ev *TrapEvent, msg string) string {
	out := clampRunes(msg, maxTrapMessageChars)
	if len(out) != len(msg) {
		ev.Truncated = true
	}
	return out
}

// decodeV2StylePDU reads request-id, error-status, error-index, then varbinds
// from an SNMPv2-Trap-PDU / Inform-PDU body and returns the varbinds plus the
// number dropped by the varbind-count cap (parseVarbinds).
func decodeV2StylePDU(pduBody []byte) ([]TrapVarbind, int, error) {
	_, _, r, err := readTLV(pduBody) // request-id
	if err != nil {
		return nil, 0, err
	}
	_, _, r, err = readTLV(r) // error-status
	if err != nil {
		return nil, 0, err
	}
	_, _, r, err = readTLV(r) // error-index
	if err != nil {
		return nil, 0, err
	}
	_, vbList, _, err := readTLV(r) // variable-bindings SEQUENCE
	if err != nil {
		return nil, 0, err
	}
	vbs, dropped := parseVarbinds(vbList)
	return vbs, dropped, nil
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
	if ip := decodeIP(agentRaw); ip != "" {
		// agent-addr is the device's OWN address (NAT-surviving) — kept for device
		// attribution (attributeDevice). Only stand in for Host if none is known.
		ev.agentAddr = ip
		if ev.Host == "" {
			ev.Host = ip
		}
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
	vbs, dropped := parseVarbinds(vbList)
	ev.Varbinds = vbs
	if dropped > 0 {
		ev.VarbindsDropped = dropped
		ev.Truncated = true
	}
	parts := []string{ev.TrapName, ev.TrapOID}
	for _, vb := range vbs {
		parts = append(parts, vb.OID+"="+vb.Value)
	}
	if dropped > 0 {
		parts = append(parts, fmt.Sprintf("(+%d varbinds dropped: trap exceeded the %d-varbind cap)",
			dropped, maxTrapVarbinds))
	}
	ev.Message = boundMessage(ev, strings.Join(parts, " "))
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
	// Primary device attribution: the source IP, resolved fail-closed (a unique
	// inventory match — a device trapping from its own management address, the
	// non-NAT norm). When the source is unknown or an ambiguous shared NAT gateway,
	// this leaves Device empty and attributeDevice (post-decode, in Run) rescues the
	// identity from the PDU itself — sysName / v1 agent-addr, both NAT-surviving.
	// For v1/v2c the attribution is CONFIRMED against the device's community once
	// decoded (guardTrapCommunity, M4) — the source IP alone is spoofable UDP.
	var srcTG Target
	srcKnown := false
	if resolve != nil {
		if tg, ok := resolve(srcIP); ok {
			srcTG, srcKnown = tg, true
			ev.Device = tg.ID
		}
	}
	switch decodeInt(verRaw) {
	case 0: // SNMPv1
		ev.Version = "v1"
		commTag, commRaw, r, err := readTLV(rest) // community
		if err != nil || commTag != 0x04 {
			return nil, fmt.Errorf("snmptrap: v1 community")
		}
		ev.Community = string(commRaw)
		guardTrapCommunity(ev, srcKnown, srcTG)
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
		guardTrapCommunity(ev, srcKnown, srcTG)
		pduTag, pduBody, _, err := readTLV(r)
		if err != nil {
			return nil, err
		}
		if pduTag != 0xA7 && pduTag != 0xA6 { // SNMPv2-Trap-PDU / Inform-PDU
			return nil, fmt.Errorf("snmptrap: v2c pdu tag %#x", pduTag)
		}
		vbs, dropped, err := decodeV2StylePDU(pduBody)
		if err != nil {
			return nil, err
		}
		finalizeTrap(ev, vbs, dropped)
		return ev, nil

	case 3: // SNMPv3
		ev.Version = "v3"
		return decodeTrapV3(ev, pkt, resolve)

	default:
		return nil, fmt.Errorf("snmptrap: unsupported version")
	}
}

// guardTrapCommunity drops the source-IP device attribution when a v1/v2c
// trap's community does not verify against the resolved device's expected
// community (M4). The community is the ONLY authenticator those versions have:
// the trap receiver stored it "for audit" but never compared it, so any host
// that could reach :162 claimed a known device's identity — and every consumer
// downstream (events, correlation, RCA) filed the forged evidence under the
// real device. The trap itself is kept (evidence under its source host, the
// honest-unknown convention) — only the claimed identity is refused.
func guardTrapCommunity(ev *TrapEvent, srcKnown bool, tg Target) {
	if !srcKnown || ev.Device == "" {
		return
	}
	if !communityMatchesDevice(ev.Community, tg) {
		ev.Device = ""
	}
}

// communityMatchesDevice reports whether a v1/v2c trap community proves the
// sender knows the device's configured community. The expected value resolves
// exactly the way the poller's creds() does (per-device community, then the
// SNMP_COMMUNITY env default, then "public"). A v3-configured device has no
// v2c identity to claim — fail closed. Constant-time compare: the community is
// a shared secret, and a byte-at-a-time equality would let a sender oracle it.
func communityMatchesDevice(community string, tg Target) bool {
	if community == "" || tg.SNMPVersion == 3 {
		return false
	}
	want := tg.creds().Community
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(community), []byte(want)) == 1
}

// trapIdentityTrusted reports whether this trap presents enough proof to claim
// device t's identity from INSIDE the PDU (sysName varbind / v1 agent-addr).
// Those rescue paths survive NAT precisely because they trust packet CONTENT —
// which any host that can reach :162 controls — so a forged sysName varbind
// must not be enough to file an event under a real inventory device (M4):
// v1/v2c must present the device's community; v3 must have a verified HMAC
// (or the device be explicitly configured noAuthNoPriv — nothing to verify,
// the same trust it always had).
func trapIdentityTrusted(ev *TrapEvent, t Target) bool {
	switch ev.Version {
	case "v1", "v2c":
		return communityMatchesDevice(ev.Community, t)
	case "v3":
		return ev.Authenticated || (t.SNMPVersion == 3 && t.V3Level == "noAuthNoPriv")
	default:
		return false // no wire identity proof at all
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
	// A device CONFIGURED for an authenticated level whose auth key is missing
	// or unusable must NOT fall through to the cleartext path below: that would
	// accept (and attribute) an unauthenticated trap for a device the operator
	// explicitly required authPriv/authNoPriv from — a forgeable downgrade (M4).
	if creds.isV3() && creds.Level != "" && creds.Level != "noAuthNoPriv" && !creds.wantsAuth() {
		return nil, fmt.Errorf("snmptrap: v3 trap from %s: device requires %s but has no usable auth key — refusing unauthenticated trap", ev.Host, creds.Level)
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
	vbs, dropped, err := decodeV2StylePDU(pduBody)
	if err != nil {
		return nil, err
	}
	finalizeTrap(ev, vbs, dropped)
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
// FAIL-CLOSED on ambiguity: if the IP matches more than one distinct device — the
// signature of a shared trap source (a NAT gateway / proxy fronting many devices) —
// it returns no match rather than guessing one. A wrong attribution is worse than an
// honest unknown: it would let one device's trap masquerade as another's evidence
// (and, in the correlation verdict gate, manufacture false cross-device independence).
func (r *trapReceiver) resolve(ip string) (Target, bool) {
	if r.targets == nil {
		return Target{}, false
	}
	var match Target
	n := 0
	for _, t := range r.targets() {
		host := t.Address
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == ip {
			if n == 0 || t.ID != match.ID {
				n++
				match = t
			}
		}
	}
	if n == 1 {
		return match, true
	}
	return Target{}, false // 0 = unknown source, >1 = ambiguous shared source
}

// _trapSysNameOID is sysName.0 (RFC 3418) — the device's OWN configured hostname.
// When a trap carries it, it identifies the originator BY NAME, independent of the
// packet source IP, so it survives NAT (the same way syslog recovers the RFC5424
// hostname from the message body).
const _trapSysNameOID = "1.3.6.1.2.1.1.5"

// trapSysName returns the sysName.0 varbind value, or "" if the trap carries none.
func trapSysName(ev *TrapEvent) string {
	for _, vb := range ev.Varbinds {
		if vb.OID == _trapSysNameOID+".0" || vb.OID == _trapSysNameOID ||
			strings.EqualFold(vb.Name, "sysName") {
			return strings.TrimSpace(vb.Value)
		}
	}
	return ""
}

// attributeDevice resolves a trap to its canonical inventory device id, so the
// correlation entity_id/observer_id (device[:ifName]) is consistent with every other
// producer (G2 — correlation-engine.md §4.2). decodeTrap has already tried the source
// IP (fail-closed on an ambiguous shared NAT source); this RESCUES the identity from
// inside the PDU when the source IP didn't resolve — both signals survive NAT:
//
//  1. sysName.0 varbind matched (case-insensitively) to a device's stored
//     name — or its id, for inventory whose id IS its name — by NAME.
//  2. v1 agent-addr resolved by IP — the device's own address inside the PDU.
//
// When nothing resolves, Device stays "" — an honest unknown: the producer keeps the
// trap as evidence under its source host, never a guessed device. EnrichmentStatus
// records the outcome for observability. Idempotent; safe to call once per trap.
func (r *trapReceiver) attributeDevice(ev *TrapEvent, srcIP string) {
	if ev.Device == "" && r.targets != nil {
		// M4: both rescues read attacker-controlled PDU content, so each is
		// gated on the trap PROVING the claimed device's identity
		// (trapIdentityTrusted: community match for v1/v2c, verified HMAC for
		// v3). Without the gate, a forged trap carrying a victim's sysName from
		// any unknown source became that device's evidence.
		if sn := trapSysName(ev); sn != "" {
			for _, t := range r.targets() {
				// Match on the STORED name (the raw sysName the inventory holds)
				// first: scan-device ids are ScanDeviceID(sysName, addr) —
				// sanitized + address-hash-suffixed — so the on-wire sysName
				// (e.g. "core-sw#1") never equal-folds an id like
				// "core-sw-1-9f3a2b". The id compare stays for devices whose id
				// IS their name (static/operator-created inventory). Either way
				// the trap must still PROVE the identity (M4 gate below).
				if (strings.EqualFold(t.Name, sn) || strings.EqualFold(t.ID, sn)) && trapIdentityTrusted(ev, t) {
					ev.Device = t.ID
					break
				}
			}
		}
		if ev.Device == "" && ev.agentAddr != "" && ev.agentAddr != srcIP {
			if tg, ok := r.resolve(ev.agentAddr); ok && trapIdentityTrusted(ev, tg) {
				ev.Device = tg.ID
			}
		}
	}
	if ev.Device != "" {
		ev.EnrichmentStatus = "inventory_matched"
	} else {
		ev.EnrichmentStatus = "inventory_missing"
	}
}

// decodePacket decodes and attributes ONE datagram, with panic recovery.
//
// Everything below it is hand-rolled BER/ASN.1 offset arithmetic over
// UNAUTHENTICATED UDP — anything that can reach :162 controls those bytes. An
// out-of-range slice there would otherwise be remote, pre-auth termination of
// the whole API process. A poisoned packet must cost exactly that packet: it is
// counted as a decode error and the receiver keeps listening.
func (r *trapReceiver) decodePacket(pkt []byte, srcIP string) (ev *TrapEvent, err error) {
	completed := safego.Run(safego.Stderr, "snmptrap-decode", func() {
		ev, err = decodeTrap(pkt, srcIP, r.resolve)
		if err != nil || ev == nil {
			return
		}
		r.attributeDevice(ev, srcIP)
	})
	if !completed {
		return nil, fmt.Errorf("snmptrap: decoder panicked on %d-byte packet from %s", len(pkt), srcIP)
	}
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, fmt.Errorf("snmptrap: decoder returned no event")
	}
	return ev, nil
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
	safego.Go("snmptrap-closer", func() { <-ctx.Done(); _ = pc.Close() }) // ctx teardown; nothing actionable
	safego.Go("snmptrap-forward-loop", func() { r.forwardLoop(ctx) })

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

		// Canonicalize the originating device (sysName / agent-addr / source IP) so
		// trap evidence binds to the same entity id as every other producer (G2).
		ev, derr := r.decodePacket(pkt, srcIP)
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
	client := meshHTTPClient(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-r.events:
			// Same reasoning as decodePacket: the envelope derivation runs over
			// attacker-supplied fields, and this loop must outlive any one event.
			safego.Run(safego.Stderr, "snmptrap-forward", func() { r.forward(ctx, client, ev) })
		}
	}
}

func (r *trapReceiver) forward(ctx context.Context, client *http.Client, ev *TrapEvent) {
	deriveEnvelope(ev) // fill the NormalizedEvent envelope (#32) just before emit
	// Pipeline-debugger parser decision trace (parsehook.go). Deliberately HERE
	// and not inside finalizeTrap: the decision path an operator needs includes
	// the normalisation deriveEnvelope performs (event_type, category, family,
	// parser_status), and finalizeTrap runs before any of it exists. No-op
	// unless the record carries a cx_debug marker or an operator armed the
	// filter — one strings.Index on the message otherwise.
	traceTrapDecision(ev)
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
	SetIngestAuth(req, LaneTraps) // F-08
	resp, err := client.Do(req)
	if err != nil {
		r.mu.Lock()
		r.status.LastError = "forward: " + err.Error()
		r.mu.Unlock()
		return
	}
	// F-08: same gap as the probe lane — the status was discarded, so a
	// rejected trap looked exactly like a delivered one. Surface it on the
	// receiver's own status (which /api/collectors already renders) as well as
	// in the shared counter, because a trap has no upstream that can replay it.
	if resp.StatusCode >= 300 {
		logIngestRejection("snmptrap", r.sinkURL, resp.StatusCode)
		r.mu.Lock()
		r.status.LastError = fmt.Sprintf("forward: sink rejected with status %d", resp.StatusCode)
		r.mu.Unlock()
	}
	_ = resp.Body.Close() // best-effort: nothing actionable on close failure
}
