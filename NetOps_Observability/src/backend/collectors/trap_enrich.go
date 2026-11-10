// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"encoding/hex"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// trap_enrich.go — the fields an operator reads first (tracker 387, trap
// semantics; owner 2026-11-10: "what happened, which device/peer was affected,
// whether it matters, and what to investigate next, without interpreting raw MIB
// OIDs"). Everything is derived from the varbinds through the OID index and the
// packs, BESIDE them: a varbind's OID and raw value are never rewritten. A field
// that cannot be filled truthfully is absent, never a placeholder.
//
// UI FIELD CONTRACT (flat unless noted):
//
//	title, title_basis            one sentence; templated | fallback (old summary)
//	device_name                   the inventory's display name for the device
//	native_severity               the vendor's own words, e.g. critical(1)
//	                              (severity / severity_native_* stay as they were)
//	metrics{name:{value,basis,formula?,unit?}}  observed | derived numbers,
//	                              range-checked; metrics_invalid[] names the refused
//	threshold_reported_percent    the threshold the device's message states;
//	threshold_basis               always reported_by_device (never "configured")
//	device_event_time, received_time, observed_delay_s, delay_basis
//	                              (device_clock_vs_receive: not network latency)
//	device_uptime_s, device_uptime_human
//	correlation_key               <family>:<device>:<entity>
//	event_id                      = message_key
//	lifecycle_state, lifecycle_basis, recovery_verified
//	auth_model                    community | usm (authenticated keeps its meaning)
//	event_severity, op_state, impact   three separate answers, none a priority
//	if_admin_status, if_oper_status
//	bgp{peer_address, peer_afi, peer_as?, local_address?, vrf?, prev_state?,
//	    prev_state_basis?, state, transition_class, peer_basis, last_error*}
//	transition_id, transition_seq, transition_representative, occurrence_count,
//	first_seen, last_seen
//	guidance{impact[], next_checks[], basis: pack_guidance}
//	enrichment{fields_observed[], fields_derived[], fields_guidance[], unknown[]}
//	varbinds[]{oid, name, type, value, raw_value, decoded, ...}

// Peer bases, the closed set of bgp.peer_basis.
const (
	peerFromIndex      = "index"             // the row index, by the MIB's INDEX clause
	peerFromVendorForm = "index_vendor_form" // the row index, in a pack-stated vendor form
	peerFromVarbind    = "varbind"           // a varbind's value
	peerUnparsed       = "unparsed"          // a peer was sent, and did not decode
	peerAbsent         = "absent"            // the BGP event names no peer
)

// Title bases, the closed set of title_basis.
const (
	titleTemplated = "templated"
	titleFallback  = "fallback"
)

// TrapMetric is one typed number with its provenance.
type TrapMetric struct {
	Value   float64 `json:"value"`
	Basis   string  `json:"basis"` // observed | derived
	Formula string  `json:"formula,omitempty"`
	Unit    string  `json:"unit,omitempty"`
}

// TrapBGP is a BGP session event's meaning (BGP families only).
type TrapBGP struct {
	PeerAddress      string `json:"peer_address,omitempty"`
	PeerAFI          string `json:"peer_afi,omitempty"`
	PeerAS           *int64 `json:"peer_as,omitempty"`
	LocalAddress     string `json:"local_address,omitempty"`
	VRF              string `json:"vrf,omitempty"`
	PrevState        string `json:"prev_state,omitempty"`
	PrevStateBasis   string `json:"prev_state_basis,omitempty"`
	State            string `json:"state,omitempty"`
	TransitionClass  string `json:"transition_class,omitempty"`
	PeerBasis        string `json:"peer_basis"`
	LastErrorCode    *int   `json:"last_error_code,omitempty"`
	LastErrorSubcode *int   `json:"last_error_subcode,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	LastErrorText    string `json:"last_error_text,omitempty"`
}

// TrapGuidance is what such an event usually means and what to check: written
// per family in the packs, never a diagnosis of this event.
type TrapGuidance struct {
	Impact     []string `json:"impact"`
	NextChecks []string `json:"next_checks"`
	Basis      string   `json:"basis"`
}

// TrapEnrichment says where each enriched field came from.
type TrapEnrichment struct {
	FieldsObserved []string `json:"fields_observed"`
	FieldsDerived  []string `json:"fields_derived"`
	FieldsGuidance []string `json:"fields_guidance"`
	Unknown        []string `json:"unknown"`
}

// trapAttr is one meaning read from a trap, with where it came from.
type trapAttr struct {
	val, basis string
}

// collectTrapAttrs reads every pack meaning a trap carries. The row index is
// structural, so it wins over a varbind value that states the same meaning;
// within each source the first binding wins.
func collectTrapAttrs(ev *TrapEvent, sem *trapSemantics) {
	fromIndex := map[string]trapAttr{}
	fromValue := map[string]trapAttr{}
	peerFailed := false
	decoded := map[string]bool{}
	set := func(m map[string]trapAttr, k, v, basis string) {
		if v == "" {
			return
		}
		if _, seen := m[k]; !seen {
			m[k] = trapAttr{val: v, basis: basis}
		}
	}
	for _, vb := range ev.Varbinds {
		raw := vb.Raw
		if raw == "" {
			raw = vb.Value
		}
		if n, suffix, ok := lookupOID(vb.OID); ok && n.Kind == "column" && suffix != "" && len(n.IndexSyntax) > 0 {
			col := strings.TrimSuffix(vb.OID, "."+suffix)
			entry := col
			if i := strings.LastIndexByte(col, '.'); i > 0 {
				entry = col[:i]
			}
			key := entry + "|" + suffix
			if !decoded[key] {
				decoded[key] = true
				if !indexAttrs(n, entry, suffix, sem, func(k, v, basis string) { set(fromIndex, k, v, basis) }) {
					peerFailed = peerFailed || indexNamesPeer(n, sem)
				}
			}
		}
		rule, ok := sem.objects[trapVarbindObject(vb.OID)]
		if !ok || rule.Attr == "" {
			continue
		}
		v, good := attrFromValue(rule.Attr, vb, raw)
		if !good {
			if rule.Attr == "peer_address" && strings.TrimSpace(raw) != "" {
				peerFailed = true
			}
			continue
		}
		set(fromValue, rule.Attr, v, peerFromVarbind)
	}
	for k, v := range fromValue {
		if _, seen := fromIndex[k]; !seen {
			fromIndex[k] = v
		}
	}
	ev.attrs = fromIndex
	ev.peerFailed = peerFailed
}

// indexAttrs decodes one row index and reports each part a pack gives a meaning.
// false = the index did not decode (strictly, or in a pack-stated vendor form).
func indexAttrs(n OIDNode, entry, suffix string, sem *trapSemantics, put func(k, v, basis string)) bool {
	parts, err := decodeTrapIndex(n, suffix)
	if err != nil {
		t, ok := sem.tables[entry]
		if !ok || !t.BareAddressIndex {
			return false
		}
		addr, afi, berr := decodeBareAddressIndex(suffix)
		if berr != nil {
			return false
		}
		named := false
		for _, oid := range n.IndexOIDs {
			if r, ok := sem.objects[oid]; ok && (r.Attr == "peer_address" || r.Attr == "local_address") {
				put(r.Attr, addr, peerFromVendorForm)
				put(strings.TrimSuffix(r.Attr, "_address")+"_afi", afi, peerFromVendorForm)
				named = true
			}
		}
		return named
	}
	for _, p := range parts {
		r, ok := sem.objects[p.OID]
		if !ok || r.Attr == "" {
			continue
		}
		put(r.Attr, p.Text, peerFromIndex)
		if (r.Attr == "peer_address" || r.Attr == "local_address") && p.AFI != "" {
			put(strings.TrimSuffix(r.Attr, "_address")+"_afi", p.AFI, peerFromIndex)
		}
	}
	return true
}

// indexNamesPeer: does this row's index carry the peer (so a failure loses it)?
func indexNamesPeer(n OIDNode, sem *trapSemantics) bool {
	for _, oid := range n.IndexOIDs {
		if r, ok := sem.objects[oid]; ok && r.Attr == "peer_address" {
			return true
		}
	}
	return false
}

// attrFromValue reads a varbind value as a meaning. false = the value does not
// say what the meaning needs (a malformed address, a non-number), never a guess.
func attrFromValue(attr string, vb TrapVarbind, raw string) (string, bool) {
	r := strings.TrimSpace(raw)
	switch attr {
	case "peer_address", "local_address":
		return addressFromValue(r, vb.Type)
	case "peer_afi", "local_afi":
		if l := strings.ToLower(vb.Label); l != "" {
			if _, ok := inetAddressLen[l]; ok || l == "dns" {
				return l, true
			}
		}
		if n, err := strconv.ParseUint(r, 10, 32); err == nil {
			if name, ok := inetAddressTypes[uint32(n)]; ok {
				return name, true
			}
		}
		return "", false
	case "bgp_state", "bgp_prev_state":
		s := normalizeBGPState(vb.Label, r)
		return s, s != ""
	case "peer_as", "bgp_error_code", "bgp_error_subcode":
		n, err := strconv.ParseUint(r, 10, 32)
		if err != nil {
			return "", false
		}
		return strconv.FormatUint(n, 10), true
	case "bgp_last_error":
		if _, _, ok := parseBGPLastError(r); !ok {
			return "", false
		}
		return r, true
	case "bgp_last_error_text":
		t := titleValue(r)
		if strings.HasPrefix(t, "0x") { // a binary blob, not words
			return "", false
		}
		return t, t != ""
	default: // routing_instance, if_*_status: the enum label, else the value
		if vb.Label != "" {
			return titleValue(vb.Label), true
		}
		t := titleValue(r)
		return t, t != ""
	}
}

// addressFromValue reads an address a device sent as a value: text (most MIBs,
// and an IpAddress as the decoder renders it), or InetAddress octets (rendered as
// 0x-hex, or as text when every octet happened to be printable).
func addressFromValue(r, typ string) (string, bool) {
	if a, err := netip.ParseAddr(r); err == nil && a.Zone() == "" {
		return a.Unmap().String(), true
	}
	var b []byte
	if strings.HasPrefix(r, "0x") {
		if h, err := hex.DecodeString(r[2:]); err == nil {
			b = h
		}
	} else if strings.Contains(typ, "InetAddress") || typ == "OCTET STRING" {
		b = []byte(r)
	}
	if len(b) != 4 && len(b) != 16 {
		return "", false
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return "", false
	}
	return a.String(), true
}

// attr returns a collected meaning's value, or "".
func (ev *TrapEvent) attr(k string) string { return ev.attrs[k].val }

// provenance collects which fields came from where, for the enrichment block.
type provenance struct{ observed, derived, guidance, unknown []string }

// applyTrapEnrichment fills the typed fields from the meanings, the metrics and
// the times. The transition class and lifecycle are refined by the caller once
// the receiver's memory has been consulted.
func applyTrapEnrichment(ev *TrapEvent, sem *trapSemantics) {
	ev.attrsProvenance = &provenance{}
	applyTrapMetrics(ev, sem)
	applyTrapTimes(ev)
	if ev.Version == "v3" {
		ev.AuthModel = "usm"
	} else if ev.Version != "" {
		ev.AuthModel = "community"
	}
	if ev.NativeSeverity != "" {
		ev.attrsProvenance.observed = append(ev.attrsProvenance.observed, "native_severity")
	}
	ev.IfAdminStatus = strings.ToLower(ev.attr("if_admin_status"))
	ev.IfOperStatus = strings.ToLower(ev.attr("if_oper_status"))
	for _, f := range []struct{ name, v string }{{"if_admin_status", ev.IfAdminStatus}, {"if_oper_status", ev.IfOperStatus}} {
		if f.v != "" {
			ev.attrsProvenance.observed = append(ev.attrsProvenance.observed, f.name)
		}
	}
	ev.BGP = bgpOf(ev)
	classifyTrapEvent(ev)
}

// bgpOf builds the bgp object, or nil when the trap says nothing about a session.
func bgpOf(ev *TrapEvent) *TrapBGP {
	state := ev.attr("bgp_state")
	if state == "" && ev.attr("peer_address") == "" && !ev.peerFailed {
		return nil
	}
	b := &TrapBGP{
		PeerAddress: ev.attr("peer_address"), PeerAFI: ev.attr("peer_afi"),
		LocalAddress: ev.attr("local_address"), VRF: ev.attr("routing_instance"), State: state,
	}
	if as := ev.attr("peer_as"); as != "" {
		if n, err := strconv.ParseInt(as, 10, 64); err == nil {
			b.PeerAS = &n
		}
	}
	switch {
	case b.PeerAddress != "":
		b.PeerBasis = ev.attrs["peer_address"].basis
	case ev.peerFailed:
		b.PeerBasis = peerUnparsed
	default:
		b.PeerBasis = peerAbsent
	}
	if b.PeerAddress == "" {
		b.PeerAFI = "" // a family with no address names nothing
	}
	if p := ev.attr("bgp_prev_state"); p != "" && state != "" {
		b.PrevState, b.PrevStateBasis = p, bgpPrevFromTrap
	}
	if code, sub, ok := parseBGPLastError(ev.attr("bgp_last_error")); ok && code != 0 {
		b.LastErrorCode, b.LastErrorSubcode = &code, &sub
	} else if code, err := strconv.Atoi(ev.attr("bgp_error_code")); err == nil && code != 0 {
		sub, serr := strconv.Atoi(ev.attr("bgp_error_subcode"))
		if serr != nil {
			sub = 0 // a code with no subcode: RFC 4271 "unspecific"
		}
		b.LastErrorCode, b.LastErrorSubcode = &code, &sub
	}
	if b.LastErrorCode != nil {
		b.LastError = bgpErrorName(*b.LastErrorCode, *b.LastErrorSubcode)
	}
	b.LastErrorText = ev.attr("bgp_last_error_text")
	return b
}

// classifyTrapEvent names the BGP transition and the event's separate severity,
// operational state and impact from what is known now.
func classifyTrapEvent(ev *TrapEvent) {
	ev.EventSeverity, ev.OpState, ev.Impact = "", "", ""
	if b := ev.BGP; b != nil {
		b.TransitionClass = ""
		if b.State != "" {
			b.TransitionClass = classifyBGPTransition(b.PrevState, b.State)
			m := bgpTransitionMeaning[b.TransitionClass]
			ev.EventSeverity, ev.OpState, ev.Impact = m.severity, m.opState, m.impact
		}
		if ev.EventSeverity == "" {
			ev.EventSeverity = ev.Severity // unknown prior state: the MIB's own hint
		}
		return
	}
	// Interfaces: a port an operator shut down is down by intent, which is not a
	// service fault of the port.
	if ev.IfOperStatus != "" {
		ev.OpState = ev.IfOperStatus
		switch {
		case ev.IfOperStatus == "up":
			ev.EventSeverity, ev.Impact = "info", "none"
		case ev.IfAdminStatus == "down":
			ev.EventSeverity, ev.Impact = "notice", "none"
		case ev.IfOperStatus == "down" || ev.IfOperStatus == "lowerlayerdown":
			ev.EventSeverity, ev.Impact = "err", "service_affecting"
		default:
			ev.EventSeverity, ev.Impact = ev.Severity, "unknown"
		}
		return
	}
	ev.EventSeverity = ev.Severity
	switch ev.EventState {
	case trapStateClear:
		ev.OpState, ev.Impact = "recovered", "none"
	case trapStateRaise:
		ev.OpState, ev.Impact = "alarm", "unknown"
	}
}

// inRange: a value inside the rule's declared bounds (open bounds pass).
func inRange(v float64, lo, hi *float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && (lo == nil || v >= *lo) && (hi == nil || v <= *hi)
}

// round2 keeps two decimals, as devices send them (100 - 85.34 is 14.66, not
// 14.659999999999997).
func round2(v float64) float64 { return math.Round(v*100) / 100 }

// applyTrapMetrics builds the metrics block: every number a pack types, range-
// checked, then the pack's derived metrics, then the threshold the device's own
// text reports. A value that does not parse or is out of range is omitted (and
// dropped from the legacy `values` too) and named in metrics_invalid.
func applyTrapMetrics(ev *TrapEvent, sem *trapSemantics) {
	metrics := map[string]TrapMetric{}
	invalid := map[string]bool{}
	for _, vb := range ev.Varbinds {
		obj := trapVarbindObject(vb.OID)
		raw := vb.Raw
		if raw == "" {
			raw = vb.Value
		}
		if rule, ok := sem.objects[obj]; ok && (rule.Type == "float" || rule.Type == "int") {
			if _, seen := metrics[rule.Field]; seen || invalid[rule.Field] {
				continue
			}
			f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err != nil || !inRange(f, rule.Min, rule.Max) || (rule.Type == "int" && f != math.Trunc(f)) {
				invalid[rule.Field] = true
				delete(ev.Values, rule.Field)
				continue
			}
			metrics[rule.Field] = TrapMetric{Value: f, Basis: "observed", Unit: rule.Unit}
		}
		for _, x := range sem.extracts[obj] {
			if ev.ThresholdReportedPercent != nil {
				break
			}
			m := x.re.FindStringSubmatch(raw)
			if m == nil {
				continue
			}
			if f, err := strconv.ParseFloat(m[1], 64); err == nil && inRange(f, x.Min, x.Max) {
				ev.ThresholdReportedPercent = &f
				ev.ThresholdBasis = "reported_by_device"
				ev.attrsProvenance.observed = append(ev.attrsProvenance.observed, "threshold_reported_percent")
			}
		}
	}
	for _, d := range sem.derived {
		src, ok := metrics[d.Of]
		if !ok {
			continue // never derived from a missing or refused value
		}
		v := round2(d.Base - src.Value)
		if !inRange(v, d.Min, d.Max) {
			invalid[d.Field] = true
			continue
		}
		metrics[d.Field] = TrapMetric{Value: v, Basis: "derived", Formula: d.Formula, Unit: d.Unit}
	}
	if len(metrics) > 0 {
		ev.Metrics = metrics
	}
	ev.MetricsInvalid = trapSortedKeys(invalid)
	for name, m := range metrics {
		if m.Basis == "derived" {
			ev.attrsProvenance.derived = append(ev.attrsProvenance.derived, "metrics."+name)
		} else {
			ev.attrsProvenance.observed = append(ev.attrsProvenance.observed, "metrics."+name)
		}
	}
}

func trapSortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// applyTrapTimes separates the device's clock, the receive time and the gap.
// The gap is the device clock against ours: it includes clock skew and agent
// queueing as well as transit, so it is never called latency.
func applyTrapTimes(ev *TrapEvent) {
	ev.ReceivedTime = ev.Timestamp
	if ev.DeviceEventTime != "" {
		ev.attrsProvenance.observed = append(ev.attrsProvenance.observed, "device_event_time")
		dt, err1 := time.Parse(time.RFC3339Nano, ev.DeviceEventTime)
		rt, err2 := time.Parse(time.RFC3339Nano, ev.ReceivedTime)
		if err1 == nil && err2 == nil {
			d := math.Round(rt.Sub(dt).Seconds()*1000) / 1000
			ev.ObservedDelayS, ev.DelayBasis = &d, "device_clock_vs_receive"
			ev.attrsProvenance.derived = append(ev.attrsProvenance.derived, "observed_delay_s")
		}
	}
}

// applyTrapUptime copies the agent's sysUpTime under the contract's names, once
// the envelope has read it.
func applyTrapUptime(ev *TrapEvent) {
	if ev.UptimeSeconds > 0 {
		u := ev.UptimeSeconds
		ev.DeviceUptimeS, ev.DeviceUptimeHuman = &u, ev.UptimeHuman
		ev.attrsProvenance.observed = append(ev.attrsProvenance.observed, "device_uptime_s")
	}
}

// titleValues is the vocabulary a title template can use.
func titleValues(ev *TrapEvent) map[string]string {
	v := map[string]string{
		"device":          titleValue(firstNonEmpty(ev.DeviceName, ev.Device, ev.Host)),
		"interface":       titleValue(ev.Interface),
		"admin":           ev.IfAdminStatus,
		"oper":            ev.IfOperStatus,
		"notification":    titleValue(ev.TrapName),
		"warning":         titleValue(ev.Fields["warning"]),
		"native_severity": titleValue(ev.NativeSeverityText),
	}
	if b := ev.BGP; b != nil {
		v["peer"], v["vrf"], v["afi"], v["local"] = b.PeerAddress, titleValue(b.VRF), b.PeerAFI, b.LocalAddress
		v["state"], v["prev_state"] = bgpStateTitle[b.State], bgpStateTitle[b.PrevState]
		v["transition"] = bgpTransitionMeaning[b.TransitionClass].text
		v["last_error"] = firstNonEmpty(b.LastError, b.LastErrorText)
		if b.PeerAS != nil {
			v["peer_as"] = strconv.FormatInt(*b.PeerAS, 10)
		}
	}
	switch ev.EventState {
	case trapStateRaise:
		v["condition"] = "raised"
	case trapStateClear:
		v["condition"] = "cleared"
	}
	for k, m := range ev.Metrics {
		v[k] = strconv.FormatFloat(m.Value, 'f', -1, 64)
	}
	if ev.ThresholdReportedPercent != nil {
		v["threshold_reported_percent"] = strconv.FormatFloat(*ev.ThresholdReportedPercent, 'f', -1, 64)
	}
	return v
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// applyTrapTitle words the trap from its pack template, or keeps the summary.
func applyTrapTitle(ev *TrapEvent, sem *trapSemantics) {
	ev.Title, ev.TitleBasis = "", titleFallback
	if rule, ok := sem.titles[ev.TrapOID]; ok {
		vals := titleValues(ev)
		for _, t := range sem.templates[rule.Template] {
			if s, ok := renderTitleTemplate(t, vals); ok {
				ev.Title, ev.TitleBasis = s, titleTemplated
				ev.attrsProvenance.derived = append(ev.attrsProvenance.derived, "title")
				return
			}
		}
	}
	ev.Title = firstNonEmpty(ev.Summary, ev.TrapName, ev.TrapOID)
}

// applyTrapGuidance attaches the family's pack guidance (the transition class's
// own first, for BGP) and computes the enrichment block.
func applyTrapGuidance(ev *TrapEvent, sem *trapSemantics) {
	pv := ev.attrsProvenance
	keys := []string{}
	if ev.BGP != nil && ev.BGP.TransitionClass != "" {
		keys = append(keys, ev.Family+"."+ev.BGP.TransitionClass)
	}
	keys = append(keys, ev.Family)
	var expects []string
	for _, k := range keys {
		g, ok := sem.guidance[k]
		if !ok || ev.Family == "" {
			continue
		}
		ev.Guidance = &TrapGuidance{Impact: g.Impact, NextChecks: g.NextChecks, Basis: "pack_guidance"}
		pv.guidance = append(pv.guidance, "guidance.impact", "guidance.next_checks")
		expects = g.Expects
		break
	}
	if ev.BGP != nil {
		b := ev.BGP
		for _, f := range []struct{ name, v, basis string }{
			{"bgp.peer_address", b.PeerAddress, b.PeerBasis},
			{"bgp.state", b.State, bgpPrevFromTrap},
			{"bgp.prev_state", b.PrevState, b.PrevStateBasis},
		} {
			switch {
			case f.v == "":
			case f.basis == bgpPrevFromPeerHistory || f.basis == bgpPrevFromTransition:
				pv.derived = append(pv.derived, f.name)
			default:
				pv.observed = append(pv.observed, f.name)
			}
		}
		if b.TransitionClass != "" {
			pv.derived = append(pv.derived, "bgp.transition_class")
		}
		for _, f := range []struct {
			name string
			ok   bool
		}{
			{"bgp.peer_as", b.PeerAS != nil}, {"bgp.vrf", b.VRF != ""}, {"bgp.local_address", b.LocalAddress != ""},
		} {
			if f.ok {
				pv.observed = append(pv.observed, f.name)
			}
		}
	}
	switch ev.InterfaceBasis {
	case InterfaceVarbindName, InterfaceIfIndexOnly:
		pv.observed = append(pv.observed, "interface")
	case InterfaceIfIndexMap:
		pv.derived = append(pv.derived, "interface")
	}
	for _, f := range []struct {
		name string
		ok   bool
	}{
		{"correlation_key", ev.CorrelationKey != ""},
		{"lifecycle_state", ev.LifecycleState != ""},
		{"event_severity", ev.EventSeverity != ""},
		{"op_state", ev.OpState != ""},
		{"impact", ev.Impact != ""},
	} {
		if f.ok {
			pv.derived = append(pv.derived, f.name)
		}
	}
	present := map[string]bool{}
	for _, l := range [][]string{pv.observed, pv.derived, pv.guidance} {
		for _, f := range l {
			present[f] = true
		}
	}
	if ev.Device == "" {
		pv.unknown = append(pv.unknown, "device")
	} else if ev.DeviceName == "" {
		pv.unknown = append(pv.unknown, "device_name")
	}
	for _, f := range expects {
		if !present[f] {
			pv.unknown = append(pv.unknown, f)
		}
	}
	for _, f := range ev.MetricsInvalid {
		pv.unknown = append(pv.unknown, "metrics."+f)
	}
	ev.Enrichment = &TrapEnrichment{
		FieldsObserved: uniqSorted(pv.observed), FieldsDerived: uniqSorted(pv.derived),
		FieldsGuidance: uniqSorted(pv.guidance), Unknown: uniqSorted(pv.unknown),
	}
}

func uniqSorted(xs []string) []string {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	out := trapSortedKeys(m)
	if out == nil {
		out = []string{}
	}
	return out
}

// normalizedSeverity is the syslog lane's five-word scale (aggregator
// `normalized_severity`), so both lanes filter the same way. "" for a word it
// does not know: never a guess.
func normalizedSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "emerg", "emergency", "alert", "crit", "critical":
		return "critical"
	case "err", "error":
		return "error"
	case "warning", "warn":
		return "warning"
	case "notice":
		return "notice"
	case "info", "informational", "debug":
		return "info"
	}
	return ""
}
