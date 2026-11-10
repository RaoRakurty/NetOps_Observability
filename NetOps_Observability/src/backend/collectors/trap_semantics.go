// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// trap_semantics.go — what a decoded trap MEANS, read from data.
//
// The OID index (oidindex.go) knows names, types and enums: the facts a MIB
// states. It cannot know that one object carries the vendor's own severity, that
// another says whether the condition raised or cleared, or that a percentage is
// sent as text. Those facts differ per vendor, so they live in trap packs
// (mibs/packs/*.json), a table keyed by the OID of the object or notification.
// Adding a vendor means adding a pack: no code here names one, and
// TestTrapSemantics_SecondEnterpriseThroughDataOnly proves it. Format and rules:
// mibs/README.md.
//
// Three ideas stay separate (telemetry plan §5.3): the vendor's native severity,
// our normalized severity, and whether the event raises or clears. A recovery
// can be natively `minor` and still be a clear.
//
// Never reinterpret: a varbind always keeps its numeric OID and raw value, and
// everything here is added beside them. No evidence means no claim: a trap whose
// state cannot be shown from a row reads `point`.

//go:embed mibs/packs/*.json
var trapPackFS embed.FS

// Event states. A point event has no lifecycle, or none the trap can evidence.
const (
	trapStateRaise = "raise"
	trapStateClear = "clear"
	trapStatePoint = "point"
)

// Roles an object can play in a pack.
const (
	trapRoleNativeSeverity = "native_severity"
	trapRoleSummary        = "summary"
)

// Severity a recovery normalizes to: a clear is never itself a fault.
const trapClearSeverity = "info"

// trapFidelities is the catalogue's evidence ladder (telemetry-catalog/README.md).
var trapFidelities = map[string]bool{"doc_claimed": true, "lab_validated": true, "live_validated": true}

// TrapPack is one vendor's semantics table, as stored on disk.
type TrapPack struct {
	Schema        int                             `json:"schema"`
	Pack          string                          `json:"pack"`
	Source        string                          `json:"source"`
	Objects       map[string]TrapObjectRule       `json:"objects"`
	Notifications map[string]TrapNotificationRule `json:"notifications"`
	// Tables states a vendor's deviation from its own MIB's INDEX encoding,
	// keyed by the row (entry) OID. Evidence-backed: each names its fidelity.
	Tables map[string]TrapTableRule `json:"tables,omitempty"`
	// TitleTemplates are the wordings (trap_title.go), by key; Titles picks one
	// per notification OID. A notification needs no `notifications` row to get
	// a title, so wording never changes what the engine admits.
	TitleTemplates map[string][]string      `json:"title_templates,omitempty"`
	Titles         map[string]TrapTitleRule `json:"titles,omitempty"`
	// Derived metrics and per-family guidance (trap_enrich.go).
	Derived  []TrapDerivedMetric         `json:"derived,omitempty"`
	Guidance map[string]TrapGuidanceRule `json:"guidance,omitempty"`
	// Platform names the product line a pack's MIB is specific to (SD-WAN,
	// SR OS), so a trap it words carries it. Empty for a MIB several platforms
	// share (CISCO-BGP4-MIB runs on IOS, IOS-XE and NX-OS): never a guess.
	Platform string `json:"platform,omitempty"`
}

// TrapTableRule is one table's deviation. BareAddressIndex: the agent may send
// the row index as the bare address octets, without the type and length arcs.
type TrapTableRule struct {
	Name             string `json:"name"`
	BareAddressIndex bool   `json:"bare_address_index"`
	Fidelity         string `json:"fidelity"`
}

// TrapTitleRule names the template a notification is worded with.
type TrapTitleRule struct {
	Name     string `json:"name"`
	Template string `json:"template"`
}

// TrapObjectRule says what one object means. Name must match the OID index.
type TrapObjectRule struct {
	Name string `json:"name"`
	// Role is trapRoleNativeSeverity or trapRoleSummary, or empty.
	Role string `json:"role,omitempty"`
	// Normalized maps a native severity label to our severity. Native role only.
	Normalized map[string]string `json:"normalized,omitempty"`
	// Field names the event field this value fills; Type is float, int or string.
	Field string `json:"field,omitempty"`
	Type  string `json:"type,omitempty"`
	// Attr is the meaning this object carries, from the closed trapAttrs set:
	// read from the varbind's value, and from the row index when the object is
	// an index object of the row a varbind names (bgpPeerRemoteAddr is both).
	Attr string `json:"attr,omitempty"`
	// A typed number's legal range and unit: a value outside it is not shown
	// (metrics_invalid names it), never clamped.
	Min  *float64 `json:"min,omitempty"`
	Max  *float64 `json:"max,omitempty"`
	Unit string   `json:"unit,omitempty"`
	// Extract reads a number the vendor states inside this object's text.
	Extract []TrapExtractRule `json:"extract,omitempty"`
}

// TrapExtractRule: one capture group of Pattern (RE2) fills Field, from the
// closed trapExtractFields set.
type TrapExtractRule struct {
	Pattern string   `json:"pattern"`
	Field   string   `json:"field"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
}

// trapExtractFields: what text may state. The threshold is the one the DEVICE
// reports in its message, never a configured one (threshold_basis says so).
var trapExtractFields = map[string]bool{"threshold_reported_percent": true}

// TrapDerivedMetric is a metric computed from observed ones, with its formula as
// the operator should read it. Op is from the closed set: complement (Base - Of).
type TrapDerivedMetric struct {
	Field   string   `json:"field"`
	Op      string   `json:"op"`
	Of      string   `json:"of"`
	Base    float64  `json:"base"`
	Formula string   `json:"formula"`
	Unit    string   `json:"unit,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
}

// TrapGuidanceRule is per family (or family.transition_class): what the event
// usually means for service and what to check next, written vendor-neutral and
// never a diagnosis. Expects names the fields such an event should carry, so the
// ones that are missing are reported as unknown.
type TrapGuidanceRule struct {
	Impact     []string `json:"impact"`
	NextChecks []string `json:"next_checks"`
	Expects    []string `json:"expects,omitempty"`
}

// trapAttrs is the closed set of meanings a pack may give an object.
var trapAttrs = map[string]bool{
	"peer_address": true, "peer_afi": true, "peer_as": true,
	"local_address": true, "local_afi": true, "routing_instance": true,
	"bgp_state": true, "bgp_prev_state": true, "bgp_last_error": true,
	"bgp_error_code": true, "bgp_error_subcode": true, "bgp_last_error_text": true,
	"if_admin_status": true, "if_oper_status": true,
}

// TrapNotificationRule says how one notification reports its lifecycle.
type TrapNotificationRule struct {
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Family   string `json:"family,omitempty"`
	// Fidelity is the evidence behind the row: doc_claimed until captured.
	Fidelity string `json:"fidelity"`
	// EventState is the fixed state of a notification whose identity says it all.
	EventState string `json:"event_state,omitempty"`
	// StateObject is the state-bearing varbind; its enum label (or raw value)
	// is looked up in Raise and Clear. Any other value reads as point.
	StateObject string   `json:"state_object,omitempty"`
	Raise       []string `json:"raise,omitempty"`
	Clear       []string `json:"clear,omitempty"`
	// TextObject is a free-text varbind for a notification with no state object.
	TextObject string          `json:"text_object,omitempty"`
	Text       []TrapTextState `json:"text,omitempty"`
}

// TrapTextState is one wording that evidences a state. Fidelity is per wording
// because a captured recovery says nothing about the raise's wording.
type TrapTextState struct {
	Contains []string `json:"contains"`
	State    string   `json:"state"`
	Fidelity string   `json:"fidelity"`
}

// trapObjectEntry is an object rule with its OID set.
type trapObjectEntry struct {
	TrapObjectRule
	lookup map[string]string // lower-cased native label → normalized severity
}

// trapNotificationEntry is a notification rule with lower-cased lookups.
type trapNotificationEntry struct {
	TrapNotificationRule
	states map[string]string // lower-cased label or raw value → state
}

// trapSemantics is the compiled union of every pack, keyed by OID.
type trapSemantics struct {
	objects       map[string]trapObjectEntry
	notifications map[string]trapNotificationEntry
	tables        map[string]TrapTableRule
	templates     map[string][]string
	titles        map[string]TrapTitleRule
	derived       []TrapDerivedMetric
	guidance      map[string]TrapGuidanceRule
	extracts      map[string][]trapExtract // object OID → compiled extractions
	platforms     map[string]string        // notification OID → its pack's platform
}

type trapExtract struct {
	TrapExtractRule
	re *regexp.Regexp
}

func newTrapSemantics() *trapSemantics {
	return &trapSemantics{
		objects: map[string]trapObjectEntry{}, notifications: map[string]trapNotificationEntry{},
		tables: map[string]TrapTableRule{}, templates: map[string][]string{}, titles: map[string]TrapTitleRule{},
		guidance: map[string]TrapGuidanceRule{}, extracts: map[string][]trapExtract{}, platforms: map[string]string{},
	}
}

var trapSem = loadEmbeddedTrapPacks()

// loadEmbeddedTrapPacks compiles the embedded packs. A bad pack must not take the
// API down, so it is logged and the receiver keeps decoding from the index alone;
// TestTrapPacks_EmbeddedLoadClean fails the build long before that can ship.
func loadEmbeddedTrapPacks() *trapSemantics {
	sem, err := compileTrapPacks(trapPackFS, "mibs/packs")
	if err != nil {
		slog.Error("snmptrap: trap packs not loaded, traps decode without vendor semantics", "err", err)
		return newTrapSemantics()
	}
	return sem
}

// compileTrapPacks reads every *.json under dir, in name order.
func compileTrapPacks(fsys fs.FS, dir string) (*trapSemantics, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("trap packs: %w", err)
	}
	var packs [][]byte
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := fs.ReadFile(fsys, path.Join(dir, n))
		if err != nil {
			return nil, fmt.Errorf("trap packs: %s: %w", n, err)
		}
		packs = append(packs, b)
	}
	return compileTrapPackData(packs...)
}

// compileTrapPackData validates and merges packs. Strict: an unknown key, an OID
// claimed twice or a state outside the vocabulary refuses the whole set, because
// a half-read table would make a trap's meaning depend on load order.
func compileTrapPackData(packs ...[]byte) (*trapSemantics, error) {
	sem := newTrapSemantics()
	for _, raw := range packs {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var p TrapPack
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("trap pack: %w", err)
		}
		if p.Schema != 1 || p.Pack == "" {
			return nil, fmt.Errorf("trap pack %q: schema must be 1 and pack named", p.Pack)
		}
		for oid, o := range p.Objects {
			if _, dup := sem.objects[oid]; dup {
				return nil, fmt.Errorf("trap pack %s: object %s is claimed twice", p.Pack, oid)
			}
			e, err := compileTrapObject(o)
			if err != nil {
				return nil, fmt.Errorf("trap pack %s: object %s: %w", p.Pack, oid, err)
			}
			sem.objects[oid] = e
			for _, x := range o.Extract {
				if !trapExtractFields[x.Field] {
					return nil, fmt.Errorf("trap pack %s: object %s: extract field %q is not allowed", p.Pack, oid, x.Field)
				}
				re, err := regexp.Compile(x.Pattern)
				if err != nil || re.NumSubexp() != 1 {
					return nil, fmt.Errorf("trap pack %s: object %s: extract pattern %q needs one capture group", p.Pack, oid, x.Pattern)
				}
				sem.extracts[oid] = append(sem.extracts[oid], trapExtract{TrapExtractRule: x, re: re})
			}
		}
		for oid, n := range p.Notifications {
			if _, dup := sem.notifications[oid]; dup {
				return nil, fmt.Errorf("trap pack %s: notification %s is claimed twice", p.Pack, oid)
			}
			e, err := compileTrapNotification(n)
			if err != nil {
				return nil, fmt.Errorf("trap pack %s: notification %s: %w", p.Pack, oid, err)
			}
			sem.notifications[oid] = e
		}
		for oid, t := range p.Tables {
			if _, dup := sem.tables[oid]; dup {
				return nil, fmt.Errorf("trap pack %s: table %s is claimed twice", p.Pack, oid)
			}
			if t.Name == "" || !trapFidelities[t.Fidelity] || !t.BareAddressIndex {
				return nil, fmt.Errorf("trap pack %s: table %s needs a name, a fidelity and a deviation", p.Pack, oid)
			}
			sem.tables[oid] = t
		}
		for key, ts := range p.TitleTemplates {
			if _, dup := sem.templates[key]; dup {
				return nil, fmt.Errorf("trap pack %s: title template %q is claimed twice", p.Pack, key)
			}
			if len(ts) == 0 {
				return nil, fmt.Errorf("trap pack %s: title template %q has no wording", p.Pack, key)
			}
			for _, t := range ts {
				if err := compileTitleTemplate(t); err != nil {
					return nil, fmt.Errorf("trap pack %s: title template %q: %w", p.Pack, key, err)
				}
			}
			sem.templates[key] = ts
		}
		for _, d := range p.Derived {
			if d.Field == "" || d.Of == "" || d.Op != "complement" || d.Formula == "" {
				return nil, fmt.Errorf("trap pack %s: derived metric %+v is incomplete", p.Pack, d)
			}
			sem.derived = append(sem.derived, d)
		}
		for fam, g := range p.Guidance {
			if _, dup := sem.guidance[fam]; dup {
				return nil, fmt.Errorf("trap pack %s: guidance for %q is claimed twice", p.Pack, fam)
			}
			if len(g.Impact) == 0 || len(g.NextChecks) == 0 {
				return nil, fmt.Errorf("trap pack %s: guidance for %q needs impact and next_checks", p.Pack, fam)
			}
			sem.guidance[fam] = g
		}
		if p.Platform != "" {
			for oid := range p.Notifications {
				sem.platforms[oid] = p.Platform
			}
			for oid := range p.Titles {
				sem.platforms[oid] = p.Platform
			}
		}
		for oid, t := range p.Titles {
			if _, dup := sem.titles[oid]; dup {
				return nil, fmt.Errorf("trap pack %s: title for %s is claimed twice", p.Pack, oid)
			}
			if t.Name == "" || t.Template == "" {
				return nil, fmt.Errorf("trap pack %s: title for %s needs a name and a template", p.Pack, oid)
			}
			sem.titles[oid] = t
		}
	}
	// A title may use another pack's wording (the standard pack's, typically), so
	// the reference is checked once every pack is in.
	for oid, t := range sem.titles {
		if _, ok := sem.templates[t.Template]; !ok {
			return nil, fmt.Errorf("trap packs: title for %s names template %q, which no pack defines", oid, t.Template)
		}
	}
	return sem, nil
}

func compileTrapObject(o TrapObjectRule) (trapObjectEntry, error) {
	if o.Name == "" {
		return trapObjectEntry{}, fmt.Errorf("no name")
	}
	switch o.Role {
	case "", trapRoleSummary:
		if len(o.Normalized) > 0 {
			return trapObjectEntry{}, fmt.Errorf("normalized belongs to role %s", trapRoleNativeSeverity)
		}
	case trapRoleNativeSeverity:
	default:
		return trapObjectEntry{}, fmt.Errorf("unknown role %q", o.Role)
	}
	if o.Attr != "" && !trapAttrs[o.Attr] {
		return trapObjectEntry{}, fmt.Errorf("unknown attr %q", o.Attr)
	}
	if (o.Field == "") != (o.Type == "") {
		return trapObjectEntry{}, fmt.Errorf("field and type go together")
	}
	switch o.Type {
	case "", "float", "int", "string":
	default:
		return trapObjectEntry{}, fmt.Errorf("unknown type %q", o.Type)
	}
	e := trapObjectEntry{TrapObjectRule: o, lookup: map[string]string{}}
	for label, sev := range o.Normalized {
		e.lookup[strings.ToLower(label)] = sev
	}
	return e, nil
}

func compileTrapNotification(n TrapNotificationRule) (trapNotificationEntry, error) {
	if n.Name == "" {
		return trapNotificationEntry{}, fmt.Errorf("no name")
	}
	if !trapFidelities[n.Fidelity] {
		return trapNotificationEntry{}, fmt.Errorf("fidelity %q is not on the ladder", n.Fidelity)
	}
	ways := 0
	if n.EventState != "" {
		ways++
		if !validTrapState(n.EventState) {
			return trapNotificationEntry{}, fmt.Errorf("event_state %q", n.EventState)
		}
	}
	if n.StateObject != "" {
		ways++
	}
	if n.TextObject != "" {
		ways++
	}
	if ways != 1 {
		return trapNotificationEntry{}, fmt.Errorf("needs exactly one of event_state, state_object, text_object")
	}
	if (n.StateObject == "") != (len(n.Raise)+len(n.Clear) == 0) {
		return trapNotificationEntry{}, fmt.Errorf("state_object and raise/clear go together")
	}
	if (n.TextObject == "") != (len(n.Text) == 0) {
		return trapNotificationEntry{}, fmt.Errorf("text_object and text go together")
	}
	for _, t := range n.Text {
		if len(t.Contains) == 0 || !validTrapState(t.State) || !trapFidelities[t.Fidelity] {
			return trapNotificationEntry{}, fmt.Errorf("bad text row %+v", t)
		}
	}
	e := trapNotificationEntry{TrapNotificationRule: n, states: map[string]string{}}
	for _, v := range n.Raise {
		e.states[strings.ToLower(v)] = trapStateRaise
	}
	for _, v := range n.Clear {
		if e.states[strings.ToLower(v)] == trapStateRaise {
			return trapNotificationEntry{}, fmt.Errorf("%q is both raise and clear", v)
		}
		e.states[strings.ToLower(v)] = trapStateClear
	}
	return e, nil
}

func validTrapState(s string) bool {
	return s == trapStateRaise || s == trapStateClear || s == trapStatePoint
}

// decodeVarbind resolves one binding against the index. The raw value and the
// numeric OID are kept whatever else resolves.
func decodeVarbind(oid, raw string) TrapVarbind {
	return decodeVarbindTag(oid, raw, 0)
}

// berTypeNames are the SMI types a BER tag states (RFC 2578 §7.1), for a varbind
// whose OID no indexed MIB names. 0 = the tag is not known (a replay, a test).
var berTypeNames = map[byte]string{
	0x02: "INTEGER", 0x04: "OCTET STRING", 0x05: "NULL", 0x06: "OBJECT IDENTIFIER",
	0x40: "IpAddress", 0x41: "Counter32", 0x42: "Gauge32", 0x43: "TimeTicks",
	0x44: "Opaque", 0x46: "Counter64",
}

// smiTypeName spells a MIB SYNTAX the way an operator reads it: net-snmp's index
// pass records OCTET STRING as its first word.
func smiTypeName(t string) string {
	if t == "OCTET" {
		return "OCTET STRING"
	}
	return t
}

// decodeVarbindTag is decodeVarbind with the BER tag the value arrived with,
// which names the SMI type when no MIB does.
func decodeVarbindTag(oid, raw string, tag byte) TrapVarbind {
	name, disp := resolveVarbind(oid, raw)
	vb := TrapVarbind{OID: oid, Name: sanitizeLabel(name), Value: disp, Raw: raw, Type: berTypeNames[tag]}
	n, _, ok := lookupOID(oid)
	if !ok {
		return vb
	}
	if n.Type != "" {
		vb.Type = smiTypeName(n.Type)
	}
	if lbl, found := n.Enum[raw]; found {
		vb.Label = lbl
		vb.Decoded = lbl
		return vb
	}
	switch n.Type {
	case "DateAndTime":
		if t, ok := decodeDateAndTime(raw); ok {
			vb.Time = t
			vb.Decoded = t
		}
	case "Integer32", "Unsigned32", "Gauge32", "Counter32", "Counter64", "TimeTicks", "INTEGER":
		// A Counter64 past 2^53 loses precision here; Raw stays exact.
		if f, err := strconv.ParseFloat(raw, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			vb.Num = &f
		}
	}
	return vb
}

// decodeDateAndTime reads an RFC 2579 DateAndTime as the receiver renders it (a
// hex string, since the first year octet is never printable) into RFC 3339.
// Any impossible value reads as not decoded; the raw value is still there.
func decodeDateAndTime(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "0x") {
		return "", false
	}
	h := raw[2:]
	if len(h) != 16 && len(h) != 22 {
		return "", false
	}
	b := make([]int, len(h)/2)
	for i := range b {
		v, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return "", false
		}
		b[i] = int(v)
	}
	loc := time.UTC
	if len(b) == 11 {
		if (b[8] != '+' && b[8] != '-') || b[9] > 13 || b[10] > 59 {
			return "", false
		}
		off := b[9]*3600 + b[10]*60
		if b[8] == '-' {
			off = -off
		}
		loc = time.FixedZone("", off)
	}
	year, month, day, hour, minute, sec, deci := b[0]<<8|b[1], b[2], b[3], b[4], b[5], b[6], b[7]
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || sec > 60 || deci > 9 {
		return "", false
	}
	t := time.Date(year, time.Month(month), day, hour, minute, sec, deci*100_000_000, loc)
	if t.Day() != day && sec != 60 { // 31 Feb normalizes to March: not a real date
		return "", false
	}
	return t.UTC().Format(time.RFC3339Nano), true
}

// trapVarbindObject returns the OID a binding is an instance of: the object a
// pack row is keyed by.
func trapVarbindObject(oid string) string {
	if _, suffix, ok := lookupOID(oid); ok && suffix != "" {
		return strings.TrimSuffix(oid, "."+suffix)
	}
	return oid
}

// applyTrapSemantics fills the semantic envelope from the index and the packs.
// It reads only data, for any enterprise, decoded or raw.
func applyTrapSemantics(ev *TrapEvent, sem *trapSemantics) {
	ev.EventState = trapStatePoint
	bound := map[string]string{} // object OID → label or raw value, first binding wins
	var severityRule *trapObjectEntry
	for i := range ev.Varbinds {
		vb := &ev.Varbinds[i]
		obj := trapVarbindObject(vb.OID)
		raw := vb.Raw
		if raw == "" {
			raw = vb.Value // an event built without the decoder, e.g. a replay
		}
		if _, seen := bound[obj]; !seen {
			if vb.Label != "" {
				bound[obj] = vb.Label
			} else {
				bound[obj] = raw
			}
		}
		if vb.Time != "" && ev.DeviceEventTime == "" {
			ev.DeviceEventTime = vb.Time
		}
		rule, ok := sem.objects[obj]
		if !ok {
			continue
		}
		switch rule.Role {
		case trapRoleNativeSeverity:
			if ev.NativeSeverityCode == nil {
				if code, err := strconv.Atoi(raw); err == nil {
					ev.NativeSeverityCode = &code
				}
				ev.NativeSeverityText = vb.Label
				ev.NativeSeverity = vb.Value // the vendor's own words: critical(1)
				r := rule
				severityRule = &r
			}
		case trapRoleSummary:
			if ev.semanticSummary == "" {
				ev.semanticSummary = strings.Join(strings.Fields(raw), " ")
			}
		}
		applyTrapField(ev, rule, raw)
	}

	if ev.TrapName == "" || ev.TrapName == "enterpriseSpecific" {
		return
	}
	if n, _, ok := lookupOID(ev.TrapOID); ok {
		ev.MIBModule = n.MIB
		ev.MIBBundleVersion = oidIdx.Version
	}
	rule, ok := sem.notifications[ev.TrapOID]
	if !ok {
		return
	}
	ev.semanticCategory, ev.semanticFamily = rule.Category, rule.Family
	ev.EventState, ev.EventStateFidelity = rule.resolve(bound)
	// Normalized severity follows the native one ONLY for a listed notification
	// with an evidenced state: an unreviewed notification keeps its MIB hint, so
	// a vendor's `critical` on something nobody has read cannot open an incident.
	switch ev.EventState {
	case trapStateClear:
		ev.Severity = trapClearSeverity
	case trapStateRaise:
		if severityRule != nil {
			if sev, ok := severityRule.lookup[strings.ToLower(ev.NativeSeverityText)]; ok {
				ev.Severity = sev
			}
		}
	}
}

// resolve finds the state a row evidences, and the fidelity of that evidence.
func (n trapNotificationEntry) resolve(bound map[string]string) (state, fidelity string) {
	switch {
	case n.EventState != "":
		return n.EventState, n.Fidelity
	case n.StateObject != "":
		v, ok := bound[n.StateObject]
		if !ok {
			return trapStatePoint, ""
		}
		if s, ok := n.states[strings.ToLower(v)]; ok {
			return s, n.Fidelity
		}
		return trapStatePoint, ""
	}
	text := strings.ToLower(bound[n.TextObject])
	for _, row := range n.Text {
		for _, needle := range row.Contains {
			if strings.Contains(text, strings.ToLower(needle)) {
				return row.State, row.Fidelity
			}
		}
	}
	return trapStatePoint, ""
}

// applyTrapField fills a typed field. A value that does not parse fills nothing:
// a guessed number is worse than none, and the raw value is on the varbind.
func applyTrapField(ev *TrapEvent, rule trapObjectEntry, raw string) {
	switch rule.Type {
	case "float", "int":
		f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return
		}
		if rule.Type == "int" && f != math.Trunc(f) {
			return
		}
		if ev.Values == nil {
			ev.Values = map[string]float64{}
		}
		if _, seen := ev.Values[rule.Field]; !seen {
			ev.Values[rule.Field] = f
		}
	case "string":
		if ev.Fields == nil {
			ev.Fields = map[string]string{}
		}
		if _, seen := ev.Fields[rule.Field]; !seen {
			ev.Fields[rule.Field] = raw
		}
	}
}
