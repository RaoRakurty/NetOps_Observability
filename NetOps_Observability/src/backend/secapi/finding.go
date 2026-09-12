// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// finding.go — the OpenSearch document → API Finding projection.
//
// The wire the router writes is the secbus EvidenceEvent (classification in
// `attrs.*`, identity/severity/seam at the top level). The API contract is the
// owned secfindings.Finding JSON plus four identity fields the store adds. This
// file is the ONE place that bridge is made, and it is deliberately TOLERANT in
// one direction only: it prefers a direct secfindings.Finding field when the
// document carries one (the index template declares those names for a future
// direct writer) and falls back to the attrs form the bus carries today. It
// never INVENTS a value — a field that is on neither shape stays empty, which
// is the §5g honesty rule applied to a projection: a missing narrative must read
// as missing, not as an empty finding that looks assessed-and-clean.
//
// KNOWN GAPS (not defects — properties of the bus contract, reported with the
// feature): `observed`, `intended` and `remediation` are NOT on the bus (secbus
// keeps raw evidence and the fix text off the wire by design, §5c / LLM06), so
// they decode empty and are omitted from the JSON. `uid` (the producer's own
// finding id) is likewise absent — it survives only INSIDE native_id, which IS
// returned.
//
// `status_detail` LEFT that list on 2026-09-03. It is the verdict REASON, and
// §5g's "never a false clear" is only half a rule without it: an Unknown whose
// reason does not survive the bus reaches the operator as a bare grey chip, and
// "the running-config was unavailable", "this control has no realization on this
// platform" and "we could not resolve the platform at all" are three different
// facts with three different fixes. secbus.attrsOf now carries it in
// attrs.status_detail, which is the fallback read below — the direct
// `status_detail` field still wins when a direct-Finding writer sets it.

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/secfindings"
)

// Finding is one row of the findings API. It embeds the owned model so the
// response cannot drift from secfindings.Finding, and adds the four store-level
// identity fields the contract names. TenantID stays json:"-" through the
// embedding — it is NEVER serialized to a client (§3a hygiene).
type Finding struct {
	secfindings.Finding
	// DocID is the OpenSearch document id: sha2(native_id|scan_id). It is the
	// id every other route in this API addresses a finding by.
	DocID string `json:"id"`
	// Scan is the assessment run (attrs.scan_id on the wire).
	Scan string `json:"scan_id"`
	// Native is the producer's deterministic verdict identity — the key the
	// current-state collapse groups on.
	Native string `json:"native_id"`
}

// srcMap is a decoded _source document.
type srcMap map[string]any

// str reads a string at a dotted path, tolerating the value having been indexed
// as a number or bool (ignore_malformed is on for this index, so a provider
// that sends the wrong scalar type must not crash the reader).
func (s srcMap) str(path string) string {
	v, ok := s.lookup(path)
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// JSON numbers decode as float64; render integral values without the
		// ".000000" a naive %v would produce.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// strs reads a string slice at a dotted path (a single scalar counts as one).
func (s srcMap) strs(path string) []string {
	v, ok := s.lookup(path)
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if str, ok := e.(string); ok && str != "" {
				out = append(out, str)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	default:
		return nil
	}
}

// boolAt reads a boolean at a dotted path.
func (s srcMap) boolAt(path string) bool {
	v, ok := s.lookup(path)
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	default:
		return false
	}
}

// lookup walks a dotted path through nested objects.
func (s srcMap) lookup(path string) (any, bool) {
	var cur any = map[string]any(s)
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// first returns the first non-empty value among the paths — the "direct field
// wins, attrs is the fallback" rule, in one call.
func (s srcMap) first(paths ...string) string {
	for _, p := range paths {
		if v := s.str(p); v != "" {
			return v
		}
	}
	return ""
}

// decodeTime reads the canonical event time. The router normalizes `ts` to
// integer epoch MILLISECONDS (the &log_lane contract), but the field is mapped
// as a date so an RFC3339 string is equally legal; both are accepted. A
// document with no readable time yields the zero time, which serializes as the
// zero instant rather than "now" — a verdict whose time we do not know must
// never be dated to the moment it was read.
func decodeTime(s srcMap) time.Time {
	v, ok := s.lookup(FieldTime)
	if !ok {
		v, ok = s.lookup("timestamp")
		if !ok {
			return time.Time{}
		}
	}
	switch t := v.(type) {
	case float64:
		return time.UnixMilli(int64(t)).UTC()
	case string:
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed.UTC()
		}
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return time.UnixMilli(n).UTC()
		}
	}
	return time.Time{}
}

// hostFromTokens recovers the subject hostname from the engine co-location
// tokens (secbus stamps "host:<hostname>" alongside the bare entity id). It is
// a projection of data already on the document, never an inference.
func hostFromTokens(s srcMap) string {
	for _, tok := range s.strs(FieldEntityTokens) {
		if rest, ok := strings.CutPrefix(tok, "host:"); ok && rest != "" {
			return rest
		}
	}
	return ""
}

// DecodeFinding projects one OpenSearch _source (plus its document id) onto the
// API Finding. docID comes from the hit's _id rather than the source so the
// value the caller pages and re-fetches by is exactly the store's identity.
func DecodeFinding(raw json.RawMessage, docID string) (Finding, error) {
	var s srcMap
	if err := json.Unmarshal(raw, &s); err != nil {
		return Finding{}, err
	}
	f := Finding{
		DocID:  docID,
		Scan:   s.first(FieldScanID, "scan_uid", "scan_id"),
		Native: s.str(FieldNativeID),
	}
	if f.DocID == "" {
		f.DocID = s.str(FieldDocID)
	}
	f.Time = decodeTime(s)
	f.Source = s.first("source", "attrs.provider_source")
	f.ScanID = f.Scan
	f.EvidenceClass = s.first("evidence_class", FieldEvidenceClass)
	f.Status = s.first("status", FieldStatus)
	if id := s.first("status_id", FieldStatusID); id != "" {
		if n, err := strconv.Atoi(id); err == nil && secfindings.StatusID(n).Valid() {
			f.StatusID = secfindings.StatusID(n)
		}
	}
	if f.StatusID == secfindings.StatusUnknown && f.Status != "" {
		// The pair must never disagree; derive the id from the canonical name
		// when only the name was written.
		if parsed, err := secfindings.ParseStatus(f.Status); err == nil {
			f.StatusID = parsed
		}
	}
	if std := s.strs("standards"); len(std) > 0 {
		f.Standards = std
	} else {
		f.Standards = s.strs(FieldFramework)
	}
	f.ControlID = s.first("control", FieldControlID)
	f.ControlTitle = s.first("control_title", FieldControlTitle)
	f.Category = s.first("category_name", "category", "attrs.category")
	f.Severity = s.str(FieldSeverity)
	f.RawRuleID = s.first("raw_rule_id", FieldRawRuleID)

	f.Resource = secfindings.Resource{
		DeviceID:   s.first("resource.uid", FieldEntityID),
		DeviceName: s.str("resource.name"),
		Hostname:   s.str("resource.hostname"),
		Address:    s.str("resource.ip"),
		Kind:       s.first("resource.type", "resource.kind", "attrs.resource_kind"),
		Platform:   s.str("resource.platform"),
		ProfileID:  s.str("resource.profile_id"),
	}
	if f.Resource.Hostname == "" {
		f.Resource.Hostname = hostFromTokens(s)
	}

	// Narrative: observed/intended/remediation are present only if a
	// direct-Finding writer put them there — absent from the bus shape by
	// design. status_detail (the verdict REASON) IS on the bus, in
	// attrs.status_detail; see the file header.
	f.Observed = s.str("observed")
	f.Intended = s.str("intended")
	f.Detail = s.first("status_detail", "detail", FieldStatusDetail)
	f.Remediation = s.str("remediation")

	if ref := decodeEvidenceRef(s); ref != nil {
		f.EvidenceRef = ref
	}
	if seam := decodeSeam(s); seam != nil {
		f.SeamContext = seam
	}
	return f, nil
}

// decodeEvidenceRef reads the by-reference evidence pointer from either the
// direct singular field or the bus's evidence_refs array (first element — the
// producer emits at most one).
func decodeEvidenceRef(s srcMap) *secfindings.EvidenceRef {
	read := func(prefix string) *secfindings.EvidenceRef {
		loc := s.str(prefix + ".locator")
		kind := s.str(prefix + ".kind")
		ver := s.str(prefix + ".ruleset_version")
		digest := s.str(prefix + ".digest")
		if loc == "" && kind == "" && ver == "" && digest == "" {
			return nil
		}
		return &secfindings.EvidenceRef{Locator: loc, Kind: kind, RulesetVersion: ver, Digest: digest}
	}
	if ref := read("evidence_ref"); ref != nil {
		return ref
	}
	v, ok := s.lookup("evidence_refs")
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return nil
	}
	m, ok := arr[0].(map[string]any)
	if !ok {
		return nil
	}
	inner := srcMap(m)
	ref := &secfindings.EvidenceRef{
		Locator:        inner.str("locator"),
		Kind:           inner.str("kind"),
		RulesetVersion: inner.str("ruleset_version"),
		Digest:         inner.str("digest"),
	}
	if ref.Locator == "" && ref.Kind == "" && ref.RulesetVersion == "" && ref.Digest == "" {
		return nil
	}
	return ref
}

// decodeSeam reads the seam attribution from either the nested object (direct
// Finding shape) or the flattened top-level fields (bus shape).
func decodeSeam(s srcMap) *secfindings.SeamContext {
	id := s.first("seam.seam_id", FieldSeamID)
	typ := s.first("seam.seam_type", FieldSeamType)
	facing := s.boolAt("seam.internet_facing") || s.boolAt("internet_facing")
	if id == "" && typ == "" && !facing {
		return nil
	}
	return &secfindings.SeamContext{SeamID: id, SeamType: typ, InternetFacing: facing}
}
