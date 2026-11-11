// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package logsecrets removes credential-bearing fields from stored log
// documents on their way out of the platform.
//
// WHY IT EXISTS. Until 2026-11-09 the SNMP trap receiver published the v1/v2c
// community string as `snmp_community`, and the router indexed it, so documents
// in netops-snmptrap-* hold a shared device credential in `_source`. The
// receiver and both Vector tiers no longer emit or forward the field, but stored
// documents only leave when retention ages them out. Every path that serves
// `_source` therefore strips here: the interactive log search, every export mode
// (sync and queued), the pipeline debugger's store and bus stages, and the
// quarantine restore.
//
// The strip is unconditional. It names no signal, index or vendor and makes no
// exception for a value such as "public", so a read that spans index families
// cannot miss it. It only removes fields: it never adds a filter or changes an
// index pattern, so it cannot widen what a caller's tenant scope selects.
//
// A CREDENTIAL IN A LINE'S TEXT. A device can log one (`snmp-server community
// public RO`), and since tracker 387 PR 10 the same text is stored again in
// `message_original` and `structured_data`, beside `message`. The Logs page hides it
// when it draws a record, but the API and the json/ndjson exports serve `_source`, so
// the text fields are masked here too, with the one dialect the platform has
// (ai.RedactSecrets). The store keeps the original (owner D5). Identifiers such as
// usernames are NOT masked: they stay for security attribution, behind the same
// RBAC, tenant scope and audit as the line itself (owner D7).
//
// A CREDENTIAL BY VALUE. ConfD names a v1/v2c SNMP session by its community, in a
// slot that holds a real account on every other session, so no pattern can find
// it (found live 2026-11-11, see internal/credscrub). Every function that serves
// a document therefore also takes a ValueMasker: the configured communities,
// masked wherever they occur as a whole token in ANY string of the document, not
// only the text fields (audit_user, title, summary, the keys, nested values).
// A nil masker masks no value; the field strip and the text dialect still run.
package logsecrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"netops/backend/ai"
)

// TrapCommunityField is the document key that held the v1/v2c community.
const TrapCommunityField = "snmp_community"

// redactedText replaces the key and value in ScrubText's output.
const redactedText = `"` + TrapCommunityField + `":"[REDACTED]"`

// quotedCommunityValue matches the key and its string value in serialized JSON,
// including a value cut short by an excerpt limit (no closing quote).
var quotedCommunityValue = regexp.MustCompile(`"` + TrapCommunityField + `"\s*:\s*"(?:[^"\\]|\\.?)*"?`)

// ValueMasker masks known credential values by value (internal/credscrub). It
// never reveals which values it holds: MayHold only gates the parse, and
// MaskValue returns the masked copy.
type ValueMasker interface {
	// MayHold reports whether serialized JSON could hold a value (fast path).
	MayHold(raw []byte) bool
	// MaskValue masks every string inside a decoded JSON value.
	MaskValue(v any) (any, bool)
}

// mayHoldValue is the by-value half of the fast path.
func mayHoldValue(raw []byte, vm ValueMasker) bool {
	return vm != nil && vm.MayHold(raw)
}

// maskRaw masks every string inside one serialized JSON value, numbers kept to
// the digit. It says whether anything changed.
func maskRaw(raw json.RawMessage, vm ValueMasker) (json.RawMessage, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false, fmt.Errorf("logsecrets: value is not JSON: %w", err)
	}
	masked, changed := vm.MaskValue(v)
	if !changed {
		return raw, false, nil
	}
	out, err := encode(masked)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// maskValues runs maskRaw over every value of a decoded object.
func maskValues(doc map[string]json.RawMessage, vm ValueMasker) (bool, error) {
	changed := false
	for key, value := range doc {
		masked, ch, err := maskRaw(value, vm)
		if err != nil {
			return false, err
		}
		if ch {
			doc[key] = masked
			changed = true
		}
	}
	return changed, nil
}

// textFields are the document keys that hold a line's text.
var textFields = [...]string{"message", "message_original", "structured_data", "summary"}

// mayHoldSecretText is the fast path for text: it is a superset of what
// ai.RedactSecrets can match, so an ordinary document is not parsed and goes through
// byte for byte. A false positive costs one parse; RE2 keeps the scan linear.
var mayHoldSecretText = regexp.MustCompile(
	`(?i)passw|pwd|secret|community|token|api[_-]?key|bearer|basic |digest |eyJ|sk-|xox|gh[pousr]_|private key|://|via snmp`)

// SourceExcludes is the `_source.excludes` list every document search sends, so
// the value does not reach this process at all when the store honours it. The
// response-side strip below stays authoritative.
func SourceExcludes() []string {
	return []string{TrapCommunityField}
}

// mayHoldField is the fast path: a body that spells neither the key nor any
// JSON unicode escape (which could spell the key another way) cannot hold the
// field and is passed through byte for byte, unparsed.
func mayHoldField(raw []byte) bool {
	return bytes.Contains(raw, []byte(TrapCommunityField)) || bytes.Contains(raw, []byte(`\u`)) ||
		mayHoldSecretText.Match(raw)
}

// scrubTextFields masks credentials in the text fields of a decoded document and
// says whether it changed anything. A field that is not a JSON string is left alone.
func scrubTextFields(doc map[string]json.RawMessage) (bool, error) {
	changed := false
	for _, key := range textFields {
		value, present := doc[key]
		if !present {
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			continue
		}
		clean := ai.RedactSecrets(text)
		if clean == text {
			continue
		}
		encoded, err := encode(clean)
		if err != nil {
			return false, err
		}
		doc[key] = encoded
		changed = true
	}
	return changed, nil
}

// StripSource returns one `_source` document without the field, its text fields
// masked and every value vm holds masked in every string. A document that holds
// none of these comes back unchanged, byte for byte. A document that may hold
// one but cannot be parsed as a JSON object is an error: the caller must refuse
// it rather than serve it.
func StripSource(raw json.RawMessage, vm ValueMasker) (json.RawMessage, error) {
	byValue := mayHoldValue(raw, vm)
	if !byValue && !mayHoldField(raw) {
		return raw, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("logsecrets: _source is not a JSON object: %w", err)
	}
	changed, err := scrubTextFields(doc)
	if err != nil {
		return nil, err
	}
	if _, present := doc[TrapCommunityField]; present {
		delete(doc, TrapCommunityField)
		changed = true
	}
	if byValue {
		masked, err := maskValues(doc, vm)
		if err != nil {
			return nil, err
		}
		changed = changed || masked
	}
	if !changed {
		return raw, nil
	}
	return encode(doc)
}

// StripFields removes the field from a document already decoded into a map.
//
// Only the field, not the text: the quarantine restore calls this on a document going
// back INTO the pipeline, and the store must keep the original (owner D5). Text is
// masked where a document leaves the platform, in StripSource.
func StripFields(doc map[string]any) {
	delete(doc, TrapCommunityField)
}

// StripSearchResponse runs StripSource over every hit's `_source` in an
// OpenSearch _search response, and masks vm's values in `aggregations` too (a
// terms bucket key is a field value). All other bytes of each value are
// preserved, so numbers keep their full precision. A response that may hold
// something to strip but cannot be parsed is an error: the caller must refuse it
// rather than serve it.
//
// Only `_source` and `aggregations` are walked because the callers compose the
// search body themselves and never request `fields`, `docvalue_fields` or
// `highlight`.
func StripSearchResponse(raw []byte, vm ValueMasker) ([]byte, error) {
	byValue := mayHoldValue(raw, vm)
	if !byValue && !mayHoldField(raw) {
		return raw, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("logsecrets: search response is not a JSON object: %w", err)
	}
	aggsChanged := false
	if aggs, ok := top["aggregations"]; ok && byValue {
		masked, ch, err := maskRaw(aggs, vm)
		if err != nil {
			return nil, fmt.Errorf("logsecrets: aggregations: %w", err)
		}
		if ch {
			top["aggregations"] = masked
			aggsChanged = true
		}
	}
	unchangedHits := func() ([]byte, error) {
		if aggsChanged {
			return encode(top)
		}
		return raw, nil
	}
	outerRaw, ok := top["hits"]
	if !ok {
		return unchangedHits()
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(outerRaw, &outer); err != nil {
		return nil, fmt.Errorf("logsecrets: hits is not a JSON object: %w", err)
	}
	listRaw, ok := outer["hits"]
	if !ok {
		return unchangedHits()
	}
	var hits []map[string]json.RawMessage
	if err := json.Unmarshal(listRaw, &hits); err != nil {
		return nil, fmt.Errorf("logsecrets: hits.hits is not a list of objects: %w", err)
	}
	for i, hit := range hits {
		source, ok := hit["_source"]
		if !ok {
			continue
		}
		clean, err := StripSource(source, vm)
		if err != nil {
			return nil, fmt.Errorf("logsecrets: hit %d: %w", i, err)
		}
		hit["_source"] = clean
	}
	list, err := encode(hits)
	if err != nil {
		return nil, err
	}
	outer["hits"] = list
	inner, err := encode(outer)
	if err != nil {
		return nil, err
	}
	top["hits"] = inner
	return encode(top)
}

// ScrubText replaces the field's value in serialized JSON that is handled as
// text, such as a bus record excerpt that may be cut short and so cannot be
// parsed. Every other byte is kept: the pipeline debugger's own redaction runs over
// the excerpt and marks what it hid, so masking here would hide that from its reader.
func ScrubText(s string) string {
	return quotedCommunityValue.ReplaceAllString(s, redactedText)
}

// encode marshals without HTML escaping, so a stripped document differs from
// the stored one only by the removed key and JSON key order.
func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("logsecrets: re-encode failed: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
