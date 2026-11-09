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
package logsecrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

// TrapCommunityField is the document key that held the v1/v2c community.
const TrapCommunityField = "snmp_community"

// redactedText replaces the key and value in ScrubText's output.
const redactedText = `"` + TrapCommunityField + `":"[REDACTED]"`

// quotedCommunityValue matches the key and its string value in serialized JSON,
// including a value cut short by an excerpt limit (no closing quote).
var quotedCommunityValue = regexp.MustCompile(`"` + TrapCommunityField + `"\s*:\s*"(?:[^"\\]|\\.?)*"?`)

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
	return bytes.Contains(raw, []byte(TrapCommunityField)) || bytes.Contains(raw, []byte(`\u`))
}

// StripSource returns one `_source` document without the field. A document that
// does not hold it comes back unchanged. A document that may hold the field but
// cannot be parsed as a JSON object is an error: the caller must refuse it
// rather than serve it.
func StripSource(raw json.RawMessage) (json.RawMessage, error) {
	if !mayHoldField(raw) {
		return raw, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("logsecrets: _source is not a JSON object: %w", err)
	}
	if _, present := doc[TrapCommunityField]; !present {
		return raw, nil
	}
	delete(doc, TrapCommunityField)
	return encode(doc)
}

// StripFields removes the field from a document already decoded into a map.
func StripFields(doc map[string]any) {
	delete(doc, TrapCommunityField)
}

// StripSearchResponse removes the field from every hit's `_source` in an
// OpenSearch _search response. All other bytes of each value are preserved, so
// numbers keep their full precision. A response that may hold the field but
// cannot be parsed is an error: the caller must refuse it rather than serve it.
//
// Only `_source` is walked because the callers compose the search body
// themselves and never request `fields`, `docvalue_fields` or `highlight`.
func StripSearchResponse(raw []byte) ([]byte, error) {
	if !mayHoldField(raw) {
		return raw, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("logsecrets: search response is not a JSON object: %w", err)
	}
	outerRaw, ok := top["hits"]
	if !ok {
		return raw, nil
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(outerRaw, &outer); err != nil {
		return nil, fmt.Errorf("logsecrets: hits is not a JSON object: %w", err)
	}
	listRaw, ok := outer["hits"]
	if !ok {
		return raw, nil
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
		clean, err := StripSource(source)
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
// parsed. Every other byte is kept.
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
