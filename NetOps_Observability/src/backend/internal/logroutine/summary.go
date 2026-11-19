// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Param is the request parameter (query string and JSON body) that shows the
// class. Absent or false: routine records are left out.
const Param = "include_routine_mgmt"

// ResponseKey is the top-level member a search answer carries.
const ResponseKey = "routine_mgmt"

// Summary is what a search answer says about the class: whether it was shown
// and how many records of it match the query (hidden when Included is false).
//
// Tracker 410: routine originals in the netops-syslogroutine family are kept
// raw for only a few days; their per-minute roll-ups keep the count. Count is
// the records the search matched, with routine-family originals counted only
// from RollupCut onward; Summarised is the roll-up count of routine sessions
// before RollupCut, so the two never overlap. SummarisedNote says why the
// older part was not counted: NoteTextQuery (roll-ups carry no message text a
// search could match) or NoteUnavailable (the roll-ups could not be read).
type Summary struct {
	Included       bool   `json:"included"`
	Count          int64  `json:"count"`
	Summarised     int64  `json:"summarised,omitempty"`
	SummarisedNote string `json:"summarised_note,omitempty"`
}

// RollupCut is how far back a routine-family original is counted from the
// originals themselves; older sessions are counted from their roll-ups. It is
// well inside the originals' >= 72 h window, so nothing in [now-RollupCut, now)
// has expired, and the cut is a fixed boundary so the two counts never overlap.
const RollupCut = 24 * time.Hour

// Summary notes for an older part that was not counted.
const (
	NoteTextQuery   = "text_query"
	NoteUnavailable = "unavailable"
)

// RoutineOriginalsPrefix is the routine originals' index-name prefix (the
// family internal/oslog.SyslogRoutineIndexBase names).
const RoutineOriginalsPrefix = "netops-syslogroutine-"

// AggSince counts the routine records matching a search like Agg, except that
// a routine-family ORIGINAL older than cut is left to the roll-ups (it may
// already have expired, and when it has not it would be counted twice).
// Main-family records are counted at any age.
func AggSince(src Sources, cut time.Time) map[string]any {
	return map[string]any{"filter": map[string]any{"bool": map[string]any{
		"filter": []any{Clause(src)},
		"must_not": []any{map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"prefix": map[string]any{"_index": RoutineOriginalsPrefix}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"lt": cut.UTC().Format(time.RFC3339)}}},
		}}}},
	}}}
}

// RollupSumBody sums occurrence_count over the roll-ups whose minute is in
// [from, to), under the caller's scope filters (tenant filter, device
// narrowing) and exclusions.
func RollupSumBody(from, to time.Time, filters, mustNot []any) map[string]any {
	f := append([]any{map[string]any{"range": map[string]any{"timestamp": map[string]any{
		"gte": from.UTC().Format(time.RFC3339), "lt": to.UTC().Format(time.RFC3339),
	}}}}, filters...)
	q := map[string]any{"filter": f}
	if len(mustNot) > 0 {
		q["must_not"] = mustNot
	}
	return map[string]any{
		"size": 0, "query": map[string]any{"bool": q},
		"aggs": map[string]any{"n": map[string]any{"sum": map[string]any{"field": "occurrence_count"}}},
	}
}

// ParseRollupSum reads RollupSumBody's answer.
func ParseRollupSum(raw []byte) (int64, error) {
	var out struct {
		Aggregations struct {
			N struct {
				Value float64 `json:"value"`
			} `json:"n"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, err
	}
	return int64(out.Aggregations.N.Value), nil
}

// SummarisedWindow is the part of a search window [from, to) that only the
// roll-ups can count: [from, min(to, now-RollupCut)). ok=false when the
// window lies wholly inside the originals' counted part.
func SummarisedWindow(from, to, now time.Time) (time.Time, time.Time, bool) {
	cut := now.Add(-RollupCut)
	end := to
	if cut.Before(end) {
		end = cut
	}
	if !from.Before(end) {
		return time.Time{}, time.Time{}, false
	}
	return from, end, true
}

// ErrBadParam is returned for a value of Param that is not a boolean.
var ErrBadParam = errors.New(Param + " must be true or false")

// ParseParam reads Param from a query string value. Empty is false.
func ParseParam(v string) (bool, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, ErrBadParam
	}
	return b, nil
}

// Inject adds `"routine_mgmt":{"included":…,"count":…}` to a search answer,
// reading the count from the AggName aggregation. Every other byte of the
// answer is kept as it was (the answer can be large, so it is not re-encoded).
// An answer that is not a JSON object is returned unchanged.
func Inject(raw []byte, included bool) ([]byte, error) {
	return InjectSummary(raw, Summary{Included: included})
}

// InjectSummary is Inject with the older part filled in (tracker 410): base
// carries Included, Summarised and SummarisedNote; Count is read from the
// aggregation as Inject does.
func InjectSummary(raw []byte, base Summary) ([]byte, error) {
	included := base.Included
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return raw, nil
	}
	var parsed struct {
		Aggregations map[string]json.RawMessage `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	sum := Summary{Included: included, Summarised: base.Summarised, SummarisedNote: base.SummarisedNote}
	if agg, ok := parsed.Aggregations[AggName]; ok {
		var a struct {
			DocCount int64 `json:"doc_count"`
		}
		if err := json.Unmarshal(agg, &a); err != nil {
			return nil, err
		}
		sum.Count = a.DocCount
	}
	member, err := json.Marshal(sum)
	if err != nil {
		return nil, err
	}
	rest := bytes.TrimLeft(trimmed[1:], " \t\r\n")
	out := make([]byte, 0, len(raw)+len(member)+len(ResponseKey)+8)
	out = append(out, `{"`+ResponseKey+`":`...)
	out = append(out, member...)
	if len(rest) > 0 && rest[0] != '}' {
		out = append(out, ',')
	}
	return append(out, rest...), nil
}
