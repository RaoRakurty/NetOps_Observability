// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Param is the request parameter (query string and JSON body) that shows the
// class. Absent or false: routine records are left out.
const Param = "include_routine_mgmt"

// ResponseKey is the top-level member a search answer carries.
const ResponseKey = "routine_mgmt"

// Summary is what a search answer says about the class: whether it was shown
// and how many records of it match the query (hidden when Included is false).
type Summary struct {
	Included bool  `json:"included"`
	Count    int64 `json:"count"`
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
	sum := Summary{Included: included}
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
