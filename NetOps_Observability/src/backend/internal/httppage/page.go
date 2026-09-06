// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package httppage is the bounded-read pagination CONTRACT (Phase-2 W4.1,
// extracted from package main's pagination.go): the request parse with
// fail-closed limits (F-71), unknown-query rejection, the truncation-honesty
// headers stamped on every paginated read, the opt-in envelope shape and the
// slice/complete helpers. Pure over net/http.
package httppage

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"netops/backend/internal/applog"
)

// writeBody mirrors main's writeJSON marshal-before-commit rule locally: the
// body is marshaled first so an encode failure can never emit an empty 200
// (the writeJSON invariant, duplicated at the boundary).
func writeBody(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		applog.Error("httppage", "page body marshal failed", map[string]any{"err": err.Error()})
		http.Error(w, `{"error":"encoding failure"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b) // best-effort: status committed; a failed write means the client is gone
}

const (
	HeaderTotalCount = "X-Total-Count"    // TRUE number of rows matching the caller's filter
	HeaderPageLimit  = "X-Page-Limit"     // limit actually applied
	HeaderPageOffset = "X-Page-Offset"    // offset actually applied
	HeaderPageDone   = "X-Page-Complete"  // "true" iff this response IS the whole matching set
	HeaderPageMax    = "X-Page-Max-Limit" // server-side ceiling, so a client can size its walk
)

// LogTruncated records a bounded read that returned less than the caller
// matched WITHOUT the caller having asked for a page. A client walking pages on
// purpose is not a defect and is not logged; a client that asked for "the list"
// and silently got part of it is exactly the F-61 shape, and §10 (no silent
// failures) says an operator must be able to see it.
func LogTruncated(endpoint string, p Request, returned, total int) {
	if p.Explicit || Complete(p, returned, total) {
		return
	}
	applog.Error("pagination", "unpaged read truncated at the server ceiling", map[string]any{
		"endpoint": endpoint, "returned": returned, "total": total,
		"limit": p.Limit, "offset": p.Offset,
	})
}

// Request is a parsed, validated, in-range bounded read.
type Request struct {
	Limit    int
	Offset   int
	Max      int
	Envelope bool
	// Explicit records that the caller actually supplied limit and/or offset,
	// i.e. asked for a page rather than "the list". Only used to decide whether
	// a short response is worth an operator-facing log line.
	Explicit bool
}

// MaxOffset bounds `offset` itself. Without a ceiling, offset is an
// unbounded integer a caller can use to make the server skip an arbitrary
// number of rows; with a ceiling, an over-large offset is an explicit 400
// rather than a silently empty page that reads like "no more data".
const MaxOffset = 1_000_000

// intQuery mirrors main's F-71 fail-closed bounded int parser (duplicated at
// the boundary): absent = default; malformed or out-of-range = a 400 naming
// the key and its bounds — silently returning fewer rows than asked reads as
// "that is all the data there is".
func intQuery(r *http.Request, key string, def, min, max int) (int, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	return n, nil
}

// Parse parses limit/offset/envelope. Both numeric parameters go through
// intQuery, which fails closed on malformed or out-of-range input (F-71), so
// every error here is a 400 that names the parameter and its legal range.
func Parse(r *http.Request, defLimit, maxLimit int) (Request, error) {
	p := Request{Max: maxLimit}
	var err error
	if p.Limit, err = intQuery(r, "limit", defLimit, 1, maxLimit); err != nil {
		return Request{}, err
	}
	if p.Offset, err = intQuery(r, "offset", 0, 0, MaxOffset); err != nil {
		return Request{}, err
	}
	if p.Envelope, err = BoolQuery(r, "envelope"); err != nil {
		return Request{}, err
	}
	q := r.URL.Query()
	p.Explicit = q.Get("limit") != "" || q.Get("offset") != ""
	return p, nil
}

// BoolQuery parses a strict boolean query parameter. Anything that is not an
// exact member of the accepted vocabulary is an error — "envelope=yes please"
// must never quietly mean false.
func BoolQuery(r *http.Request, key string) (bool, error) {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	switch v {
	case "":
		return false, nil
	case "1", "true", "TRUE", "True":
		return true, nil
	case "0", "false", "FALSE", "False":
		return false, nil
	}
	return false, fmt.Errorf("%s must be one of 1/0/true/false (got %q)", key, v)
}

// alwaysAllowedQuery are the parameters every authenticated endpoint accepts:
// the acting-tenant narrowing applied by the tenancy middleware, and the
// envelope/paging trio handled here.
var alwaysAllowedQuery = map[string]bool{
	"as_tenant": true,
	"limit":     true,
	"offset":    true,
	"envelope":  true,
}

// RejectUnknownQuery returns an error naming the first unrecognised query
// parameter. This is the actual fix for the F-61 class: `?page_size=1` used to
// be swallowed and answered 200 with the whole table. A caller that misspells
// its pagination parameter must LEARN that, not receive 21 MB.
//
// Keys are checked in sorted order so the message is deterministic.
func RejectUnknownQuery(r *http.Request, allowed ...string) error {
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	allow := make(map[string]bool, len(allowed)+len(alwaysAllowedQuery))
	for k := range alwaysAllowedQuery {
		allow[k] = true
	}
	for _, k := range allowed {
		allow[k] = true
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !allow[k] {
			known := make([]string, 0, len(allow))
			for a := range allow {
				known = append(known, a)
			}
			sort.Strings(known)
			return fmt.Errorf("unknown query parameter %q (accepted: %s)", k, strings.Join(known, ", "))
		}
	}
	return nil
}

// SliceOf applies an already-validated page to an in-memory slice.
//
// An offset past the end yields an EMPTY page, never a clamped last page: a
// clamped page re-serves rows the caller already walked past and makes a
// sequential walk never terminate.
func SliceOf[T any](rows []T, p Request) []T {
	if p.Offset >= len(rows) {
		return rows[:0:0]
	}
	end := p.Offset + p.Limit
	if end > len(rows) {
		end = len(rows)
	}
	return rows[p.Offset:end]
}

// Complete reports whether a single response IS the entire matching set —
// the one bit a client needs to tell a partial answer from a whole one.
func Complete(p Request, returned, total int) bool {
	return p.Offset == 0 && returned == total
}

// WriteHeaders stamps the bounded-read contract onto any response shape.
// Called on EVERY paginated read, including the legacy bare-array ones, so the
// true total is never withheld regardless of body shape.
func WriteHeaders(w http.ResponseWriter, p Request, returned, total int) {
	h := w.Header()
	h.Set(HeaderTotalCount, strconv.Itoa(total))
	h.Set(HeaderPageLimit, strconv.Itoa(p.Limit))
	h.Set(HeaderPageOffset, strconv.Itoa(p.Offset))
	h.Set(HeaderPageMax, strconv.Itoa(p.Max))
	if Complete(p, returned, total) {
		h.Set(HeaderPageDone, "true")
	} else {
		h.Set(HeaderPageDone, "false")
	}
}

// Envelope is the opt-in (?envelope=1) JSON body: the rows under `key`
// plus the same numbers the headers carry.
func Envelope(key string, rows any, p Request, returned, total int) map[string]any {
	return map[string]any{
		key:        rows,
		"total":    total,
		"returned": returned,
		"limit":    p.Limit,
		"offset":   p.Offset,
		"complete": Complete(p, returned, total),
	}
}

// Write is the whole contract in one call: headers always, envelope when
// the caller opted in, legacy bare shape otherwise.
func Write(w http.ResponseWriter, key string, rows any, p Request, returned, total int) {
	WriteHeaders(w, p, returned, total)
	if p.Envelope {
		writeBody(w, Envelope(key, rows, p, returned, total))
		return
	}
	writeBody(w, rows)
}
