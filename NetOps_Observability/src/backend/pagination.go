package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// pagination.go — the ONE bounded-read contract for list endpoints (audit
// F-57 / F-61 / F-74 / F-79, 2026-07-21).
//
// The audit's diagnosis of this class was not "a limit was missing"; it was
// that the endpoints ACCEPTED pagination parameters, answered 200, and did
// something other than what the caller asked:
//
//   - /api/devices parsed nothing and returned the whole table — four different
//     parameter sets produced byte-identical 218 KB responses (F-61).
//   - /api/vulns truncated 7,560 findings to 500 with no offset and no cursor,
//     so 5,560 of them were unreachable at ANY limit (F-79).
//   - /api/incidents accepted ?severity=bogus and applied a DIFFERENT filter
//     (F-74).
//   - /api/audit capped the read at 1,000 while the table grew without bound,
//     so the trail's growth was invisible by construction (F-57).
//
// Three rules follow, and this file is the only place they are implemented:
//
//  1. A parameter is APPLIED or REJECTED — never accepted and ignored.
//     rejectUnknownQuery names the offending key in a 400. Silent acceptance
//     is what made this class invisible for the whole life of the codebase.
//  2. A bounded read reports the caller's TRUE total. Fewer rows than asked
//     for, returned silently, is indistinguishable at the client from "that is
//     all the data there is".
//  3. Range/format errors fail CLOSED (intQuery, F-71 precedent) — never
//     substitute a default the caller did not ask for.
//
// Wire compatibility. `docs/design/sot-provider-model.md` pins /api/devices*
// to an unchanged response shape, and the SPA types /api/audit and
// /api/incidents as bare arrays. So the total is reported on EVERY response as
// headers (always present, shape-neutral), and the JSON envelope carrying the
// same numbers is opt-in via ?envelope=1. Neither is silent.
const (
	headerTotalCount = "X-Total-Count"    // TRUE number of rows matching the caller's filter
	headerPageLimit  = "X-Page-Limit"     // limit actually applied
	headerPageOffset = "X-Page-Offset"    // offset actually applied
	headerPageDone   = "X-Page-Complete"  // "true" iff this response IS the whole matching set
	headerPageMax    = "X-Page-Max-Limit" // server-side ceiling, so a client can size its walk
)

// Per-endpoint bounds. The DEFAULT is deliberately the same as the MAX on
// /api/devices: the SPA and every existing API-key client call the endpoint
// with no parameters at all, and quietly handing them 100 of 512 devices would
// be a NEW instance of the very defect this change closes. The ceiling is a
// real bound (an unbounded materialisation of a 50,000-device fleet is a 21 MB
// per-caller response, F-61), and crossing it is announced three ways: the
// X-Page-Complete header, the ?envelope=1 `complete` field, and a structured
// server log — never silence.
const (
	deviceDefaultPage = 5000
	deviceMaxPage     = 5000
)

// logTruncatedPage records a bounded read that returned less than the caller
// matched WITHOUT the caller having asked for a page. A client walking pages on
// purpose is not a defect and is not logged; a client that asked for "the list"
// and silently got part of it is exactly the F-61 shape, and §10 (no silent
// failures) says an operator must be able to see it.
func logTruncatedPage(endpoint string, p pageRequest, returned, total int) {
	if p.Explicit || pageComplete(p, returned, total) {
		return
	}
	logError("pagination", "unpaged read truncated at the server ceiling", map[string]any{
		"endpoint": endpoint, "returned": returned, "total": total,
		"limit": p.Limit, "offset": p.Offset,
	})
}

// pageRequest is a parsed, validated, in-range bounded read.
type pageRequest struct {
	Limit    int
	Offset   int
	Max      int
	Envelope bool
	// Explicit records that the caller actually supplied limit and/or offset,
	// i.e. asked for a page rather than "the list". Only used to decide whether
	// a short response is worth an operator-facing log line.
	Explicit bool
}

// pageMaxOffset bounds `offset` itself. Without a ceiling, offset is an
// unbounded integer a caller can use to make the server skip an arbitrary
// number of rows; with a ceiling, an over-large offset is an explicit 400
// rather than a silently empty page that reads like "no more data".
const pageMaxOffset = 1_000_000

// parsePage parses limit/offset/envelope. Both numeric parameters go through
// intQuery, which fails closed on malformed or out-of-range input (F-71), so
// every error here is a 400 that names the parameter and its legal range.
func parsePage(r *http.Request, defLimit, maxLimit int) (pageRequest, error) {
	p := pageRequest{Max: maxLimit}
	var err error
	if p.Limit, err = intQuery(r, "limit", defLimit, 1, maxLimit); err != nil {
		return pageRequest{}, err
	}
	if p.Offset, err = intQuery(r, "offset", 0, 0, pageMaxOffset); err != nil {
		return pageRequest{}, err
	}
	if p.Envelope, err = boolQuery(r, "envelope"); err != nil {
		return pageRequest{}, err
	}
	q := r.URL.Query()
	p.Explicit = q.Get("limit") != "" || q.Get("offset") != ""
	return p, nil
}

// boolQuery parses a strict boolean query parameter. Anything that is not an
// exact member of the accepted vocabulary is an error — "envelope=yes please"
// must never quietly mean false.
func boolQuery(r *http.Request, key string) (bool, error) {
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

// rejectUnknownQuery returns an error naming the first unrecognised query
// parameter. This is the actual fix for the F-61 class: `?page_size=1` used to
// be swallowed and answered 200 with the whole table. A caller that misspells
// its pagination parameter must LEARN that, not receive 21 MB.
//
// Keys are checked in sorted order so the message is deterministic.
func rejectUnknownQuery(r *http.Request, allowed ...string) error {
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

// pageSliceOf applies an already-validated page to an in-memory slice.
//
// An offset past the end yields an EMPTY page, never a clamped last page: a
// clamped page re-serves rows the caller already walked past and makes a
// sequential walk never terminate.
func pageSliceOf[T any](rows []T, p pageRequest) []T {
	if p.Offset >= len(rows) {
		return rows[:0:0]
	}
	end := p.Offset + p.Limit
	if end > len(rows) {
		end = len(rows)
	}
	return rows[p.Offset:end]
}

// pageComplete reports whether a single response IS the entire matching set —
// the one bit a client needs to tell a partial answer from a whole one.
func pageComplete(p pageRequest, returned, total int) bool {
	return p.Offset == 0 && returned == total
}

// writePageHeaders stamps the bounded-read contract onto any response shape.
// Called on EVERY paginated read, including the legacy bare-array ones, so the
// true total is never withheld regardless of body shape.
func writePageHeaders(w http.ResponseWriter, p pageRequest, returned, total int) {
	h := w.Header()
	h.Set(headerTotalCount, intToString(total))
	h.Set(headerPageLimit, intToString(p.Limit))
	h.Set(headerPageOffset, intToString(p.Offset))
	h.Set(headerPageMax, intToString(p.Max))
	if pageComplete(p, returned, total) {
		h.Set(headerPageDone, "true")
	} else {
		h.Set(headerPageDone, "false")
	}
}

// pageEnvelope is the opt-in (?envelope=1) JSON body: the rows under `key`
// plus the same numbers the headers carry.
func pageEnvelope(key string, rows any, p pageRequest, returned, total int) map[string]any {
	return map[string]any{
		key:        rows,
		"total":    total,
		"returned": returned,
		"limit":    p.Limit,
		"offset":   p.Offset,
		"complete": pageComplete(p, returned, total),
	}
}

// writePage is the whole contract in one call: headers always, envelope when
// the caller opted in, legacy bare shape otherwise.
func writePage(w http.ResponseWriter, key string, rows any, p pageRequest, returned, total int) {
	writePageHeaders(w, p, returned, total)
	if p.Envelope {
		writeJSON(w, http.StatusOK, pageEnvelope(key, rows, p, returned, total))
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
