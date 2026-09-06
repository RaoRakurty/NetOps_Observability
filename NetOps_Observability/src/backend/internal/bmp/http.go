// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// http.go — the read surface, under /api/bgp/bmp/*.
//
// Every handler follows the same order, and the order IS the isolation
// guarantee (the igpmon/pcap precedent):
//
//  1. GET only, then AUTHORIZE at the read gate.
//  2. REFUSE unknown query parameters and BOUND every accepted value. A bound
//     is refused, never clamped: a caller who asks for 10 000 rows is told they
//     cannot have them, instead of getting 200 rows behind a 200 status that
//     reads like "that is all the data there is".
//  3. READ through the store, which takes (tenant, cross) and CANNOT be asked
//     for an unscoped list.
//  4. REPORT coverage honestly: with no session up, the answer says so rather
//     than presenting an empty feed as a converged, quiet network.
//
// The tenant is never read from a query string or a body.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Read bounds (§9: every read has a ceiling).
const (
	defaultUpdateLimit = 100
	maxUpdateLimit     = 1000

	// maxFilterLen bounds a filter string before it is parsed. A megabyte of
	// "prefix" is not a prefix.
	maxFilterLen = 64
)

// cursorPrefix versions the opaque cursor. A cursor from a different version
// is refused rather than reinterpreted — a silently-misread cursor is a page
// that skips rows.
const cursorPrefix = "bmp1:"

// Handler returns the single dispatcher for the /api/bgp/bmp/* routes. main.go
// registers each concrete path against it, so every route stays individually
// visible to the route-isolation ledger guard.
func (a *API) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a == nil {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
			return
		}
		const prefix = "/api/bgp/bmp/"
		op := strings.TrimPrefix(r.URL.Path, prefix)
		if op == r.URL.Path || strings.Contains(op, "/") {
			http.NotFound(w, r)
			return
		}
		switch op {
		case "sessions":
			a.handleSessions(w, r)
		case "updates":
			a.handleUpdates(w, r)
		case "stats":
			a.handleStats(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

// rejectUnknownQuery fails closed on any parameter this endpoint does not
// accept. `as_tenant` is always allowed because the platform's tenancy
// middleware consumes it (and NARROWS with it — it can never widen scope).
func rejectUnknownQuery(r *http.Request, allowed ...string) error {
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	allow := map[string]bool{"as_tenant": true}
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

// coverage is the honesty block every response carries. It names what the
// answer is BUILT FROM, so an empty feed reads as "nothing is exporting to us"
// rather than as "your network announced nothing".
type coverage struct {
	// Receiver is always true where these routes are registered — they only
	// exist when FEATURE_BMP is on.
	Receiver bool `json:"receiver_enabled"`
	// SessionsUp is how many routers are currently exporting to this platform.
	SessionsUp int `json:"sessions_up"`
	// Complete is false when ANY of the caller's sessions has dropped updates
	// under backpressure or hit a parse error — i.e. when the stored feed is
	// known to be missing something.
	Complete bool     `json:"complete"`
	Notes    []string `json:"notes"`
}

func (a *API) coverageFor(st StatsView) coverage {
	c := coverage{Receiver: true, SessionsUp: st.SessionsUp, Complete: true}
	if st.Sessions == 0 {
		c.Complete = false
		c.Notes = append(c.Notes, "No router is exporting BMP to this platform. This is an empty FEED, not an empty routing table — point a router's BMP export at the receiver (see the ingestion guide).")
		return c
	}
	if st.SessionsUp == 0 {
		c.Complete = false
		c.Notes = append(c.Notes, "Every BMP session is closed; the records below are historical and the peer states are reported as unknown, not as up.")
	}
	if st.UpdatesDropped > 0 {
		c.Complete = false
		c.Notes = append(c.Notes, fmt.Sprintf("%d update records were dropped by the bounded ring — the stored feed is incomplete.", st.UpdatesDropped))
	}
	if st.ParseErrors > 0 {
		c.Complete = false
		c.Notes = append(c.Notes, fmt.Sprintf("%d frames could not be parsed and were skipped.", st.ParseErrors))
	}
	if st.Unsupported > 0 {
		c.Complete = false
		c.Notes = append(c.Notes, fmt.Sprintf("%d well-formed elements (address families or path attributes this receiver does not decode) arrived and are NOT reflected below.", st.Unsupported))
	}
	c.Notes = append(c.Notes, "This is a bounded monitoring feed of recent updates, not a converged RIB: a prefix that is absent has simply not been seen recently.")
	return c
}

// handleSessions serves GET /api/bgp/bmp/sessions.
func (a *API) handleSessions(w http.ResponseWriter, r *http.Request) {
	p, ok := a.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := rejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	sessions := a.store.Sessions(p.Tenant, p.Cross)
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"sessions": sessions,
		"count":    len(sessions),
		"coverage": a.coverageFor(a.store.Stats(p.Tenant, p.Cross)),
	})
}

// handleStats serves GET /api/bgp/bmp/stats — the caller's OWN aggregate. The
// process-wide counters are deliberately not exposed here: another tenant's
// message volume is another tenant's data.
func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	p, ok := a.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := rejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	st := a.store.Stats(p.Tenant, p.Cross)
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"stats":    st,
		"limits":   a.limits(),
		"coverage": a.coverageFor(st),
	})
}

// limits publishes the receiver's hard bounds, so an operator reading a
// non-zero dropped count can see WHAT it was measured against.
func (a *API) limits() map[string]any {
	maxConn := a.deps.MaxConnections
	if maxConn <= 0 {
		maxConn = MaxConnections
	}
	recs := a.deps.MaxSessionRecords
	if recs <= 0 {
		recs = MaxSessionRecords
	}
	ring := a.deps.MaxUpdatesPerSession
	if ring <= 0 {
		ring = MaxUpdatesPerSession
	}
	return map[string]any{
		"max_connections":         maxConn,
		"max_session_records":     recs,
		"max_updates_per_session": ring,
		"max_message_bytes":       MaxMessageSize,
	}
}

// handleUpdates serves GET /api/bgp/bmp/updates.
func (a *API) handleUpdates(w http.ResponseWriter, r *http.Request) {
	p, ok := a.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := rejectUnknownQuery(r, "prefix", "peer", "session", "limit", "cursor"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	q := r.URL.Query()

	limit, err := parseLimit(q.Get("limit"), defaultUpdateLimit, maxUpdateLimit)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	f := UpdateFilter{Limit: limit}

	if raw := strings.TrimSpace(q.Get("prefix")); raw != "" {
		pfx, perr := parsePrefixFilter(raw)
		if perr != nil {
			a.deps.WriteError(w, http.StatusBadRequest, perr)
			return
		}
		f.Prefix, f.HasPrefix = pfx, true
	}
	if raw := strings.TrimSpace(q.Get("peer")); raw != "" {
		peer, perr := parsePeerFilter(raw)
		if perr != nil {
			a.deps.WriteError(w, http.StatusBadRequest, perr)
			return
		}
		f.Peer = peer
	}
	if raw := strings.TrimSpace(q.Get("session")); raw != "" {
		if len(raw) > maxFilterLen || !isSessionID(raw) {
			a.deps.WriteError(w, http.StatusBadRequest, errors.New("session: not a session id"))
			return
		}
		f.Session = raw
	}
	if raw := strings.TrimSpace(q.Get("cursor")); raw != "" {
		before, cerr := decodeCursor(raw)
		if cerr != nil {
			a.deps.WriteError(w, http.StatusBadRequest, cerr)
			return
		}
		f.Before = before
	}

	rows := a.store.Updates(p.Tenant, p.Cross, f)
	body := map[string]any{
		"updates":  rows,
		"count":    len(rows),
		"limit":    limit,
		"coverage": a.coverageFor(a.store.Stats(p.Tenant, p.Cross)),
	}
	// A full page gets a cursor. A short page does NOT: handing back a cursor
	// that yields nothing makes a walker loop forever on an exhausted feed.
	if len(rows) == limit && limit > 0 {
		body["next_cursor"] = encodeCursor(rows[len(rows)-1].Seq)
	}
	a.deps.WriteJSON(w, http.StatusOK, body)
}

// parseLimit reads ?limit= and fails closed on anything out of range.
func parseLimit(raw string, def, max int) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("limit: %q is not an integer", raw)
	}
	if n < 1 || n > max {
		return 0, fmt.Errorf("limit: %d is outside the accepted range 1..%d", n, max)
	}
	return n, nil
}

// parsePrefixFilter accepts a CIDR ("10.0.0.0/8") or a bare address, which is
// read as a host prefix. It is REFUSED, not ignored, when unparseable.
func parsePrefixFilter(raw string) (netip.Prefix, error) {
	if len(raw) > maxFilterLen {
		return netip.Prefix{}, fmt.Errorf("prefix: longer than %d characters", maxFilterLen)
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("prefix: %q is not a CIDR", raw)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("prefix: %q is neither a CIDR nor an IP address", raw)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parsePeerFilter accepts an IP address and normalizes it, so "10.0.0.1" and
// "::ffff:10.0.0.1" do not silently miss each other.
func parsePeerFilter(raw string) (string, error) {
	if len(raw) > maxFilterLen {
		return "", fmt.Errorf("peer: longer than %d characters", maxFilterLen)
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("peer: %q is not an IP address", raw)
	}
	return a.Unmap().String(), nil
}

// isSessionID reports whether a string has the receiver's session-id shape.
// Session ids are minted by this package, so anything else is a caller error.
func isSessionID(s string) bool {
	const p = "bmp-"
	if !strings.HasPrefix(s, p) || len(s) == len(p) {
		return false
	}
	for _, r := range s[len(p):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// encodeCursor renders an opaque keyset position. It is opaque so the page
// boundary stays an implementation detail a client cannot forge meaning into;
// it is NOT a security boundary, which is why the tenant scope is re-applied on
// every read regardless of what a cursor says.
func encodeCursor(seq uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + strconv.FormatUint(seq, 10)))
}

// decodeCursor parses one. A cursor that is not ours is REFUSED.
func decodeCursor(raw string) (uint64, error) {
	if len(raw) > 128 {
		return 0, errors.New("cursor: too long to be one of ours")
	}
	dec, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return 0, errors.New("cursor: not a valid cursor")
	}
	s := string(dec)
	if !strings.HasPrefix(s, cursorPrefix) {
		return 0, errors.New("cursor: not a valid cursor")
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(s, cursorPrefix), 10, 64)
	if err != nil {
		return 0, errors.New("cursor: not a valid cursor")
	}
	return n, nil
}
