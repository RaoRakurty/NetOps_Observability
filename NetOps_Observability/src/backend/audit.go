package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// audit.go — a tamper-evident-ish append-only audit trail (Phase 3).
//
// Rather than instrument every handler, the trail is captured at ONE chokepoint:
// a middleware that runs after withAuth (so the principal is known) and records
// every mutating request and every authorization denial — who, what, when,
// tenant, and the decision (derived from the response status). This guarantees a
// new endpoint is audited automatically, the same way the central Authorize()
// guarantees it's access-controlled.
//
// /api/audit is itself tenant-scoped: the platform owner sees all events; a
// tenant admin sees only its own tenant's. before/after field-level diffs are a
// future enhancement (would need per-handler hooks); this records the action and
// outcome, which is the who/what/when/tenant/decision enterprises require.

const (
	auditMaxEvents     = 5000 // file backend: bounded in-memory ring; oldest fall off
	auditDefaultLimit  = 200  // List default when no limit asked
	auditMaxQueryLimit = 1000 // List hard cap (avoid unbounded reads)
)

// auditRepo is the audit-trail seam: append-only Record + a tenant-scoped,
// time-bounded, newest-first paginated List. Two backends implement it:
//   - auditStore (file/default): a bounded in-memory ring flushed as one blob —
//     fine for single-node dev/lab.
//   - pgAuditStore (STORE_BACKEND=postgres, audit_pg.go): one row per event, no
//     load-all/rewrite-whole, queries served from SQL with RLS scoping the read.
type auditRepo interface {
	Record(e AuditEvent)
	// List returns the matching page, or an ERROR when the backend could not
	// answer. F-73: this used to return a bare slice, so a failed query was
	// indistinguishable from "no privileged actions occurred" — on the one
	// surface where silence must never read as success. A SIEM polling through
	// a PG blip recorded a clean bill of health.
	List(tenant string, cross bool, q auditQuery) ([]AuditEvent, error)
	// Count is List's TRUE total under the SAME filters and the SAME tenant
	// scope, ignoring Limit/Offset.
	//
	// F-57: the Postgres trail is an unbounded INSERT (29,002 rows / 13 MB and
	// +597/day at audit time, with no counterpart trim) while its read path is
	// capped at 1,000. The table grew without bound and the UI stopped
	// reflecting it — growth was invisible BY CONSTRUCTION, on the one surface
	// where silence must never read as "no privileged actions occurred".
	// Reporting the real count is what makes that growth observable at all.
	Count(tenant string, cross bool, q auditQuery) int
}

// auditQuery bounds a List: newest-first within an optional [Since, Before) time
// window, capped at Limit (see clampAuditLimit) and skipping Offset rows.
type auditQuery struct {
	Limit  int
	Offset int
	Before time.Time // exclusive upper bound (keyset pagination cursor); zero = newest
	Since  time.Time // inclusive lower bound; zero = unbounded
}

// auditMergeCeiling bounds the org-admin merge path (auditScopedList), which
// must materialise Offset+Limit rows PER administered tenant before it can
// merge-sort them. Beyond this the caller is told — with a 400, never a short
// page — to walk with `before=` (keyset) instead of a growing offset.
const auditMergeCeiling = 5000

// clampAuditLimit normalizes a requested count: <=0 → default, over the cap →
// cap. Shared by both backends so paging behaves identically.
func clampAuditLimit(n int) int {
	switch {
	case n <= 0:
		return auditDefaultLimit
	case n > auditMaxQueryLimit:
		return auditMaxQueryLimit
	default:
		return n
	}
}

// AuditEvent is one recorded action.
type AuditEvent struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`            // username/sub ("" = unauthenticated)
	Tenant   string    `json:"tenant,omitempty"` // actor's tenant
	Cross    bool      `json:"cross,omitempty"`  // actor was the platform owner
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
	Decision string    `json:"decision"` // allow | deny | error
	Remote   string    `json:"remote,omitempty"`
	// Detail carries action-specific context for sensitive operations (e.g. an
	// export's query/size/execution_id) beyond the generic request envelope.
	Detail map[string]any `json:"detail,omitempty"`
}

type auditStore struct {
	mu     sync.RWMutex
	path   string
	events []AuditEvent // append-only, capped at auditMaxEvents
}

// newAuditStore selects the audit backend. Under STORE_BACKEND=postgres the trail
// is a real per-row append/query repository (no load-all); otherwise it's the
// file-backed bounded ring.
func newAuditStore(path string) (auditRepo, error) {
	if ps, ok := backend.(*pgStore); ok {
		return &pgAuditStore{db: ps.db}, nil
	}
	if path == "" {
		path = "/data/audit.json"
	}
	s := &auditStore{path: path}
	if b, err := kvLoad(path); err == nil {
		_ = json.Unmarshal(b, &s.events) // a corrupt/empty trail just starts fresh
	}
	return s, nil
}

// Record appends an event (id/time stamped here) and persists. Best-effort: an
// audit write must never break the request, so persistence errors are swallowed
// (the in-memory trail still has it).
func (s *auditStore) Record(e AuditEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = randHex(8)
	}
	s.mu.Lock()
	s.events = append(s.events, e)
	if len(s.events) > auditMaxEvents {
		s.events = s.events[len(s.events)-auditMaxEvents:]
	}
	b, err := json.Marshal(s.events)
	s.mu.Unlock()
	if err == nil {
		_ = kvSave(s.path, b)
	}
}

// List returns events newest-first, scoped to the caller: the platform owner
// sees all; a scoped principal sees only its own tenant's events (global/untagged
// events never match a scoped tenant — same rule the pg backend's RLS enforces).
// List cannot fail on the file backend (the ring is in memory), but it returns
// an error to satisfy the seam — the Postgres backend genuinely can.
func (s *auditStore) List(tenant string, cross bool, q auditQuery) ([]AuditEvent, error) {
	out := s.matching(tenant, cross, q)
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	limit := clampAuditLimit(q.Limit)
	if q.Offset >= len(out) {
		// Past the end is an EMPTY page, never a clamped last page: a clamped
		// page re-serves rows the caller already walked and never terminates.
		return out[:0:0], nil
	}
	end := q.Offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[q.Offset:end], nil
}

// Count is List's true total under the same filters and the same tenant scope.
func (s *auditStore) Count(tenant string, cross bool, q auditQuery) int {
	return len(s.matching(tenant, cross, q))
}

// matching applies the tenant scope and the time window — the filters List and
// Count MUST share, so a page and its total can never disagree.
func (s *auditStore) matching(tenant string, cross bool, q auditQuery) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, 0, len(s.events))
	for _, e := range s.events {
		if !(cross || sameTenantStrict(e.Tenant, tenant)) {
			continue
		}
		if !q.Before.IsZero() && !e.Time.Before(q.Before) {
			continue
		}
		if !q.Since.IsZero() && e.Time.Before(q.Since) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func auditDecision(status int) string {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden, status == http.StatusNotFound:
		return "deny"
	case status >= 400:
		return "error"
	default:
		return "allow"
	}
}

// withAudit records every mutating API request and every denial. Reads must run
// AFTER withAuth so the principal is in context. GET reads that succeed are not
// recorded (too noisy); GET denials are (probing).
func (s *server) withAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		if s.audit == nil || !strings.HasPrefix(r.URL.Path, "/api/") {
			return
		}
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		denied := auditDecision(rec.status) == "deny"
		if !mutating && !denied {
			return // successful reads are not worth recording
		}
		// Don't recurse on reads of the trail itself.
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/audit") {
			return
		}
		claims, _ := userFrom(r.Context())
		tenant, cross := principalTenant(claims)
		s.audit.Record(AuditEvent{
			Actor:    claims.Sub,
			Tenant:   tenant,
			Cross:    cross,
			Method:   r.Method,
			Path:     r.URL.Path,
			Status:   rec.status,
			Decision: auditDecision(rec.status),
			Remote:   auditClientIP(r),
		})
	})
}

func auditClientIP(r *http.Request) string {
	if trustProxy() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// auditScopedList returns the audit trail visible to the caller (PBAC Phase E,
// scoped audit visibility):
//   - platform owner → every event (cross);
//   - org-admin → events for ALL tenants in the org(s) it administers (queried
//     per-tenant and merged, so each read stays under its tenant's RLS — no
//     bypass, works for the file and Postgres backends alike);
//   - tenant admin → only its own tenant's events.
//
// Break-glass sessions are recorded like any other mutation, so they surface here.
func (s *server) auditScopedList(claims jwtClaims, q auditQuery) ([]AuditEvent, error) {
	tenant, cross := principalTenant(claims)
	if cross {
		return s.audit.List(tenant, true, q)
	}
	// Org-admin: union of the tenants in the orgs it administers, plus its own.
	if tids := s.auditOrgTenants(claims, tenant); len(tids) > 0 {
		// Each per-tenant read must cover the caller's whole window
		// (Offset+Limit) before the merge-sort can pick the right slice —
		// asking each tenant for only Limit rows and then slicing would drop
		// rows that belong on the page. auditMergeCeiling bounds that, and
		// handleAudit refuses (400) rather than serving a short page beyond it.
		sub := q
		sub.Offset = 0
		sub.Limit = clampAuditLimit(q.Limit) + q.Offset
		if sub.Limit > auditMergeCeiling {
			sub.Limit = auditMergeCeiling
		}
		var merged []AuditEvent
		for _, tid := range tids {
			part, err := s.audit.List(tid, false, sub)
			if err != nil {
				// F-73: one tenant's read failing used to contribute zero rows
				// and vanish into the merge — an org-admin got a SHORT page that
				// looked complete. A partial audit answer is a wrong audit
				// answer; refuse the whole request.
				return nil, fmt.Errorf("audit read failed for tenant %s: %w", tid, err)
			}
			merged = append(merged, part...)
		}
		sort.Slice(merged, func(i, j int) bool { return merged[i].Time.After(merged[j].Time) })
		limit := clampAuditLimit(q.Limit)
		if q.Offset >= len(merged) {
			return nil, nil
		}
		end := q.Offset + limit
		if end > len(merged) {
			end = len(merged)
		}
		return merged[q.Offset:end], nil
	}
	return s.audit.List(tenant, false, q)
}

// auditScopedCount is auditScopedList's TRUE total under the same scope and
// window. Per-tenant rows are disjoint, so the org-admin total is the sum.
// Returns -1 when a backend could not answer — never 0, which on this surface
// would read as "no privileged actions occurred".
func (s *server) auditScopedCount(claims jwtClaims, q auditQuery) int {
	tenant, cross := principalTenant(claims)
	if cross {
		return s.audit.Count(tenant, true, q)
	}
	if tids := s.auditOrgTenants(claims, tenant); len(tids) > 0 {
		total := 0
		for _, tid := range tids {
			n := s.audit.Count(tid, false, q)
			if n < 0 {
				return -1
			}
			total += n
		}
		return total
	}
	return s.audit.Count(tenant, false, q)
}

// auditOrgTenants is the de-duplicated tenant set an org-admin may read, or nil
// when the caller is not an org-admin. Shared by the list and count paths so
// the two can never disagree about scope.
func (s *server) auditOrgTenants(claims jwtClaims, tenant string) []string {
	orgs := s.orgAdminOrgs(claims.Sub)
	if len(orgs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(tid string) {
		if tid == "" || seen[tid] {
			return
		}
		seen[tid] = true
		out = append(out, tid)
	}
	for _, org := range orgs {
		for _, t := range s.tenants.ListByOrg(org) {
			add(t.ID)
		}
	}
	add(tenant) // its own tenant, in case it's outside the administered orgs
	return out
}

// handleAudit serves the audit trail, scoped to the caller (Phase E). Admin-gated.
func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	// F-57: `limit` used to be parsed with a discarded error and then silently
	// clamped, and a malformed `before`/`since` was silently dropped — so a SIEM
	// asking for a window it mistyped got the FULL newest page and read it as
	// the window. Every parameter is now applied as written or refused by name.
	if err := rejectUnknownQuery(r, "before", "since"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	page, err := parsePage(r, auditDefaultLimit, auditMaxQueryLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	q := auditQuery{Limit: page.Limit, Offset: page.Offset}
	// before/since accept RFC3339 timestamps for keyset pagination + range
	// filtering ("?before=<ts of the last row you saw>" walks older pages).
	if v := r.URL.Query().Get("before"); v != "" {
		t, perr := time.Parse(time.RFC3339, v)
		if perr != nil {
			writeError(w, http.StatusBadRequest, errors.New("before must be an RFC3339 timestamp"))
			return
		}
		q.Before = t
	}
	if v := r.URL.Query().Get("since"); v != "" {
		t, perr := time.Parse(time.RFC3339, v)
		if perr != nil {
			writeError(w, http.StatusBadRequest, errors.New("since must be an RFC3339 timestamp"))
			return
		}
		q.Since = t
	}
	// The org-admin merge path must materialise Offset+Limit rows per
	// administered tenant. Past the ceiling, say so — a short page here would
	// be indistinguishable from the end of the trail.
	if _, cross := principalTenant(claims); !cross && len(s.auditOrgTenants(claims, "")) > 0 &&
		q.Offset+q.Limit > auditMergeCeiling {
		writeError(w, http.StatusBadRequest, fmt.Errorf(
			"offset+limit must be <= %d for an org-scoped trail; walk older pages with ?before=<ts of the last row you saw>",
			auditMergeCeiling))
		return
	}
	// F-73: a failed query must NOT render as an empty trail. This is the one
	// endpoint where "no rows" is itself a security assertion — a SIEM reads it
	// as "no privileged actions occurred". 503 (not 500): the trail exists, we
	// just could not read it right now, and the caller should retry rather than
	// record a clean bill of health.
	events, err := s.auditScopedList(claims, q)
	if err != nil {
		logError("audit", "scoped list failed", map[string]any{"error": err.Error(), "user": claims.Sub})
		writeError(w, http.StatusServiceUnavailable,
			errors.New("audit trail is temporarily unreadable; this is NOT an empty trail — retry"))
		return
	}
	if events == nil {
		events = []AuditEvent{}
	}
	total := s.auditScopedCount(claims, q)
	logTruncatedPage("/api/audit", page, len(events), total)
	writePage(w, "audit", events, page, len(events), total)
}
