package main

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
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
	List(tenant string, cross bool, q auditQuery) []AuditEvent
}

// auditQuery bounds a List: newest-first within an optional [Since, Before) time
// window, capped at Limit (see clampAuditLimit).
type auditQuery struct {
	Limit  int
	Before time.Time // exclusive upper bound (keyset pagination cursor); zero = newest
	Since  time.Time // inclusive lower bound; zero = unbounded
}

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
func (s *auditStore) List(tenant string, cross bool, q auditQuery) []AuditEvent {
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
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if limit := clampAuditLimit(q.Limit); len(out) > limit {
		out = out[:limit]
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

// handleAudit serves the audit trail, scoped to the caller's tenant. Admin-gated.
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
	tenant, cross := principalTenant(claims)
	q := auditQuery{Limit: auditDefaultLimit}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	// before/since accept RFC3339 timestamps for keyset pagination + range
	// filtering ("?before=<ts of the last row you saw>" walks older pages).
	if v := r.URL.Query().Get("before"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Before = t
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Since = t
		}
	}
	writeJSON(w, http.StatusOK, s.audit.List(tenant, cross, q))
}
