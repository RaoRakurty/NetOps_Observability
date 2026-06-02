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

const auditMaxEvents = 5000 // bounded ring; oldest events fall off

// AuditEvent is one recorded action.
type AuditEvent struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`              // username/sub ("" = unauthenticated)
	Tenant   string    `json:"tenant,omitempty"`   // actor's tenant
	Cross    bool      `json:"cross,omitempty"`    // actor was the platform owner
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
	Decision string    `json:"decision"` // allow | deny | error
	Remote   string    `json:"remote,omitempty"`
}

type auditStore struct {
	mu     sync.RWMutex
	path   string
	events []AuditEvent // append-only, capped at auditMaxEvents
}

func newAuditStore(path string) (*auditStore, error) {
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
// sees all; a scoped principal sees only its own tenant's events. limit<=0 ⇒ all.
func (s *auditStore) List(tenant string, cross bool, limit int) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, 0, len(s.events))
	for _, e := range s.events {
		if cross || sameTenantStrict(e.Tenant, tenant) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if limit > 0 && len(out) > limit {
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
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
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
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, s.audit.List(tenant, cross, limit))
}
