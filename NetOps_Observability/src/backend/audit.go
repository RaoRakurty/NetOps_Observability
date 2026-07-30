package backend

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"netops/backend/internal/audit"
	"netops/backend/internal/platformdb"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/httppage"
)

// randHex mints a crypto-random lowercase-hex id of nBytes entropy. Used across
// the root package for event/record ids (it lived in refresh.go until the
// refresh store moved to internal/session, which keeps its own copy).
// randID is a 32-hex (16-byte) crypto-random object id — re-homed from
// saved.go when that store moved; the package keeps its own copy.
func randID() string { return randHex(16) }

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

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

// normTenant lowercases/trims a tenant id — main's copy (the audit store moved
// to internal/audit, which keeps its own strict-compare helper).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// internal/audit wiring: source-compat shims + the backend selector.
type (
	AuditEvent = audit.Event
	auditQuery = audit.Query
	auditRepo  = audit.Repo
)

const auditMergeCeiling = audit.MergeCeiling

func clampAuditLimit(n int) int { return audit.ClampLimit(n) }

// newAuditStore selects the audit backend: per-row RLS pg under
// STORE_BACKEND=postgres, else the bounded file ring.
func newAuditStore(path string) (auditRepo, error) {
	if ps, ok := platformdb.ActivePG(); ok {
		return audit.NewPGStore(ps.DB(), logError), nil
	}
	return audit.NewFileStore(path, platformKV{})
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
			Actor:  claims.Sub,
			Tenant: tenant,
			Cross:  cross,
			Method: r.Method,
			// Masked: a DENIED request on a capability-link route still carries
			// the token in its path, and this trail is persisted to Postgres and
			// readable by admins. A forged-or-expired token is exactly what an
			// attacker probes with — recording it verbatim hands a reader the
			// candidate. Same helper the request log uses.
			Path:     maskCapabilityTokenPath(r.URL.Path),
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
	if err := httppage.RejectUnknownQuery(r, "before", "since"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	page, err := httppage.Parse(r, audit.DefaultLimit, audit.MaxQueryLimit)
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
	httppage.LogTruncated("/api/audit", page, len(events), total)
	httppage.Write(w, "audit", events, page, len(events), total)
}
