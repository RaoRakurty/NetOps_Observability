// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC-4122 v5 name-based UUIDs (identity, not cryptography)
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"netops/backend/internal/audit"
	"netops/backend/internal/platformdb"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
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
	// Tracker 235: the file ring is shared by every authenticated request and
	// spans hours, so platform-global config changes get their own separately
	// bounded trail beside it. The env READ stays here (the ParseRetentionDays
	// precedent); the package owns the defaults and the ceiling.
	policy := audit.ParseTrailPolicy(os.Getenv(audit.EnvTrailDays), os.Getenv(audit.EnvTrailMaxEvents))
	store, err := audit.NewFileStore(path, platformKV{}, audit.WithTrailPolicy(policy))
	if err != nil {
		return nil, err
	}
	// The horizon is stated at boot. A retention bound nobody can read is
	// indistinguishable from no bound at all — and the whole point of this
	// trail is that an operator can rely on how far back it reaches.
	st := store.TrailStats()
	logInfo("audit", "platform config-change trail", map[string]any{
		"retention_days": policy.Days, "max_events": policy.MaxEvents,
		"retained": st.Kept, "oldest": st.Oldest.Format(time.RFC3339),
		"request_ring_events": audit.MaxEvents,
	})
	return store, nil
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

// ── audit → signal-spine bridge (item 121: audit as an event-feed source) ────
//
// The unified event feed answers "what is the network doing"; the first NOC
// question during an incident is "what did a HUMAN change". Those records exist
// (this trail) but in a different substrate (file/PG) than the feed
// (ClickHouse corr_signals) — so the bridge mirrors every successfully-ALLOWED
// mutating action onto the spine as source='audit', kind='audit_change'
// (visible under class=changes next to config/adjacency/cloud changes).
// Denials and errors are NOT mirrored: they are recorded in the trail but they
// are not changes, and the feed's "what changed" answer must stay honest.
//
// The mirror is best-effort and asynchronous behind a BOUNDED queue (§9): the
// audit trail itself is the durable record — a full queue or a ClickHouse
// outage drops the MIRROR (counted + logged, §10), never blocks the request
// path and never loses the audit row. Tenant mapping: a scoped principal's
// action lands under its tenant (visible in that tenant's feed); a
// platform-owner/unauthenticated event lands untagged (tenant_id ''), which
// the strict row policy shows to the platform owner only — an owner action is
// never leaked into a tenant's feed.

// auditSignalQueueCap bounds the mirror queue (audit events are low-rate;
// hundreds of buffered events means ClickHouse is down, not that we're busy).
const auditSignalQueueCap = 512

type auditSignalBridge struct {
	inner   auditRepo
	queue   chan AuditEvent
	dropped int64 // updated atomically
}

// newAuditSignalBridge wraps the real store. No-op passthrough when ClickHouse
// is not configured (file-only deployments keep exactly the old behavior).
func newAuditSignalBridge(inner auditRepo) auditRepo {
	if envOr("CLICKHOUSE_URL", "") == "" {
		return inner
	}
	b := &auditSignalBridge{inner: inner, queue: make(chan AuditEvent, auditSignalQueueCap)}
	go b.run()
	return b
}

func (b *auditSignalBridge) List(tenant string, cross bool, q auditQuery) ([]AuditEvent, error) {
	return b.inner.List(tenant, cross, q)
}
func (b *auditSignalBridge) Count(tenant string, cross bool, q auditQuery) int {
	return b.inner.Count(tenant, cross, q)
}

func (b *auditSignalBridge) Record(e AuditEvent) {
	b.inner.Record(e) // the durable trail ALWAYS gets the event first
	b.mirror(e)
}

// RecordStrict propagates the durable trail's error (M19): the mirror is
// attempted only once the durable write succeeded — an event the trail refused
// must not surface in ClickHouse as if it were recorded.
func (b *auditSignalBridge) RecordStrict(e AuditEvent) error {
	if err := b.inner.RecordStrict(e); err != nil {
		return err
	}
	b.mirror(e)
	return nil
}

func (b *auditSignalBridge) mirror(e AuditEvent) {
	if !auditSignalWorthy(e) {
		return
	}
	select {
	case b.queue <- e:
	default:
		if n := atomic.AddInt64(&b.dropped, 1); n == 1 || n%100 == 0 {
			logWarn("audit.bridge", "signal mirror queue full — mirror dropped, audit trail unaffected",
				map[string]any{"dropped_total": n})
		}
	}
}

// auditSignalWorthy: only successfully-allowed mutations are changes. The
// synthetic methods some call sites use (e.g. "TRIAGE") count as mutating.
func auditSignalWorthy(e AuditEvent) bool {
	if e.Decision != "allow" {
		return false
	}
	switch e.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

func (b *auditSignalBridge) run() {
	for e := range b.queue {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		row, scope := auditSignalRow(e)
		if err := chInsertJSON(ctx, "netops.corr_signals", scope, []map[string]any{row}); err != nil {
			logWarn("audit.bridge", "signal mirror insert failed — audit trail unaffected", errf(err))
		}
		cancel()
	}
}

// auditSignalArea extracts the API area for the entity field: "/api/alerts/…"
// → "alerts". Bounded and shape-safe (path segments only).
func auditSignalArea(path string) string {
	p := strings.TrimPrefix(path, "/api/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "api"
	}
	if len(p) > 64 {
		p = p[:64]
	}
	return p
}

// auditSignalRow maps one audit event to a corr_signals row. Deterministic
// signal_id (UUIDv5 over the event identity) keeps a retried insert idempotent
// — the same rule the Python producers follow.
func auditSignalRow(e AuditEvent) (row map[string]any, scope string) {
	ts := e.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	tenant := ""
	if !e.Cross {
		tenant = normTenant(e.Tenant)
	}
	if tenant == TenantGlobal {
		tenant = "" // platform-owned, never a tenant literal on the spine
	}
	attrs := map[string]any{
		"actor":  e.Actor,
		"method": e.Method,
		"path":   e.Path,
		"status": e.Status,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil || len(attrsJSON) > 2048 {
		attrsJSON = []byte("{}")
	}
	scope = tenant
	if scope == "" {
		scope = "__all__" // deliberately platform-scoped write (visible choice)
	}
	return map[string]any{
		"tenant_id":      tenant,
		"signal_id":      uuidV5("audit|" + e.ID + "|" + e.Actor + "|" + e.Method + "|" + e.Path + "|" + strconv.FormatInt(ts.UnixNano(), 10)),
		"ts":             ts.UTC().Format("2006-01-02 15:04:05.000"),
		"source":         "audit",
		"kind":           "audit_change",
		"observer_id":    "platform-api",
		"observer_type":  "platform",
		"modality_class": "management_plane",
		"entity_type":    "service",
		"entity_id":      auditSignalArea(e.Path),
		"severity":       "info",
		"attrs":          string(attrsJSON),
	}, scope
}

// uuidV5 is RFC-4122 v5 (SHA-1, name-based) over a fixed platform namespace —
// minted by hand because the tree deliberately has no uuid dependency (§6).
func uuidV5(name string) string {
	// Namespace: a fixed random UUID minted for the audit bridge.
	ns := [16]byte{0x8e, 0x1f, 0x42, 0xb7, 0x5d, 0x0a, 0x4c, 0x39, 0x9b, 0x21, 0xd6, 0x44, 0x7a, 0x03, 0x5e, 0xc2}
	h := sha1.New() // #nosec G401 -- v5 UUID identity hashing per RFC 4122, not a security control
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
