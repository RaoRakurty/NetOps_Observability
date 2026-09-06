// Package audit is the tamper-evident-ish append-only audit trail: the event
// model, the bounded file ring and the per-row FORCE-RLS pg repository. The
// capture chokepoint (withAudit middleware) and the org-scoped read merge stay
// with the integrator.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
)

// randHex8 / sameTenantStrict mirror the integrator's helpers (duplicated per
// the no-utils rule).
func randHex8() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
	return hex.EncodeToString(b)
}

func sameTenantStrict(resourceTenant, principalTenant string) bool {
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(principalTenant))
}

// KV abstracts persistence for the file ring (the platform kv layer).
type KV interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

const (
	MaxEvents     = 5000 // file backend: bounded in-memory ring; oldest fall off
	DefaultLimit  = 200  // List default when no limit asked
	MaxQueryLimit = 1000 // List hard cap (avoid unbounded reads)
)

// Repo is the audit-trail seam: append-only Record + a tenant-scoped,
// time-bounded, newest-first paginated List. Two backends implement it:
//   - FileStore (file/default): a bounded in-memory ring flushed as one blob —
//     fine for single-node dev/lab.
//   - pgAuditStore (STORE_BACKEND=postgres, audit_pg.go): one row per event, no
//     load-all/rewrite-whole, queries served from SQL with RLS scoping the read.
type Repo interface {
	Record(e Event)
	// RecordStrict is Record with the persistence error PROPAGATED instead of
	// swallowed. M19: high-value actions — today the sealed-PII reveal, which
	// turns protected data back into plaintext — must be audit-BEFORE-commit:
	// if the trail cannot durably hold "who read what and why", the action
	// itself must not complete. Everything else keeps best-effort Record (an
	// audit blip must not break ordinary requests). Other candidates for the
	// strict path later: key rotation/retirement, backup restore, custody
	// overrides.
	RecordStrict(e Event) error
	// List returns the matching page, or an ERROR when the backend could not
	// answer. F-73: this used to return a bare slice, so a failed query was
	// indistinguishable from "no privileged actions occurred" — on the one
	// surface where silence must never read as success. A SIEM polling through
	// a PG blip recorded a clean bill of health.
	List(tenant string, cross bool, q Query) ([]Event, error)
	// Count is List's TRUE total under the SAME filters and the SAME tenant
	// scope, ignoring Limit/Offset.
	//
	// F-57: the Postgres trail is an unbounded INSERT (29,002 rows / 13 MB and
	// +597/day at audit time, with no counterpart trim) while its read path is
	// capped at 1,000. The table grew without bound and the UI stopped
	// reflecting it — growth was invisible BY CONSTRUCTION, on the one surface
	// where silence must never read as "no privileged actions occurred".
	// Reporting the real count is what makes that growth observable at all.
	Count(tenant string, cross bool, q Query) int
}

// Query bounds a List: newest-first within an optional [Since, Before) time
// window, capped at Limit (see ClampLimit) and skipping Offset rows.
type Query struct {
	Limit  int
	Offset int
	Before time.Time // exclusive upper bound (keyset pagination cursor); zero = newest
	Since  time.Time // inclusive lower bound; zero = unbounded
	// Path filters to one recorded route. Added for the Sensitive Data Access
	// view, which must show reveals ONLY. Filtering client-side over a capped
	// page would render an EMPTY list whenever reveals sit below the newest N
	// rows — a compliance surface that silently reports "nobody read anything"
	// is the one failure mode it must never have.
	Path string
}

// MergeCeiling bounds the org-admin merge path (auditScopedList), which
// must materialise Offset+Limit rows PER administered tenant before it can
// merge-sort them. Beyond this the caller is told — with a 400, never a short
// page — to walk with `before=` (keyset) instead of a growing offset.
const MergeCeiling = 5000

// ClampLimit normalizes a requested count: <=0 → default, over the cap →
// cap. Shared by both backends so paging behaves identically.
func ClampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultLimit
	case n > MaxQueryLimit:
		return MaxQueryLimit
	default:
		return n
	}
}

// Event is one recorded action.
type Event struct {
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

type FileStore struct {
	// flushMu serializes the whole append→marshal→Save sequence, so two
	// concurrent Records can never persist two snapshots OUT OF ORDER (an
	// older, shorter snapshot overwriting a newer one — a silently truncated
	// trail). It is deliberately NOT mu: mu is held only for the in-memory
	// append and marshal and is released before the blocking kv IO, so List /
	// Count never wait on a disk write.
	//
	// Lock order is always flushMu → mu, and nothing takes mu before flushMu,
	// so the pair cannot deadlock.
	flushMu sync.Mutex
	mu      sync.RWMutex
	path    string
	kv      KV
	events  []Event // append-only, capped at MaxEvents

	// The retained platform trail (tracker 235): the same events, but only the
	// platform-global CONFIG CHANGES, in their own file under their own policy,
	// so the request ring rolling cannot take them with it. See platformtrail.go.
	trailPath string
	policy    TrailPolicy
	retained  []Event
	dropped   int64 // cumulative retained-trail evictions, for TrailStats
}

// FileOption configures a FileStore at construction.
type FileOption func(*FileStore)

// WithTrailPolicy sets the retained platform trail's bounds. Unset = the
// conservative default (DefaultTrailPolicy).
func WithTrailPolicy(p TrailPolicy) FileOption {
	return func(s *FileStore) { s.policy = p }
}

// NewFileStore opens the bounded in-memory ring mirrored to the kv layer
// (backend selection is the integrator's job), together with the separately
// bounded platform trail beside it.
func NewFileStore(path string, kv KV, opts ...FileOption) (*FileStore, error) {
	if path == "" {
		path = "/data/audit.json"
	}
	s := &FileStore{path: path, kv: kv, policy: DefaultTrailPolicy()}
	for _, opt := range opts {
		opt(s)
	}
	// The trail sits beside the ring, named for it, so an operator looking at
	// the data directory can see immediately which file is which.
	s.trailPath = strings.TrimSuffix(path, ".json") + "-platform.json"
	if b, err := kv.Load(path); err == nil {
		_ = json.Unmarshal(b, &s.events) // best-effort: a corrupt/empty trail just starts fresh
	}
	if b, err := kv.Load(s.trailPath); err == nil {
		_ = json.Unmarshal(b, &s.retained) // best-effort, same contract as the ring
	}
	// Apply the policy on LOAD as well as on write: a horizon shortened between
	// two boots must take effect at the next boot, not at the next change.
	kept, byAge, byCount := pruneTrail(s.retained, s.policy, time.Now().UTC())
	s.retained = kept
	s.noteTrailDrops(byAge, byCount)
	return s, nil
}

// TrailStats reports what the retained platform trail holds and what it has had
// to evict. It exists so the ceiling is OBSERVABLE — a bound nobody can read is
// indistinguishable from no bound at all.
func (s *FileStore) TrailStats() TrailStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := TrailStats{Policy: s.policy, Kept: len(s.retained), Dropped: s.dropped}
	if len(s.retained) > 0 {
		st.Oldest = s.retained[0].Time
	}
	return st
}

// noteTrailDrops counts and REPORTS evictions. An eviction is a permanent loss
// of attribution, so it is never silent (§10), and the two reasons are logged
// distinctly: aging out is the policy working as configured, hitting the count
// ceiling is the trail being NARROWER than the operator asked for.
func (s *FileStore) noteTrailDrops(byAge, byCount int) {
	if byAge > 0 {
		s.dropped += int64(byAge)
		applog.Info("audit", "platform trail: events aged out of the retention horizon",
			map[string]any{"dropped": byAge, "retention_days": s.policy.Days})
	}
	if byCount > 0 {
		s.dropped += int64(byCount)
		applog.Error("audit", "platform trail: FULL — oldest platform config changes evicted before their retention horizon; raise "+
			EnvTrailMaxEvents+" or move the audit trail to Postgres",
			map[string]any{"dropped": byCount, "max_events": s.policy.MaxEvents, "retention_days": s.policy.Days})
	}
}

// Record appends an event (id/time stamped here) and persists. Best-effort: an
// audit write must never break the request, so persistence errors are swallowed
// (the in-memory trail still has it).
func (s *FileStore) Record(e Event) {
	if err := s.record(e); err != nil {
		// The in-memory trail still has the event (see doc above), but a trail
		// that stops persisting is an audit gap — it must be visible.
		applog.Error("audit", "audit trail not persisted; events survive in memory only", map[string]any{"error": err.Error()})
	}
}

// RecordStrict propagates the persistence error (see Repo). The event still
// lands in the in-memory ring either way — a failed strict write refuses the
// caller's ACTION, it does not un-witness the attempt.
func (s *FileStore) RecordStrict(e Event) error { return s.record(e) }

func (s *FileStore) record(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = randHex8()
	}
	// One writer at a time through append→marshal→Save (see flushMu): the
	// snapshot that lands on disk is always the newest one taken.
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	s.mu.Lock()
	s.events = append(s.events, e)
	if len(s.events) > MaxEvents {
		s.events = s.events[len(s.events)-MaxEvents:]
	}
	b, err := json.Marshal(s.events)
	// Tracker 235: a platform-global config change is ALSO appended to the
	// retained trail, which the request ring's eviction cannot reach. It is
	// marshalled under the same lock so the two snapshots can never disagree
	// about an event, and written outside it (below) like the ring is.
	var trail []byte
	var trailErr error
	if retain := IsPlatformChange(e); retain {
		s.retained = append(s.retained, e)
		kept, byAge, byCount := pruneTrail(s.retained, s.policy, e.Time)
		s.retained = kept
		s.noteTrailDrops(byAge, byCount)
		trail, trailErr = json.Marshal(s.retained)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if trailErr != nil {
		return trailErr
	}
	if trail != nil {
		// The retained trail is written FIRST: if only one of the two lands,
		// the one that must survive is the long-lived record of the change.
		if err := s.kv.Save(s.trailPath, trail); err != nil {
			return err
		}
	}
	return s.kv.Save(s.path, b)
}

// List returns events newest-first, scoped to the caller: the platform owner
// sees all; a scoped principal sees only its own tenant's events (global/untagged
// events never match a scoped tenant — same rule the pg backend's RLS enforces).
// List cannot fail on the file backend (the ring is in memory), but it returns
// an error to satisfy the seam — the Postgres backend genuinely can.
func (s *FileStore) List(tenant string, cross bool, q Query) ([]Event, error) {
	out := s.matching(tenant, cross, q)
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	limit := ClampLimit(q.Limit)
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
func (s *FileStore) Count(tenant string, cross bool, q Query) int {
	return len(s.matching(tenant, cross, q))
}

// matching applies the tenant scope and the time window — the filters List and
// Count MUST share, so a page and its total can never disagree.
func (s *FileStore) matching(tenant string, cross bool, q Query) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Event, 0, len(s.events)+len(s.retained))
	seen := make(map[string]bool, len(s.events))
	keep := func(e Event, dedupe bool) {
		if !(cross || sameTenantStrict(e.Tenant, tenant)) {
			return
		}
		if !q.Before.IsZero() && !e.Time.Before(q.Before) {
			return
		}
		if !q.Since.IsZero() && e.Time.Before(q.Since) {
			return
		}
		if q.Path != "" && e.Path != q.Path {
			return
		}
		if dedupe && seen[e.ID] {
			return
		}
		out = append(out, e)
	}
	for _, e := range s.events {
		seen[e.ID] = true
		keep(e, false)
	}
	// Tracker 235: the retained platform trail is part of the ANSWER, not a
	// separate surface. A change that has fallen out of the request ring is
	// still returned here — same tenant scope, same window, deduplicated by id
	// against the ring so a recent change is not reported twice.
	for _, e := range s.retained {
		keep(e, true)
	}
	return out
}
