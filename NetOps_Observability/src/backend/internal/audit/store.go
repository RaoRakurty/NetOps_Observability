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
)

// randHex8 / sameTenantStrict mirror the integrator's helpers (duplicated per
// the no-utils rule).
func randHex8() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
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
	mu     sync.RWMutex
	path   string
	kv     KV
	events []Event // append-only, capped at MaxEvents
}

// NewFileStore opens the bounded in-memory ring mirrored to the kv layer
// (backend selection is the integrator's job).
func NewFileStore(path string, kv KV) (*FileStore, error) {
	if path == "" {
		path = "/data/audit.json"
	}
	s := &FileStore{path: path, kv: kv}
	if b, err := kv.Load(path); err == nil {
		_ = json.Unmarshal(b, &s.events) // a corrupt/empty trail just starts fresh
	}
	return s, nil
}

// Record appends an event (id/time stamped here) and persists. Best-effort: an
// audit write must never break the request, so persistence errors are swallowed
// (the in-memory trail still has it).
func (s *FileStore) Record(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = randHex8()
	}
	s.mu.Lock()
	s.events = append(s.events, e)
	if len(s.events) > MaxEvents {
		s.events = s.events[len(s.events)-MaxEvents:]
	}
	b, err := json.Marshal(s.events)
	s.mu.Unlock()
	if err == nil {
		_ = s.kv.Save(s.path, b)
	}
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
	out := make([]Event, 0, len(s.events))
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
