package ticketing

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// ticketing_store.go — persistence seam for RCA auto-ticketing (#78). Two
// backends selected like every other store (topology_store.go): an in-memory
// map for the default dependency-free build, and a Postgres-backed, RLS-scoped
// repository under STORE_BACKEND=postgres. BOTH enforce tenant isolation in the
// store itself (CLAUDE.md §3a): the in-memory store filters by tenant and never
// exposes an unscoped "list all" to a scoped caller; the pg store relies on the
// tenant_iso FORCE-RLS policy via withTenant. A non-cross caller can never see,
// fetch, write, or delete another tenant's policies, links, outbox, or audit.

// ErrPolicyConflict is returned by PutPolicy when saving an ENABLED policy
// while another policy is already enabled for the same (tenant, external
// system). The HTTP layer pre-checks and 409s with the conflicting policy's
// name; this store-level invariant closes the check-then-write race (and any
// non-API write path). In Postgres it is enforced transactionally by the
// incident_policies_one_enabled partial unique index (migration 0021).
var ErrPolicyConflict = errors.New("another policy is already enabled for this tenant and external system")

type Store interface {
	// incident policies
	ListPolicies(ctx context.Context, tenant string, cross bool) ([]IncidentPolicy, error)
	GetPolicy(ctx context.Context, tenant string, cross bool, id string) (IncidentPolicy, bool, error)
	// PutPolicy upserts one policy; returns ErrPolicyConflict when enabling it
	// would violate the one-enabled-per-(tenant, external_system) invariant.
	PutPolicy(ctx context.Context, p IncidentPolicy) error
	DeletePolicy(ctx context.Context, tenant string, cross bool, id string) (bool, error)

	// RCA object ↔ ticket links (the dedupe anchor)
	GetLink(ctx context.Context, tenant string, cross bool, corrID, system string) (Link, bool, error)
	PutLink(ctx context.Context, l Link) error
	// ListLinksForTenant returns the caller-visible ticket links, most recently
	// updated first, capped at limit (bounded read — the notified-via join in the
	// RCA candidate list only needs the recent working set).
	// ListLinksForTenant returns ONE page plus the true total. F-67: this took a
	// hardcoded 1000 and dropped everything past it SILENTLY — and a link the
	// caller never received reads as {"state":"not_created"}, so crossing the
	// cliff flips the oldest RCAs' badge from a real ServiceNow ticket to "no
	// ticket filed" and operators file duplicates against incidents that already
	// have them. Returning the total lets a caller SEE that it holds a partial
	// set; ListLinksForCorr avoids the question entirely for detail views.
	ListLinksForTenant(ctx context.Context, tenant string, cross bool, limit, offset int) ([]Link, int, error)
	// ListLinksForCorr returns every link for ONE correlation object — an exact
	// lookup with no cliff, for the detail surfaces that must never guess.
	ListLinksForCorr(ctx context.Context, tenant string, cross bool, corrID string) ([]Link, error)
	// ListSyncableLinks returns the live, externally-filed links the inbound state
	// syncer should poll (a real sys_id, non-terminal status, touched since `since`).
	// Runs at platform scope (the syncer spans all tenants; each row carries its
	// tenant_id) — like ClaimDueOutbox.
	ListSyncableLinks(ctx context.Context, since time.Time) ([]Link, error)

	// outbox + audit
	// EnqueueOutbox inserts one action, deduped by idempotency_key. enqueued
	// reports whether a row was actually created (or a dead_letter row REVIVED
	// to pending — M10: dead-lettering must never make a create permanently
	// un-retryable); false means an equivalent live row already exists.
	EnqueueOutbox(ctx context.Context, item OutboxItem) (enqueued bool, err error)
	// ListOutbox returns ONE page plus the true total. F-66: this had no LIMIT
	// in the SQL at all and both tables are append-only, so the endpoint served
	// a 22 MB response that grew forever and any infrastructure:read user could
	// loop into a self-DoS while holding one of the pool's 10 PG connections.
	ListOutbox(ctx context.Context, tenant string, cross bool, limit, offset int) ([]OutboxItem, int, error)
	// ClaimDueOutbox atomically leases up to n due items (status pending/retrying
	// AND next_retry_at <= now) for the worker, advancing next_retry_at by lease so
	// a concurrent/abandoned claim re-runs only after the lease expires. Runs at
	// platform scope (the worker spans all tenants; each row carries its tenant_id).
	ClaimDueOutbox(ctx context.Context, workerID string, n int, lease time.Duration) ([]OutboxItem, error)
	// FinishOutbox writes a claimed item's terminal/next state back (status,
	// retry_count, next_retry_at, last_error), keyed by (tenant_id, id).
	FinishOutbox(ctx context.Context, item OutboxItem) error
	AppendAudit(ctx context.Context, e AuditEntry) error
	// ListAudit returns ONE page plus the true total (F-66, as ListOutbox).
	ListAudit(ctx context.Context, tenant string, cross bool, corrID string, limit, offset int) ([]AuditEntry, int, error)
}

// scopeVisible reports whether a (tenant, cross) principal may see a row owned
// by rowTenant. The single rule both in-mem reads and writes use.
func scopeVisible(tenant string, cross bool, rowTenant string) bool {
	return cross || normTenant(tenant) == normTenant(rowTenant)
}

// syncableLink reports whether the inbound state syncer should poll a link: it must
// be an externally-filed ticket (a real sys_id), in a non-terminal status (closed/
// failed/pending are skipped), and touched since `since` (bounds the poll set). A
// zero `since` includes everything (used by the in-memory store in tests).
func syncableLink(l Link, since time.Time) bool {
	if l.SysID == "" {
		return false
	}
	switch l.Status {
	case "open", "updated", "resolved":
	default:
		return false
	}
	if since.IsZero() {
		return true
	}
	rec := l.CreatedAt
	if l.UpdatedAt.After(rec) {
		rec = l.UpdatedAt
	}
	if l.LastSyncedAt != nil && l.LastSyncedAt.After(rec) {
		rec = *l.LastSyncedAt
	}
	return rec.IsZero() || !rec.Before(since)
}

// ── in-memory backend ────────────────────────────────────────────────────────

// memTicketAuditMax bounds the in-memory ticketing audit trail (F-33), matching
// the auditMaxEvents ring the app audit store already uses.
const memTicketAuditMax = 5000

type MemStore struct {
	mu       sync.RWMutex
	policies map[string]IncidentPolicy // key: tenant\x00id
	links    map[string]Link           // key: tenant\x00corr\x00system
	outbox   map[string]OutboxItem     // key: tenant\x00id
	audit    []AuditEntry
}

func NewMemStore() *MemStore {
	return &MemStore{
		policies: map[string]IncidentPolicy{},
		links:    map[string]Link{},
		outbox:   map[string]OutboxItem{},
	}
}

func memKey(parts ...string) string {
	for i, p := range parts {
		parts[i] = normTenant(p)
	}
	return joinNUL(parts)
}

func joinNUL(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "\x00"
		}
		out += p
	}
	return out
}

func (m *MemStore) ListPolicies(_ context.Context, tenant string, cross bool) ([]IncidentPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []IncidentPolicy
	for _, p := range m.policies {
		if scopeVisible(tenant, cross, p.TenantID) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *MemStore) GetPolicy(_ context.Context, tenant string, cross bool, id string) (IncidentPolicy, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// A scoped caller can only ever address its own key; a cross caller may match
	// any tenant, so scan when cross.
	if !cross {
		p, ok := m.policies[memKey(tenant, id)]
		return p, ok, nil
	}
	for _, p := range m.policies {
		if p.ID == id {
			return p, true, nil
		}
	}
	return IncidentPolicy{}, false, nil
}

func (m *MemStore) PutPolicy(_ context.Context, p IncidentPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Same invariant the pg backend enforces via the incident_policies_one_enabled
	// partial unique index: at most one enabled policy per (tenant, system).
	// Checked under the store lock, so concurrent enables cannot both pass.
	if p.Enabled {
		for _, ex := range m.policies {
			if ex.Enabled && ex.ID != p.ID && ex.TenantID == p.TenantID &&
				orDefault(ex.ExternalSystem, "servicenow") == orDefault(p.ExternalSystem, "servicenow") {
				return ErrPolicyConflict
			}
		}
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.UpdatedAt = time.Now().UTC()
	m.policies[memKey(p.TenantID, p.ID)] = p
	return nil
}

func (m *MemStore) DeletePolicy(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memKey(tenant, id)
	if cross {
		for k, p := range m.policies {
			if p.ID == id {
				key = k
				break
			}
		}
	}
	if _, ok := m.policies[key]; !ok {
		return false, nil
	}
	delete(m.policies, key)
	return true, nil
}

func (m *MemStore) GetLink(_ context.Context, tenant string, cross bool, corrID, system string) (Link, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !cross {
		l, ok := m.links[memKey(tenant, corrID, system)]
		return l, ok, nil
	}
	for _, l := range m.links {
		if l.CorrObjectID == corrID && l.ExternalSystem == system {
			return l, true, nil
		}
	}
	return Link{}, false, nil
}

func (m *MemStore) PutLink(_ context.Context, l Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	l.UpdatedAt = time.Now().UTC()
	m.links[memKey(l.TenantID, l.CorrObjectID, l.ExternalSystem)] = l
	return nil
}

func (m *MemStore) ListLinksForTenant(_ context.Context, tenant string, cross bool, limit, offset int) ([]Link, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit, offset = boundPage(limit, offset, LinksDefaultPage)
	var out []Link
	for _, l := range m.links {
		if scopeVisible(tenant, cross, l.TenantID) {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].UpdatedAt.After(out[j].UpdatedAt)
		}
		if out[i].CorrObjectID != out[j].CorrObjectID {
			return out[i].CorrObjectID < out[j].CorrObjectID
		}
		return out[i].ExternalSystem < out[j].ExternalSystem
	})
	total := len(out)
	return pageSlice(out, limit, offset), total, nil
}

func (m *MemStore) ListLinksForCorr(_ context.Context, tenant string, cross bool, corrID string) ([]Link, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Link
	for _, l := range m.links {
		if scopeVisible(tenant, cross, l.TenantID) && l.CorrObjectID == corrID {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExternalSystem < out[j].ExternalSystem })
	return out, nil
}
func (m *MemStore) ListSyncableLinks(_ context.Context, since time.Time) ([]Link, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Link
	for _, l := range m.links {
		if syncableLink(l, since) {
			out = append(out, l)
		}
	}
	return out, nil
}

func (m *MemStore) EnqueueOutbox(_ context.Context, item OutboxItem) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Idempotency: an item with the same idempotency_key is a no-op
	// (at-most-once) — UNLESS the existing row is dead_letter (M10): a
	// dead-lettered action already gave up, so a fresh enqueue is the
	// operator's/policy's explicit retry and must revive it, not vanish.
	for k, ex := range m.outbox {
		if ex.IdempotencyKey == item.IdempotencyKey {
			if ex.Status != "dead_letter" {
				return false, nil
			}
			delete(m.outbox, k) // revive: replace the dead row with the fresh pending one
			break
		}
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	item.UpdatedAt = time.Now().UTC()
	m.outbox[memKey(item.TenantID, item.ID)] = item
	return true, nil
}

func (m *MemStore) ListOutbox(_ context.Context, tenant string, cross bool, limit, offset int) ([]OutboxItem, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit, offset = boundPage(limit, offset, OutboxDefaultPage)
	var out []OutboxItem
	for _, it := range m.outbox {
		if scopeVisible(tenant, cross, it.TenantID) {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	total := len(out)
	return pageSlice(out, limit, offset), total, nil
}
func (m *MemStore) ClaimDueOutbox(_ context.Context, _ string, n int, lease time.Duration) ([]OutboxItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var due []OutboxItem
	for _, it := range m.outbox {
		if (it.Status == "pending" || it.Status == "retrying") && !it.NextRetryAt.After(now) {
			due = append(due, it)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].NextRetryAt.Before(due[j].NextRetryAt) })
	if n > 0 && len(due) > n {
		due = due[:n]
	}
	for i := range due {
		due[i].Status = "retrying"
		due[i].NextRetryAt = now.Add(lease)
		due[i].UpdatedAt = now
		m.outbox[memKey(due[i].TenantID, due[i].ID)] = due[i]
	}
	return due, nil
}

func (m *MemStore) FinishOutbox(_ context.Context, item OutboxItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memKey(item.TenantID, item.ID)
	cur, ok := m.outbox[key]
	if !ok {
		return nil
	}
	cur.Status = item.Status
	cur.RetryCount = item.RetryCount
	cur.NextRetryAt = item.NextRetryAt
	cur.LastError = item.LastError
	cur.UpdatedAt = time.Now().UTC()
	m.outbox[key] = cur
	return nil
}

func (m *MemStore) AppendAudit(_ context.Context, e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	m.audit = append(m.audit, e)
	// F-33: this slice was append-only for the life of the process. Every
	// ticketing action on every tenant accumulated in the API's heap with no
	// cap, no TTL and no trim — while audit.go, a sibling store with the same
	// job, correctly ring-buffers at 5,000. This is the in-memory backend (the
	// Postgres backend is the durable one), so the honest bound is the same
	// ring: keep the most recent entries and drop the oldest.
	if len(m.audit) > memTicketAuditMax {
		m.audit = append([]AuditEntry(nil), m.audit[len(m.audit)-memTicketAuditMax:]...)
	}
	return nil
}

func (m *MemStore) ListAudit(_ context.Context, tenant string, cross bool, corrID string, limit, offset int) ([]AuditEntry, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit, offset = boundPage(limit, offset, AuditDefaultPage)
	var out []AuditEntry
	for _, e := range m.audit {
		if !scopeVisible(tenant, cross, e.TenantID) {
			continue
		}
		if corrID != "" && e.CorrObjectID != corrID {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	total := len(out)
	return pageSlice(out, limit, offset), total, nil
}

// ── Postgres backend (RLS-scoped via withTenant) ─────────────────────────────

// SeedPolicyForTest inserts a policy directly into the in-memory map,
// bypassing PutPolicy's single-enabled-policy conflict rule — for tests that
// need pre-existing/drifted state. TEST SUPPORT ONLY.
func (m *MemStore) SeedPolicyForTest(p IncidentPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[memKey(normTenant(p.TenantID), p.ID)] = p
}

// normTenant mirrors the integrator's tenant-id normalization (duplicated per
// the no-shared-utils rule).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// DB is the injected relational seam: run fn inside a transaction whose
// row-level security is scoped to tenant (or unscoped for a cross-tenant
// principal). Implemented by package main's rlsPG adapter (the portintel.DB
// idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewPGStore builds the FORCE-RLS pg repository over the injected seam.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

type PGStore struct {
	db DB
}

func (s *PGStore) ListPolicies(ctx context.Context, tenant string, cross bool) ([]IncidentPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []IncidentPolicy
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+policyCols+` FROM incident_policies ORDER BY tenant_id, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPolicy(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PGStore) GetPolicy(ctx context.Context, tenant string, cross bool, id string) (IncidentPolicy, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var p IncidentPolicy
	found := false
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+policyCols+` FROM incident_policies WHERE id=$1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if p, err = scanPolicy(rows); err != nil {
				return err
			}
			found = true
		}
		return rows.Err()
	})
	return p, found, err
}

func (s *PGStore) PutPolicy(ctx context.Context, p IncidentPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	filters, _ := json.Marshal(orEmptyMap(p.Filters))
	return s.db.WithTenant(ctx, p.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO incident_policies (tenant_id, id, name, external_system, enabled, min_verdict,
    require_customer_facing, allow_probe_only, allow_internal_monitoring, suspected_requires_critical,
    require_persistence_seconds, suppress_flapping_seconds, assignment_group, default_impact, default_urgency,
    impact_confirmed_critical, urgency_confirmed_critical, impact_confirmed, urgency_confirmed,
    allow_validation_scenarios, filters)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
ON CONFLICT (tenant_id, id) DO UPDATE SET
    name=EXCLUDED.name, external_system=EXCLUDED.external_system, enabled=EXCLUDED.enabled,
    min_verdict=EXCLUDED.min_verdict, require_customer_facing=EXCLUDED.require_customer_facing,
    allow_probe_only=EXCLUDED.allow_probe_only, allow_internal_monitoring=EXCLUDED.allow_internal_monitoring,
    suspected_requires_critical=EXCLUDED.suspected_requires_critical,
    require_persistence_seconds=EXCLUDED.require_persistence_seconds,
    suppress_flapping_seconds=EXCLUDED.suppress_flapping_seconds, assignment_group=EXCLUDED.assignment_group,
    default_impact=EXCLUDED.default_impact, default_urgency=EXCLUDED.default_urgency,
    impact_confirmed_critical=EXCLUDED.impact_confirmed_critical,
    urgency_confirmed_critical=EXCLUDED.urgency_confirmed_critical,
    impact_confirmed=EXCLUDED.impact_confirmed, urgency_confirmed=EXCLUDED.urgency_confirmed,
    allow_validation_scenarios=EXCLUDED.allow_validation_scenarios,
    filters=EXCLUDED.filters, updated_at=now()`,
			normTenant(p.TenantID), p.ID, p.Name, orDefault(p.ExternalSystem, "servicenow"), p.Enabled,
			orDefault(p.MinVerdict, "suspected"), p.RequireCustomerFacing, p.AllowProbeOnly,
			p.AllowInternalMonitoring, p.SuspectedRequiresCritical, p.RequirePersistenceSeconds,
			p.SuppressFlappingSeconds, p.AssignmentGroup, p.DefaultImpact, p.DefaultUrgency,
			p.ImpactConfirmedCritical, p.UrgencyConfirmedCritical, p.ImpactConfirmed, p.UrgencyConfirmed,
			p.AllowValidationScenarios, filters)
		// 23505 on incident_policies_one_enabled = the one-enabled invariant
		// (migration 0021) — surface the typed conflict, not a raw driver error.
		if err != nil && strings.Contains(err.Error(), "incident_policies_one_enabled") {
			return ErrPolicyConflict
		}
		return err
	})
}

func (s *PGStore) DeletePolicy(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var n int64
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM incident_policies WHERE id=$1`, id)
		if err != nil {
			return err
		}
		n = ct.RowsAffected()
		return nil
	})
	return n > 0, err
}

func (s *PGStore) GetLink(ctx context.Context, tenant string, cross bool, corrID, system string) (Link, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var l Link
	found := false
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+linkCols+` FROM correlix_ticket_links
            WHERE corr_object_id=$1 AND external_system=$2`, corrID, system)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if l, err = scanLink(rows); err != nil {
				return err
			}
			found = true
		}
		return rows.Err()
	})
	return l, found, err
}

func (s *PGStore) PutLink(ctx context.Context, l Link) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, l.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO correlix_ticket_links (tenant_id, corr_object_id, external_system, instance_url, ticket_number,
    sys_id, dedupe_key, status, last_verdict, last_confidence, last_payload_hash, last_synced_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (tenant_id, corr_object_id, external_system) DO UPDATE SET
    instance_url=EXCLUDED.instance_url, ticket_number=EXCLUDED.ticket_number, sys_id=EXCLUDED.sys_id,
    dedupe_key=EXCLUDED.dedupe_key, status=EXCLUDED.status, last_verdict=EXCLUDED.last_verdict,
    last_confidence=EXCLUDED.last_confidence, last_payload_hash=EXCLUDED.last_payload_hash,
    last_synced_at=EXCLUDED.last_synced_at, updated_at=now()`,
			normTenant(l.TenantID), l.CorrObjectID, orDefault(l.ExternalSystem, "servicenow"), l.InstanceURL,
			l.TicketNumber, l.SysID, l.DedupeKey, orDefault(l.Status, "pending"), l.LastVerdict,
			l.LastConfidence, l.LastPayloadHash, l.LastSyncedAt)
		return err
	})
}

// listPagedRLS is the count-then-page read ListLinksForTenant and ListOutbox
// share (#147 T4). The COUNT runs under the same RLS-scoped transaction as the
// page query, so the total is the caller's total — never a cross-tenant row
// count. pageSQL must take LIMIT $1 OFFSET $2.
func listPagedRLS[T any](ctx context.Context, s *PGStore, tenant string, cross bool,
	limit, offset, defPage int, countSQL, pageSQL string, scan func(pgx.Rows) (T, error)) ([]T, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	limit, offset = boundPage(limit, offset, defPage)
	var out []T
	var total int
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, countSQL).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, pageSQL, limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, total, err
}

func (s *PGStore) ListLinksForTenant(ctx context.Context, tenant string, cross bool, limit, offset int) ([]Link, int, error) {
	return listPagedRLS(ctx, s, tenant, cross, limit, offset, LinksDefaultPage,
		`SELECT count(*) FROM correlix_ticket_links`,
		`SELECT `+linkCols+` FROM correlix_ticket_links
            ORDER BY updated_at DESC, corr_object_id, external_system LIMIT $1 OFFSET $2`, scanLink)
}

// ListLinksForCorr is the exact per-object lookup that removes F-67's guess:
// a detail surface asks for the links of the object it is rendering instead of
// hoping that object appeared in a truncated top-N page.
func (s *PGStore) ListLinksForCorr(ctx context.Context, tenant string, cross bool, corrID string) ([]Link, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []Link
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+linkCols+` FROM correlix_ticket_links
            WHERE corr_object_id=$1 ORDER BY external_system`, corrID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			l, err := scanLink(rows)
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}
func (s *PGStore) ListSyncableLinks(ctx context.Context, since time.Time) ([]Link, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out []Link
	// Platform scope (cross=true): the syncer spans all tenants; each row carries
	// its tenant_id, used to scope every downstream write. Mirrors ClaimDueOutbox.
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+linkCols+` FROM correlix_ticket_links
            WHERE sys_id <> '' AND status IN ('open','updated','resolved')
              AND COALESCE(last_synced_at, updated_at, created_at) >= $1
            ORDER BY COALESCE(last_synced_at, updated_at, created_at) ASC
            LIMIT 1000`, since)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			l, err := scanLink(rows)
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PGStore) EnqueueOutbox(ctx context.Context, item OutboxItem) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	payload, _ := json.Marshal(orEmptyMap(item.Payload))
	maxRetries := item.MaxRetries
	if maxRetries == 0 {
		maxRetries = 8
	}
	next := item.NextRetryAt
	if next.IsZero() {
		next = time.Now().UTC()
	}
	var enqueued bool
	err := s.db.WithTenant(ctx, item.TenantID, false, func(tx pgx.Tx) error {
		// ON CONFLICT on the unique idempotency_key makes enqueue at-most-once
		// — except a dead_letter row, which the conflict REVIVES to a fresh
		// pending attempt (M10: dead-lettering must never be permanent for a
		// re-requested action). The DO UPDATE ... WHERE keeps live rows
		// (pending/retrying/sent) untouched: those report enqueued=false.
		tag, err := tx.Exec(ctx, `
INSERT INTO ticket_outbox (tenant_id, id, corr_object_id, external_system, action, idempotency_key,
    payload, status, retry_count, max_retries, next_retry_at, last_error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (idempotency_key) DO UPDATE SET
    payload = EXCLUDED.payload, status = EXCLUDED.status,
    retry_count = 0, next_retry_at = EXCLUDED.next_retry_at,
    last_error = '', updated_at = now()
  WHERE ticket_outbox.status = 'dead_letter'`,
			normTenant(item.TenantID), item.ID, item.CorrObjectID, orDefault(item.ExternalSystem, "servicenow"),
			item.Action, item.IdempotencyKey, payload, orDefault(item.Status, "pending"),
			item.RetryCount, maxRetries, next, item.LastError)
		if err != nil {
			return err
		}
		enqueued = tag.RowsAffected() == 1
		return nil
	})
	return enqueued, err
}

func (s *PGStore) ListOutbox(ctx context.Context, tenant string, cross bool, limit, offset int) ([]OutboxItem, int, error) {
	return listPagedRLS(ctx, s, tenant, cross, limit, offset, OutboxDefaultPage,
		`SELECT count(*) FROM ticket_outbox`,
		`SELECT `+outboxCols+` FROM ticket_outbox ORDER BY created_at LIMIT $1 OFFSET $2`, scanOutbox)
}

// claimOutboxSQL leases due rows with FOR UPDATE SKIP LOCKED (the report-queue
// pattern). The CTE selects id AS claim_id because a bare `id` in RETURNING (part
// of the shared outboxCols list) would be ambiguous between the two relations.
// Renaming the CTE column keeps `id` resolving unambiguously to o.id.
const claimOutboxSQL = `
WITH claimable AS (
    SELECT id AS claim_id FROM ticket_outbox
     WHERE status IN ('pending','retrying') AND next_retry_at <= now()
     ORDER BY next_retry_at
     FOR UPDATE SKIP LOCKED
     LIMIT $1)
UPDATE ticket_outbox o
   SET status='retrying', next_retry_at = now() + make_interval(secs => $2), updated_at = now()
  FROM claimable c
 WHERE o.id = c.claim_id
RETURNING ` + outboxCols

func (s *PGStore) ClaimDueOutbox(ctx context.Context, _ string, n int, lease time.Duration) ([]OutboxItem, error) {
	if n <= 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out []OutboxItem
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, claimOutboxSQL, n, lease.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			it, err := scanOutbox(rows)
			if err != nil {
				return err
			}
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PGStore) FinishOutbox(ctx context.Context, item OutboxItem) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, item.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
UPDATE ticket_outbox SET status=$3, retry_count=$4, next_retry_at=$5, last_error=$6, updated_at=now()
 WHERE tenant_id=$1 AND id=$2`,
			normTenant(item.TenantID), item.ID, item.Status, item.RetryCount, item.NextRetryAt, item.LastError)
		return err
	})
}

func (s *PGStore) AppendAudit(ctx context.Context, e AuditEntry) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.WithTenant(ctx, e.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO ticket_audit_log (tenant_id, id, corr_object_id, external_system, action, actor,
    old_status, new_status, payload_hash, result, error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			normTenant(e.TenantID), e.ID, e.CorrObjectID, orDefault(e.ExternalSystem, "servicenow"),
			e.Action, orDefault(e.Actor, "system"), e.OldStatus, e.NewStatus, e.PayloadHash, e.Result, e.Error)
		return err
	})
}

func (s *PGStore) ListAudit(ctx context.Context, tenant string, cross bool, corrID string, limit, offset int) ([]AuditEntry, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	limit, offset = boundPage(limit, offset, AuditDefaultPage)
	var out []AuditEntry
	var total int
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		countQ := `SELECT count(*) FROM ticket_audit_log`
		q := `SELECT ` + auditCols + ` FROM ticket_audit_log`
		args := []any{}
		if corrID != "" {
			countQ += ` WHERE corr_object_id=$1`
			q += ` WHERE corr_object_id=$1`
			args = append(args, corrID)
		}
		if err := tx.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
			return err
		}
		q += ` ORDER BY at LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)
		args = append(args, limit, offset)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e, err := scanAudit(rows)
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, total, err
}

const policyCols = `tenant_id, id, name, external_system, enabled, min_verdict, require_customer_facing,
    allow_probe_only, allow_internal_monitoring, suspected_requires_critical, require_persistence_seconds,
    suppress_flapping_seconds, assignment_group, default_impact, default_urgency,
    impact_confirmed_critical, urgency_confirmed_critical, impact_confirmed, urgency_confirmed,
    allow_validation_scenarios, filters, created_at, updated_at`

func scanPolicy(rows pgx.Rows) (IncidentPolicy, error) {
	var p IncidentPolicy
	var filters []byte
	if err := rows.Scan(&p.TenantID, &p.ID, &p.Name, &p.ExternalSystem, &p.Enabled, &p.MinVerdict,
		&p.RequireCustomerFacing, &p.AllowProbeOnly, &p.AllowInternalMonitoring, &p.SuspectedRequiresCritical,
		&p.RequirePersistenceSeconds, &p.SuppressFlappingSeconds, &p.AssignmentGroup, &p.DefaultImpact,
		&p.DefaultUrgency, &p.ImpactConfirmedCritical, &p.UrgencyConfirmedCritical, &p.ImpactConfirmed,
		&p.UrgencyConfirmed, &p.AllowValidationScenarios, &filters, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	if len(filters) > 0 {
		_ = json.Unmarshal(filters, &p.Filters) // best-effort: engine-authored JSON; malformed decodes to zero value
	}
	return p, nil
}

// Page bounds for the append-only ticketing tables (F-66/F-67). Defaults are
// what a UI actually renders; the max is what one caller may hold in memory and
// in a PG connection at once.
const (
	LinksDefaultPage  = 500
	OutboxDefaultPage = 200
	AuditDefaultPage  = 200 // exported: the AI datasource pages the audit trail with the same bound
	MaxPage           = 2000
)

// pageSlice applies limit/offset to an already-sorted slice. Offsets past the
// end yield an EMPTY page, never a wrapped or clamped one — a caller paging off
// the end must see "no more rows", not the last page again.
func pageSlice[T any](rows []T, limit, offset int) []T {
	if offset >= len(rows) {
		return nil
	}
	end := offset + limit
	if end > len(rows) {
		end = len(rows)
	}
	return rows[offset:end]
}

// boundPage clamps a requested page. Callers parse limit/offset with intQuery,
// which already fails closed on out-of-range input; this is the storage-layer
// backstop so no internal caller can accidentally ask for the whole table.
func boundPage(limit, offset, def int) (int, int) {
	if limit <= 0 {
		limit = def
	}
	if limit > MaxPage {
		limit = MaxPage
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

const linkCols = `tenant_id, corr_object_id, external_system, instance_url, ticket_number, sys_id, dedupe_key,
    status, last_verdict, last_confidence, last_payload_hash, last_synced_at, created_at, updated_at`

func scanLink(rows pgx.Rows) (Link, error) {
	var l Link
	if err := rows.Scan(&l.TenantID, &l.CorrObjectID, &l.ExternalSystem, &l.InstanceURL, &l.TicketNumber,
		&l.SysID, &l.DedupeKey, &l.Status, &l.LastVerdict, &l.LastConfidence, &l.LastPayloadHash,
		&l.LastSyncedAt, &l.CreatedAt, &l.UpdatedAt); err != nil {
		return l, err
	}
	return l, nil
}

const outboxCols = `tenant_id, id, corr_object_id, external_system, action, idempotency_key, payload, status,
    retry_count, max_retries, next_retry_at, last_error, created_at, updated_at`

func scanOutbox(rows pgx.Rows) (OutboxItem, error) {
	var it OutboxItem
	var payload []byte
	if err := rows.Scan(&it.TenantID, &it.ID, &it.CorrObjectID, &it.ExternalSystem, &it.Action,
		&it.IdempotencyKey, &payload, &it.Status, &it.RetryCount, &it.MaxRetries, &it.NextRetryAt,
		&it.LastError, &it.CreatedAt, &it.UpdatedAt); err != nil {
		return it, err
	}
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &it.Payload) // best-effort: engine-authored JSON; malformed decodes to zero value
	}
	return it, nil
}

const auditCols = `tenant_id, id, corr_object_id, external_system, action, actor, old_status, new_status,
    payload_hash, result, error, at`

func scanAudit(rows pgx.Rows) (AuditEntry, error) {
	var e AuditEntry
	if err := rows.Scan(&e.TenantID, &e.ID, &e.CorrObjectID, &e.ExternalSystem, &e.Action, &e.Actor,
		&e.OldStatus, &e.NewStatus, &e.PayloadHash, &e.Result, &e.Error, &e.At); err != nil {
		return e, err
	}
	return e, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

var _ Store = (*MemStore)(nil)
var _ Store = (*PGStore)(nil)
