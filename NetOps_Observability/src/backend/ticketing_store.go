package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
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

// errPolicyConflict is returned by PutPolicy when saving an ENABLED policy
// while another policy is already enabled for the same (tenant, external
// system). The HTTP layer pre-checks and 409s with the conflicting policy's
// name; this store-level invariant closes the check-then-write race (and any
// non-API write path). In Postgres it is enforced transactionally by the
// incident_policies_one_enabled partial unique index (migration 0021).
var errPolicyConflict = errors.New("another policy is already enabled for this tenant and external system")

type ticketingStore interface {
	// incident policies
	ListPolicies(ctx context.Context, tenant string, cross bool) ([]incidentPolicy, error)
	GetPolicy(ctx context.Context, tenant string, cross bool, id string) (incidentPolicy, bool, error)
	// PutPolicy upserts one policy; returns errPolicyConflict when enabling it
	// would violate the one-enabled-per-(tenant, external_system) invariant.
	PutPolicy(ctx context.Context, p incidentPolicy) error
	DeletePolicy(ctx context.Context, tenant string, cross bool, id string) (bool, error)

	// RCA object ↔ ticket links (the dedupe anchor)
	GetLink(ctx context.Context, tenant string, cross bool, corrID, system string) (ticketLink, bool, error)
	PutLink(ctx context.Context, l ticketLink) error
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
	ListLinksForTenant(ctx context.Context, tenant string, cross bool, limit, offset int) ([]ticketLink, int, error)
	// ListLinksForCorr returns every link for ONE correlation object — an exact
	// lookup with no cliff, for the detail surfaces that must never guess.
	ListLinksForCorr(ctx context.Context, tenant string, cross bool, corrID string) ([]ticketLink, error)
	// ListSyncableLinks returns the live, externally-filed links the inbound state
	// syncer should poll (a real sys_id, non-terminal status, touched since `since`).
	// Runs at platform scope (the syncer spans all tenants; each row carries its
	// tenant_id) — like ClaimDueOutbox.
	ListSyncableLinks(ctx context.Context, since time.Time) ([]ticketLink, error)

	// outbox + audit
	EnqueueOutbox(ctx context.Context, item ticketOutboxItem) error
	// ListOutbox returns ONE page plus the true total. F-66: this had no LIMIT
	// in the SQL at all and both tables are append-only, so the endpoint served
	// a 22 MB response that grew forever and any infrastructure:read user could
	// loop into a self-DoS while holding one of the pool's 10 PG connections.
	ListOutbox(ctx context.Context, tenant string, cross bool, limit, offset int) ([]ticketOutboxItem, int, error)
	// ClaimDueOutbox atomically leases up to n due items (status pending/retrying
	// AND next_retry_at <= now) for the worker, advancing next_retry_at by lease so
	// a concurrent/abandoned claim re-runs only after the lease expires. Runs at
	// platform scope (the worker spans all tenants; each row carries its tenant_id).
	ClaimDueOutbox(ctx context.Context, workerID string, n int, lease time.Duration) ([]ticketOutboxItem, error)
	// FinishOutbox writes a claimed item's terminal/next state back (status,
	// retry_count, next_retry_at, last_error), keyed by (tenant_id, id).
	FinishOutbox(ctx context.Context, item ticketOutboxItem) error
	AppendAudit(ctx context.Context, e ticketAuditEntry) error
	// ListAudit returns ONE page plus the true total (F-66, as ListOutbox).
	ListAudit(ctx context.Context, tenant string, cross bool, corrID string, limit, offset int) ([]ticketAuditEntry, int, error)
}

// newTicketingStore picks the backend: an RLS-scoped pg repository under
// STORE_BACKEND=postgres, else an in-memory store. Always non-nil.
func newTicketingStore() ticketingStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgTicketingStore{db: ps.db}
	}
	return newMemTicketingStore()
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
func syncableLink(l ticketLink, since time.Time) bool {
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

type memTicketingStore struct {
	mu       sync.RWMutex
	policies map[string]incidentPolicy   // key: tenant\x00id
	links    map[string]ticketLink       // key: tenant\x00corr\x00system
	outbox   map[string]ticketOutboxItem // key: tenant\x00id
	audit    []ticketAuditEntry
}

func newMemTicketingStore() *memTicketingStore {
	return &memTicketingStore{
		policies: map[string]incidentPolicy{},
		links:    map[string]ticketLink{},
		outbox:   map[string]ticketOutboxItem{},
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

func (m *memTicketingStore) ListPolicies(_ context.Context, tenant string, cross bool) ([]incidentPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []incidentPolicy
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

func (m *memTicketingStore) GetPolicy(_ context.Context, tenant string, cross bool, id string) (incidentPolicy, bool, error) {
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
	return incidentPolicy{}, false, nil
}

func (m *memTicketingStore) PutPolicy(_ context.Context, p incidentPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Same invariant the pg backend enforces via the incident_policies_one_enabled
	// partial unique index: at most one enabled policy per (tenant, system).
	// Checked under the store lock, so concurrent enables cannot both pass.
	if p.Enabled {
		for _, ex := range m.policies {
			if ex.Enabled && ex.ID != p.ID && ex.TenantID == p.TenantID &&
				orDefault(ex.ExternalSystem, "servicenow") == orDefault(p.ExternalSystem, "servicenow") {
				return errPolicyConflict
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

func (m *memTicketingStore) DeletePolicy(_ context.Context, tenant string, cross bool, id string) (bool, error) {
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

func (m *memTicketingStore) GetLink(_ context.Context, tenant string, cross bool, corrID, system string) (ticketLink, bool, error) {
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
	return ticketLink{}, false, nil
}

func (m *memTicketingStore) PutLink(_ context.Context, l ticketLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	l.UpdatedAt = time.Now().UTC()
	m.links[memKey(l.TenantID, l.CorrObjectID, l.ExternalSystem)] = l
	return nil
}

func (m *memTicketingStore) ListLinksForTenant(_ context.Context, tenant string, cross bool, limit, offset int) ([]ticketLink, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit, offset = boundPage(limit, offset, ticketLinksDefaultPage)
	var out []ticketLink
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

func (m *memTicketingStore) ListLinksForCorr(_ context.Context, tenant string, cross bool, corrID string) ([]ticketLink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []ticketLink
	for _, l := range m.links {
		if scopeVisible(tenant, cross, l.TenantID) && l.CorrObjectID == corrID {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExternalSystem < out[j].ExternalSystem })
	return out, nil
}
func (m *memTicketingStore) ListSyncableLinks(_ context.Context, since time.Time) ([]ticketLink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []ticketLink
	for _, l := range m.links {
		if syncableLink(l, since) {
			out = append(out, l)
		}
	}
	return out, nil
}

func (m *memTicketingStore) EnqueueOutbox(_ context.Context, item ticketOutboxItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Idempotency: an item with the same idempotency_key is a no-op (at-most-once).
	for _, ex := range m.outbox {
		if ex.IdempotencyKey == item.IdempotencyKey {
			return nil
		}
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	item.UpdatedAt = time.Now().UTC()
	m.outbox[memKey(item.TenantID, item.ID)] = item
	return nil
}

func (m *memTicketingStore) ListOutbox(_ context.Context, tenant string, cross bool, limit, offset int) ([]ticketOutboxItem, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit, offset = boundPage(limit, offset, ticketOutboxDefaultPage)
	var out []ticketOutboxItem
	for _, it := range m.outbox {
		if scopeVisible(tenant, cross, it.TenantID) {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	total := len(out)
	return pageSlice(out, limit, offset), total, nil
}
func (m *memTicketingStore) ClaimDueOutbox(_ context.Context, _ string, n int, lease time.Duration) ([]ticketOutboxItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var due []ticketOutboxItem
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

func (m *memTicketingStore) FinishOutbox(_ context.Context, item ticketOutboxItem) error {
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

func (m *memTicketingStore) AppendAudit(_ context.Context, e ticketAuditEntry) error {
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
		m.audit = append([]ticketAuditEntry(nil), m.audit[len(m.audit)-memTicketAuditMax:]...)
	}
	return nil
}

func (m *memTicketingStore) ListAudit(_ context.Context, tenant string, cross bool, corrID string, limit, offset int) ([]ticketAuditEntry, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit, offset = boundPage(limit, offset, ticketAuditDefaultPage)
	var out []ticketAuditEntry
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

type pgTicketingStore struct {
	db *pgDB
}

func (s *pgTicketingStore) ListPolicies(ctx context.Context, tenant string, cross bool) ([]incidentPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []incidentPolicy
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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

func (s *pgTicketingStore) GetPolicy(ctx context.Context, tenant string, cross bool, id string) (incidentPolicy, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var p incidentPolicy
	found := false
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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

func (s *pgTicketingStore) PutPolicy(ctx context.Context, p incidentPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	filters, _ := json.Marshal(orEmptyMap(p.Filters))
	return s.db.withTenant(ctx, p.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO incident_policies (tenant_id, id, name, external_system, enabled, min_verdict,
    require_customer_facing, allow_probe_only, allow_internal_monitoring, suspected_requires_critical,
    require_persistence_seconds, suppress_flapping_seconds, assignment_group, default_impact, default_urgency,
    impact_confirmed_critical, urgency_confirmed_critical, impact_confirmed, urgency_confirmed, filters)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
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
    filters=EXCLUDED.filters, updated_at=now()`,
			normTenant(p.TenantID), p.ID, p.Name, orDefault(p.ExternalSystem, "servicenow"), p.Enabled,
			orDefault(p.MinVerdict, "suspected"), p.RequireCustomerFacing, p.AllowProbeOnly,
			p.AllowInternalMonitoring, p.SuspectedRequiresCritical, p.RequirePersistenceSeconds,
			p.SuppressFlappingSeconds, p.AssignmentGroup, p.DefaultImpact, p.DefaultUrgency,
			p.ImpactConfirmedCritical, p.UrgencyConfirmedCritical, p.ImpactConfirmed, p.UrgencyConfirmed, filters)
		// 23505 on incident_policies_one_enabled = the one-enabled invariant
		// (migration 0021) — surface the typed conflict, not a raw driver error.
		if err != nil && strings.Contains(err.Error(), "incident_policies_one_enabled") {
			return errPolicyConflict
		}
		return err
	})
}

func (s *pgTicketingStore) DeletePolicy(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var n int64
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM incident_policies WHERE id=$1`, id)
		if err != nil {
			return err
		}
		n = ct.RowsAffected()
		return nil
	})
	return n > 0, err
}

func (s *pgTicketingStore) GetLink(ctx context.Context, tenant string, cross bool, corrID, system string) (ticketLink, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var l ticketLink
	found := false
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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

func (s *pgTicketingStore) PutLink(ctx context.Context, l ticketLink) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.withTenant(ctx, l.TenantID, false, func(tx pgx.Tx) error {
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

func (s *pgTicketingStore) ListLinksForTenant(ctx context.Context, tenant string, cross bool, limit, offset int) ([]ticketLink, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	limit, offset = boundPage(limit, offset, ticketLinksDefaultPage)
	var out []ticketLink
	var total int
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// The COUNT runs under the same RLS-scoped transaction, so the total is
		// the caller's total — never a cross-tenant row count.
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM correlix_ticket_links`).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+linkCols+` FROM correlix_ticket_links
            ORDER BY updated_at DESC, corr_object_id, external_system LIMIT $1 OFFSET $2`, limit, offset)
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
	return out, total, err
}

// ListLinksForCorr is the exact per-object lookup that removes F-67's guess:
// a detail surface asks for the links of the object it is rendering instead of
// hoping that object appeared in a truncated top-N page.
func (s *pgTicketingStore) ListLinksForCorr(ctx context.Context, tenant string, cross bool, corrID string) ([]ticketLink, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []ticketLink
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
func (s *pgTicketingStore) ListSyncableLinks(ctx context.Context, since time.Time) ([]ticketLink, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out []ticketLink
	// Platform scope (cross=true): the syncer spans all tenants; each row carries
	// its tenant_id, used to scope every downstream write. Mirrors ClaimDueOutbox.
	err := s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
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

func (s *pgTicketingStore) EnqueueOutbox(ctx context.Context, item ticketOutboxItem) error {
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
	return s.db.withTenant(ctx, item.TenantID, false, func(tx pgx.Tx) error {
		// ON CONFLICT on the unique idempotency_key makes enqueue at-most-once.
		_, err := tx.Exec(ctx, `
INSERT INTO ticket_outbox (tenant_id, id, corr_object_id, external_system, action, idempotency_key,
    payload, status, retry_count, max_retries, next_retry_at, last_error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (idempotency_key) DO NOTHING`,
			normTenant(item.TenantID), item.ID, item.CorrObjectID, orDefault(item.ExternalSystem, "servicenow"),
			item.Action, item.IdempotencyKey, payload, orDefault(item.Status, "pending"),
			item.RetryCount, maxRetries, next, item.LastError)
		return err
	})
}

func (s *pgTicketingStore) ListOutbox(ctx context.Context, tenant string, cross bool, limit, offset int) ([]ticketOutboxItem, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	limit, offset = boundPage(limit, offset, ticketOutboxDefaultPage)
	var out []ticketOutboxItem
	var total int
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ticket_outbox`).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+outboxCols+` FROM ticket_outbox ORDER BY created_at LIMIT $1 OFFSET $2`, limit, offset)
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
	return out, total, err
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

func (s *pgTicketingStore) ClaimDueOutbox(ctx context.Context, _ string, n int, lease time.Duration) ([]ticketOutboxItem, error) {
	if n <= 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out []ticketOutboxItem
	err := s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
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

func (s *pgTicketingStore) FinishOutbox(ctx context.Context, item ticketOutboxItem) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.withTenant(ctx, item.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
UPDATE ticket_outbox SET status=$3, retry_count=$4, next_retry_at=$5, last_error=$6, updated_at=now()
 WHERE tenant_id=$1 AND id=$2`,
			normTenant(item.TenantID), item.ID, item.Status, item.RetryCount, item.NextRetryAt, item.LastError)
		return err
	})
}

func (s *pgTicketingStore) AppendAudit(ctx context.Context, e ticketAuditEntry) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.db.withTenant(ctx, e.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO ticket_audit_log (tenant_id, id, corr_object_id, external_system, action, actor,
    old_status, new_status, payload_hash, result, error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			normTenant(e.TenantID), e.ID, e.CorrObjectID, orDefault(e.ExternalSystem, "servicenow"),
			e.Action, orDefault(e.Actor, "system"), e.OldStatus, e.NewStatus, e.PayloadHash, e.Result, e.Error)
		return err
	})
}

func (s *pgTicketingStore) ListAudit(ctx context.Context, tenant string, cross bool, corrID string, limit, offset int) ([]ticketAuditEntry, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	limit, offset = boundPage(limit, offset, ticketAuditDefaultPage)
	var out []ticketAuditEntry
	var total int
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
		q += ` ORDER BY at LIMIT $` + intToString(len(args)+1) + ` OFFSET $` + intToString(len(args)+2)
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
    filters, created_at, updated_at`

func scanPolicy(rows pgx.Rows) (incidentPolicy, error) {
	var p incidentPolicy
	var filters []byte
	if err := rows.Scan(&p.TenantID, &p.ID, &p.Name, &p.ExternalSystem, &p.Enabled, &p.MinVerdict,
		&p.RequireCustomerFacing, &p.AllowProbeOnly, &p.AllowInternalMonitoring, &p.SuspectedRequiresCritical,
		&p.RequirePersistenceSeconds, &p.SuppressFlappingSeconds, &p.AssignmentGroup, &p.DefaultImpact,
		&p.DefaultUrgency, &p.ImpactConfirmedCritical, &p.UrgencyConfirmedCritical, &p.ImpactConfirmed,
		&p.UrgencyConfirmed, &filters, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	if len(filters) > 0 {
		_ = json.Unmarshal(filters, &p.Filters)
	}
	return p, nil
}

// Page bounds for the append-only ticketing tables (F-66/F-67). Defaults are
// what a UI actually renders; the max is what one caller may hold in memory and
// in a PG connection at once.
const (
	ticketLinksDefaultPage  = 500
	ticketOutboxDefaultPage = 200
	ticketAuditDefaultPage  = 200
	ticketMaxPage           = 2000
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
	if limit > ticketMaxPage {
		limit = ticketMaxPage
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

const linkCols = `tenant_id, corr_object_id, external_system, instance_url, ticket_number, sys_id, dedupe_key,
    status, last_verdict, last_confidence, last_payload_hash, last_synced_at, created_at, updated_at`

func scanLink(rows pgx.Rows) (ticketLink, error) {
	var l ticketLink
	if err := rows.Scan(&l.TenantID, &l.CorrObjectID, &l.ExternalSystem, &l.InstanceURL, &l.TicketNumber,
		&l.SysID, &l.DedupeKey, &l.Status, &l.LastVerdict, &l.LastConfidence, &l.LastPayloadHash,
		&l.LastSyncedAt, &l.CreatedAt, &l.UpdatedAt); err != nil {
		return l, err
	}
	return l, nil
}

const outboxCols = `tenant_id, id, corr_object_id, external_system, action, idempotency_key, payload, status,
    retry_count, max_retries, next_retry_at, last_error, created_at, updated_at`

func scanOutbox(rows pgx.Rows) (ticketOutboxItem, error) {
	var it ticketOutboxItem
	var payload []byte
	if err := rows.Scan(&it.TenantID, &it.ID, &it.CorrObjectID, &it.ExternalSystem, &it.Action,
		&it.IdempotencyKey, &payload, &it.Status, &it.RetryCount, &it.MaxRetries, &it.NextRetryAt,
		&it.LastError, &it.CreatedAt, &it.UpdatedAt); err != nil {
		return it, err
	}
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &it.Payload)
	}
	return it, nil
}

const auditCols = `tenant_id, id, corr_object_id, external_system, action, actor, old_status, new_status,
    payload_hash, result, error, at`

func scanAudit(rows pgx.Rows) (ticketAuditEntry, error) {
	var e ticketAuditEntry
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

var _ ticketingStore = (*memTicketingStore)(nil)
var _ ticketingStore = (*pgTicketingStore)(nil)
