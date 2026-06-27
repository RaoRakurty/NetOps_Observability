package main

import (
	"context"
	"encoding/json"
	"sort"
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

type ticketingStore interface {
	// incident policies
	ListPolicies(ctx context.Context, tenant string, cross bool) ([]incidentPolicy, error)
	GetPolicy(ctx context.Context, tenant string, cross bool, id string) (incidentPolicy, bool, error)
	PutPolicy(ctx context.Context, p incidentPolicy) error
	DeletePolicy(ctx context.Context, tenant string, cross bool, id string) (bool, error)

	// RCA object ↔ ticket links (the dedupe anchor)
	GetLink(ctx context.Context, tenant string, cross bool, corrID, system string) (ticketLink, bool, error)
	PutLink(ctx context.Context, l ticketLink) error

	// outbox + audit
	EnqueueOutbox(ctx context.Context, item ticketOutboxItem) error
	ListOutbox(ctx context.Context, tenant string, cross bool) ([]ticketOutboxItem, error)
	AppendAudit(ctx context.Context, e ticketAuditEntry) error
	ListAudit(ctx context.Context, tenant string, cross bool, corrID string) ([]ticketAuditEntry, error)
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

// ── in-memory backend ────────────────────────────────────────────────────────

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

func (m *memTicketingStore) ListOutbox(_ context.Context, tenant string, cross bool) ([]ticketOutboxItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []ticketOutboxItem
	for _, it := range m.outbox {
		if scopeVisible(tenant, cross, it.TenantID) {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *memTicketingStore) AppendAudit(_ context.Context, e ticketAuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	m.audit = append(m.audit, e)
	return nil
}

func (m *memTicketingStore) ListAudit(_ context.Context, tenant string, cross bool, corrID string) ([]ticketAuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
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
	return out, nil
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
    require_persistence_seconds, suppress_flapping_seconds, assignment_group, default_impact, default_urgency, filters)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (tenant_id, id) DO UPDATE SET
    name=EXCLUDED.name, external_system=EXCLUDED.external_system, enabled=EXCLUDED.enabled,
    min_verdict=EXCLUDED.min_verdict, require_customer_facing=EXCLUDED.require_customer_facing,
    allow_probe_only=EXCLUDED.allow_probe_only, allow_internal_monitoring=EXCLUDED.allow_internal_monitoring,
    suspected_requires_critical=EXCLUDED.suspected_requires_critical,
    require_persistence_seconds=EXCLUDED.require_persistence_seconds,
    suppress_flapping_seconds=EXCLUDED.suppress_flapping_seconds, assignment_group=EXCLUDED.assignment_group,
    default_impact=EXCLUDED.default_impact, default_urgency=EXCLUDED.default_urgency,
    filters=EXCLUDED.filters, updated_at=now()`,
			normTenant(p.TenantID), p.ID, p.Name, orDefault(p.ExternalSystem, "servicenow"), p.Enabled,
			orDefault(p.MinVerdict, "suspected"), p.RequireCustomerFacing, p.AllowProbeOnly,
			p.AllowInternalMonitoring, p.SuspectedRequiresCritical, p.RequirePersistenceSeconds,
			p.SuppressFlappingSeconds, p.AssignmentGroup, p.DefaultImpact, p.DefaultUrgency, filters)
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

func (s *pgTicketingStore) ListOutbox(ctx context.Context, tenant string, cross bool) ([]ticketOutboxItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []ticketOutboxItem
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+outboxCols+` FROM ticket_outbox ORDER BY created_at`)
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

func (s *pgTicketingStore) ListAudit(ctx context.Context, tenant string, cross bool, corrID string) ([]ticketAuditEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []ticketAuditEntry
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		q := `SELECT ` + auditCols + ` FROM ticket_audit_log`
		args := []any{}
		if corrID != "" {
			q += ` WHERE corr_object_id=$1`
			args = append(args, corrID)
		}
		q += ` ORDER BY at`
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
	return out, err
}

// ── column lists + row scanners ──────────────────────────────────────────────

const policyCols = `tenant_id, id, name, external_system, enabled, min_verdict, require_customer_facing,
    allow_probe_only, allow_internal_monitoring, suspected_requires_critical, require_persistence_seconds,
    suppress_flapping_seconds, assignment_group, default_impact, default_urgency, filters, created_at, updated_at`

func scanPolicy(rows pgx.Rows) (incidentPolicy, error) {
	var p incidentPolicy
	var filters []byte
	if err := rows.Scan(&p.TenantID, &p.ID, &p.Name, &p.ExternalSystem, &p.Enabled, &p.MinVerdict,
		&p.RequireCustomerFacing, &p.AllowProbeOnly, &p.AllowInternalMonitoring, &p.SuspectedRequiresCritical,
		&p.RequirePersistenceSeconds, &p.SuppressFlappingSeconds, &p.AssignmentGroup, &p.DefaultImpact,
		&p.DefaultUrgency, &filters, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	if len(filters) > 0 {
		_ = json.Unmarshal(filters, &p.Filters)
	}
	return p, nil
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
