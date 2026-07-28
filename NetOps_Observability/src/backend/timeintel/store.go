package timeintel

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// timeintel_store.go — persistence for operator-supplied incident lifecycle events
// (RCA Time Intelligence #84 P1d). Engine + ITSM events stay DERIVED on read; only
// human-entered/imported timestamps persist here, merged into the lifecycle so an
// operator can supply the recovery/closure timestamps the platform can't observe.
//
// Two backends like every other store: in-memory (default, tenant-filtered in the
// store) and Postgres (tenant_iso FORCE-RLS via withTenant). Tenant isolation is
// enforced in the store itself (CLAUDE.md §3a) — no caller can read across tenants.

type TimelineEvent struct {
	TenantID       string          `json:"-"`
	ID             string          `json:"id"`
	CorrelationID  string          `json:"correlation_id"`
	EventType      EventType       `json:"event_type"`
	EventTime      time.Time       `json:"event_time"`
	Source         TimestampSource `json:"timestamp_source"`
	Confidence     float64         `json:"confidence"`
	SourceSystem   string          `json:"source_system"`
	SourceSignalID string          `json:"source_signal_id,omitempty"`
	SourceTicketID string          `json:"source_ticket_id,omitempty"`
	Note           string          `json:"note,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	CreatedBy      string          `json:"created_by"`
}

// guard is the unique-per-incident key (one row per incident/type/system/source ids);
// an edit with the same guard upserts.
func (e TimelineEvent) guard() string {
	return strings.Join([]string{e.CorrelationID, string(e.EventType), e.SourceSystem, e.SourceSignalID, e.SourceTicketID}, "\x1f")
}

type TimelineStore interface {
	List(ctx context.Context, tenant string, cross bool, corrID string) ([]TimelineEvent, error)
	Put(ctx context.Context, e TimelineEvent) error // upsert by guard
	Delete(ctx context.Context, tenant string, cross bool, corrID, id string) (bool, error)
}

// ── in-memory backend ────────────────────────────────────────────────────────

// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewMemTimelineStore / NewPGTimelineStore build the two backends.
func NewMemTimelineStore() *memTimelineStore {
	return &memTimelineStore{by: map[string]TimelineEvent{}}
}

func NewPGTimelineStore(db DB) *pgTimelineStore { return &pgTimelineStore{db: db} }

// normTenant mirrors the integrator's tenant-id normalization (duplicated).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

type memTimelineStore struct {
	mu sync.RWMutex
	by map[string]TimelineEvent // key: tenant\x1fguard
}

func (m *memTimelineStore) key(tenant, guard string) string {
	return normTenant(tenant) + "\x1f" + guard
}

func (m *memTimelineStore) List(_ context.Context, tenant string, cross bool, corrID string) ([]TimelineEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	out := []TimelineEvent{}
	for _, e := range m.by {
		if e.CorrelationID != corrID {
			continue
		}
		if !cross && e.TenantID != t { // default-closed tenant filter
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *memTimelineStore) Put(_ context.Context, e TimelineEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.by[m.key(e.TenantID, e.guard())] = e
	return nil
}

func (m *memTimelineStore) Delete(_ context.Context, tenant string, cross bool, corrID, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := normTenant(tenant)
	for k, e := range m.by {
		if e.ID != id || e.CorrelationID != corrID {
			continue
		}
		if !cross && e.TenantID != t { // can't delete another tenant's row
			return false, nil
		}
		delete(m.by, k)
		return true, nil
	}
	return false, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant) ────────────────────

type pgTimelineStore struct{ db DB }

func (s *pgTimelineStore) List(ctx context.Context, tenant string, cross bool, corrID string) ([]TimelineEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := []TimelineEvent{}
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, id, correlation_id, event_type, event_time, timestamp_source,
       confidence, source_system, source_signal_id, source_ticket_id, note, created_at, created_by
  FROM incident_timeline_events
 WHERE correlation_id = $1
 ORDER BY event_time`, corrID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e TimelineEvent
			var et string
			if err := rows.Scan(&e.TenantID, &e.ID, &e.CorrelationID, &et, &e.EventTime, &e.Source,
				&e.Confidence, &e.SourceSystem, &e.SourceSignalID, &e.SourceTicketID, &e.Note, &e.CreatedAt, &e.CreatedBy); err != nil {
				return err
			}
			e.EventType = EventType(et)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgTimelineStore) Put(ctx context.Context, e TimelineEvent) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Writer is always tenant-scoped (the owner is stamped from the token); WITH CHECK
	// enforces the row's tenant matches the bound scope.
	return s.db.WithTenant(ctx, e.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO incident_timeline_events
  (tenant_id, id, correlation_id, event_type, event_time, timestamp_source, confidence,
   source_system, source_signal_id, source_ticket_id, note, created_at, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (tenant_id, correlation_id, event_type, source_system, source_signal_id, source_ticket_id)
DO UPDATE SET id = EXCLUDED.id, event_time = EXCLUDED.event_time,
              timestamp_source = EXCLUDED.timestamp_source, confidence = EXCLUDED.confidence,
              note = EXCLUDED.note, created_at = EXCLUDED.created_at, created_by = EXCLUDED.created_by`,
			normTenant(e.TenantID), e.ID, e.CorrelationID, string(e.EventType), e.EventTime, string(e.Source),
			e.Confidence, e.SourceSystem, e.SourceSignalID, e.SourceTicketID, e.Note, e.CreatedAt, e.CreatedBy)
		return err
	})
}

func (s *pgTimelineStore) Delete(ctx context.Context, tenant string, cross bool, corrID, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var deleted bool
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM incident_timeline_events WHERE correlation_id = $1 AND id = $2`, corrID, id)
		if err != nil {
			return err
		}
		deleted = ct.RowsAffected() > 0
		return nil
	})
	return deleted, err
}
