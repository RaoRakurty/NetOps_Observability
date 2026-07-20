package main

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"netops/backend/timeintel"
)

// timeintel_store.go — persistence for operator-supplied incident lifecycle events
// (RCA Time Intelligence #84 P1d). Engine + ITSM events stay DERIVED on read; only
// human-entered/imported timestamps persist here, merged into the lifecycle so an
// operator can supply the recovery/closure timestamps the platform can't observe.
//
// Two backends like every other store: in-memory (default, tenant-filtered in the
// store) and Postgres (tenant_iso FORCE-RLS via withTenant). Tenant isolation is
// enforced in the store itself (CLAUDE.md §3a) — no caller can read across tenants.

type incidentTimelineEvent struct {
	TenantID       string                    `json:"-"`
	ID             string                    `json:"id"`
	CorrelationID  string                    `json:"correlation_id"`
	EventType      timeintel.EventType       `json:"event_type"`
	EventTime      time.Time                 `json:"event_time"`
	Source         timeintel.TimestampSource `json:"timestamp_source"`
	Confidence     float64                   `json:"confidence"`
	SourceSystem   string                    `json:"source_system"`
	SourceSignalID string                    `json:"source_signal_id,omitempty"`
	SourceTicketID string                    `json:"source_ticket_id,omitempty"`
	Note           string                    `json:"note,omitempty"`
	CreatedAt      time.Time                 `json:"created_at"`
	CreatedBy      string                    `json:"created_by"`
}

// guard is the unique-per-incident key (one row per incident/type/system/source ids);
// an edit with the same guard upserts.
func (e incidentTimelineEvent) guard() string {
	return strings.Join([]string{e.CorrelationID, string(e.EventType), e.SourceSystem, e.SourceSignalID, e.SourceTicketID}, "\x1f")
}

type incidentTimelineStore interface {
	List(ctx context.Context, tenant string, cross bool, corrID string) ([]incidentTimelineEvent, error)
	Put(ctx context.Context, e incidentTimelineEvent) error // upsert by guard
	Delete(ctx context.Context, tenant string, cross bool, corrID, id string) (bool, error)
}

// newIncidentTimelineStore selects pg under STORE_BACKEND=postgres, else in-memory.
func newIncidentTimelineStore() incidentTimelineStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgIncidentTimelineStore{db: ps.db}
	}
	return &memIncidentTimelineStore{by: map[string]incidentTimelineEvent{}}
}

// ── in-memory backend ────────────────────────────────────────────────────────

type memIncidentTimelineStore struct {
	mu sync.RWMutex
	by map[string]incidentTimelineEvent // key: tenant\x1fguard
}

func (m *memIncidentTimelineStore) key(tenant, guard string) string {
	return normTenant(tenant) + "\x1f" + guard
}

func (m *memIncidentTimelineStore) List(_ context.Context, tenant string, cross bool, corrID string) ([]incidentTimelineEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	out := []incidentTimelineEvent{}
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

func (m *memIncidentTimelineStore) Put(_ context.Context, e incidentTimelineEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.by[m.key(e.TenantID, e.guard())] = e
	return nil
}

func (m *memIncidentTimelineStore) Delete(_ context.Context, tenant string, cross bool, corrID, id string) (bool, error) {
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

type pgIncidentTimelineStore struct{ db *pgDB }

func (s *pgIncidentTimelineStore) List(ctx context.Context, tenant string, cross bool, corrID string) ([]incidentTimelineEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := []incidentTimelineEvent{}
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
			var e incidentTimelineEvent
			var et string
			if err := rows.Scan(&e.TenantID, &e.ID, &e.CorrelationID, &et, &e.EventTime, &e.Source,
				&e.Confidence, &e.SourceSystem, &e.SourceSignalID, &e.SourceTicketID, &e.Note, &e.CreatedAt, &e.CreatedBy); err != nil {
				return err
			}
			e.EventType = timeintel.EventType(et)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgIncidentTimelineStore) Put(ctx context.Context, e incidentTimelineEvent) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Writer is always tenant-scoped (the owner is stamped from the token); WITH CHECK
	// enforces the row's tenant matches the bound scope.
	return s.db.withTenant(ctx, e.TenantID, false, func(tx pgx.Tx) error {
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

func (s *pgIncidentTimelineStore) Delete(ctx context.Context, tenant string, cross bool, corrID, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var deleted bool
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM incident_timeline_events WHERE correlation_id = $1 AND id = $2`, corrID, id)
		if err != nil {
			return err
		}
		deleted = ct.RowsAffected() > 0
		return nil
	})
	return deleted, err
}
