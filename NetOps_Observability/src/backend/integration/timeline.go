// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package integration

import (
	"context"
	"netops/backend/internal/incident"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// integration_timeline.go — the merged per-incident timeline (#43 §9). Lifecycle
// events (incident_events: ack/resolve/note/assign/…) and ITSM sync events
// (integration_events: webhook-in / push-out, with their verdict + correlation_id)
// describe the same incident from two sides. This unifies them into one
// time-ordered stream so a NOC sees "operator acked → ServiceNow resolved →
// reconciler re-drove" as a single story, instead of two disjoint tables.

// TimelineEntry is one item in a merged incident timeline: either a lifecycle
// event or an ITSM sync event. The Kind discriminator tells the UI which fields
// are populated; At is the unifying sort key.
type TimelineEntry struct {
	Kind string    `json:"kind"` // "lifecycle" | "sync"
	At   time.Time `json:"at"`
	ID   string    `json:"id"`

	// lifecycle (incident_events)
	EventType string         `json:"event_type,omitempty"`
	Actor     string         `json:"actor,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`

	// sync (integration_events)
	Provider      string `json:"provider,omitempty"`
	Direction     string `json:"direction,omitempty"`
	Type          string `json:"type,omitempty"`
	ExternalID    string `json:"external_id,omitempty"`
	Status        string `json:"status,omitempty"`
	Reason        string `json:"reason,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// ListSyncEventsForIncident returns the ITSM sync events tied to an incident —
// correlated either directly (Slack actions carry the incident id in alert_id)
// or via the mapping reverse-index (provider, external_id). Tenant-scoped by RLS.
func (s *Store) ListSyncEventsForIncident(ctx context.Context, tenant string, cross bool, incidentID string) ([]TimelineEntry, error) {
	var out []TimelineEntry
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT e.id, e.provider, e.direction, e.type, e.external_id, e.status, e.reason, e.correlation_id,
       COALESCE(e.occurred_at, e.created_at) AS at
  FROM integration_events e
 WHERE e.alert_id = $1
    OR (e.provider, e.external_id) IN (
         SELECT m.provider, m.external_id
           FROM integration_mappings m
          WHERE m.internal_incident_id = $1)
 ORDER BY at ASC, e.id ASC`, incidentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e := TimelineEntry{Kind: "sync"}
			if err := rows.Scan(&e.ID, &e.Provider, &e.Direction, &e.Type, &e.ExternalID,
				&e.Status, &e.Reason, &e.CorrelationID, &e.At); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// MergeTimeline folds lifecycle events and sync events into one time-ordered
// stream (oldest first), stable on equal timestamps (lifecycle before sync, then
// by id) so the order is deterministic across calls.
func MergeTimeline(lifecycle []incident.Event, sync []TimelineEntry) []TimelineEntry {
	merged := make([]TimelineEntry, 0, len(lifecycle)+len(sync))
	for _, ev := range lifecycle {
		merged = append(merged, TimelineEntry{
			Kind: "lifecycle", At: ev.CreatedAt, ID: ev.ID,
			EventType: ev.EventType, Actor: ev.Actor, Payload: ev.Payload,
		})
	}
	merged = append(merged, sync...)
	sort.SliceStable(merged, func(i, j int) bool {
		if !merged[i].At.Equal(merged[j].At) {
			return merged[i].At.Before(merged[j].At)
		}
		if merged[i].Kind != merged[j].Kind {
			return merged[i].Kind == "lifecycle" // lifecycle before sync on a tie
		}
		return merged[i].ID < merged[j].ID
	})
	return merged
}
