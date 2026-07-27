package main

import (
	"context"
	"encoding/json"
	"errors"
	"netops/backend/internal/vault"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/integration"
)

// integration_repo_pg.go — Postgres persistence for the Integration Platform
// (migration 0006): the external<->internal correlation index + ordering
// watermark (integration_mappings) and the 3-level-idempotent event ledger
// (integration_events). Additive; wired by the inbound worker in P2. Modeled on
// incidents_pg.go (withTenant binds app.tenant_id; system writes run at
// platform scope '*' and stamp tenant_id, which RLS WITH CHECK permits).

type integrationStore struct {
	db    *pgDB
	vault *vault.Vault // secret-custody envelope for webhook_secret at rest (nil/dormant = plaintext)
}

func newIntegrationStore(db *pgDB, v *vault.Vault) *integrationStore {
	return &integrationStore{db: db, vault: v}
}

// integrationMapping is one external incident's correlation + watermark row.
type integrationMapping struct {
	Tenant     string
	Provider   string
	ExternalID string
	IncidentID string
	State      string
	Applied    integration.Watermark // Seq + At — the ordering high-water mark (§4a)
}

// GetMapping returns the mapping for (provider, externalID), tenant-scoped.
func (s *integrationStore) GetMapping(ctx context.Context, tenant string, cross bool, provider, externalID string) (integrationMapping, bool, error) {
	var m integrationMapping
	var found bool
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var appliedAt *time.Time
		row := tx.QueryRow(ctx, `
SELECT tenant_id, provider, external_id, internal_incident_id, state, applied_seq, applied_at
  FROM integration_mappings WHERE provider=$1 AND external_id=$2`, provider, externalID)
		if err := row.Scan(&m.Tenant, &m.Provider, &m.ExternalID, &m.IncidentID, &m.State, &m.Applied.Seq, &appliedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if appliedAt != nil {
			m.Applied.At = *appliedAt
		}
		found = true
		return nil
	})
	return m, found, err
}

// UpsertMapping inserts or advances a mapping. System write → platform scope; the
// row's tenant_id is stamped from m.Tenant. Advances the watermark + state.
func (s *integrationStore) UpsertMapping(ctx context.Context, m integrationMapping) error {
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		var at any
		if !m.Applied.At.IsZero() {
			at = m.Applied.At
		}
		_, err := tx.Exec(ctx, `
INSERT INTO integration_mappings
   (tenant_id, provider, external_id, internal_incident_id, state, applied_seq, applied_at, last_synced_at, updated_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7, now(), now())
 ON CONFLICT (tenant_id, provider, external_id) DO UPDATE SET
   internal_incident_id = EXCLUDED.internal_incident_id,
   state                = EXCLUDED.state,
   applied_seq          = EXCLUDED.applied_seq,
   applied_at           = EXCLUDED.applied_at,
   last_synced_at       = now(),
   updated_at           = now()`,
			m.Tenant, m.Provider, m.ExternalID, m.IncidentID, m.State, m.Applied.Seq, at)
		return err
	})
}

// ListOpenMappings returns a tenant's non-terminal mappings for a provider — the
// drift-reconciler candidates — stalest first, bounded by limit.
func (s *integrationStore) ListOpenMappings(ctx context.Context, tenant, provider string, limit int) ([]integrationMapping, error) {
	var out []integrationMapping
	err := s.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT tenant_id, provider, external_id, internal_incident_id, state, applied_seq, applied_at
  FROM integration_mappings
 WHERE provider=$1 AND state NOT IN ('resolved','closed')
 ORDER BY last_synced_at ASC NULLS FIRST
 LIMIT $2`, provider, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m integrationMapping
			var appliedAt *time.Time
			if err := rows.Scan(&m.Tenant, &m.Provider, &m.ExternalID, &m.IncidentID, &m.State, &m.Applied.Seq, &appliedAt); err != nil {
				return err
			}
			if appliedAt != nil {
				m.Applied.At = *appliedAt
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// TouchMapping bumps last_synced_at so a polled mapping rotates to the back of the
// reconciler's stalest-first queue (whether or not drift was found).
func (s *integrationStore) TouchMapping(ctx context.Context, tenant, provider, externalID string) error {
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE integration_mappings SET last_synced_at=now()
			WHERE tenant_id=$1 AND provider=$2 AND external_id=$3`, tenant, provider, externalID)
		return err
	})
}

// RecordInbound persists a normalized inbound event (level-1 raw dedup via the
// partial unique on provider_evt_id). Returns inserted=false when the event was a
// redelivery (ON CONFLICT DO NOTHING) — the caller then skips re-applying it.
//
// correlationID is the single id threaded end-to-end (§9): minted here per
// recorded event and carried through enqueue → worker apply → incident
// transition (and any resulting outbound re-push), so one grep spans the chain.
func (s *integrationStore) RecordInbound(ctx context.Context, ev integration.IntegrationEvent) (id, correlationID string, inserted bool, err error) {
	id = randHex(8)
	correlationID = "ic-" + randHex(8)
	payload, _ := json.Marshal(ev)
	var occurred any
	if !ev.OccurredAt.IsZero() {
		occurred = ev.OccurredAt
	}
	err = s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		var returned string
		qerr := tx.QueryRow(ctx, `
INSERT INTO integration_events
   (id, tenant_id, provider, direction, type, provider_evt_id, external_id, external_seq, alert_id, status, payload, occurred_at, correlation_id)
 VALUES ($1,$2,$3,'inbound',$4,$5,$6,$7,$8,'received',$9,$10,$11)
 ON CONFLICT (tenant_id, provider, provider_evt_id) WHERE provider_evt_id <> '' DO NOTHING
 RETURNING id`,
			id, ev.Tenant, ev.Provider, string(ev.Type), ev.ProviderEvtID, ev.ExternalID, ev.ExternalSeq, ev.AlertID, payload, occurred, correlationID)
		if scanErr := qerr.Scan(&returned); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				inserted = false // redelivery — collapsed by the unique index
				return nil
			}
			return scanErr
		}
		inserted = true
		return nil
	})
	return id, correlationID, inserted, err
}

// GetInboundEvent reconstructs a recorded inbound event from its ledger row (the
// canonical IntegrationEvent was stored as the payload). Used by the async apply
// worker. Platform scope (the worker resolves tenant from the event).
func (s *integrationStore) GetInboundEvent(ctx context.Context, id string) (integration.IntegrationEvent, bool, error) {
	var ev integration.IntegrationEvent
	var found bool
	err := s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		var payload []byte
		e := tx.QueryRow(ctx, `SELECT payload FROM integration_events WHERE id=$1`, id).Scan(&payload)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if uerr := json.Unmarshal(payload, &ev); uerr != nil {
			return uerr
		}
		found = true
		return nil
	})
	return ev, found, err
}

// MarkEvent records the reconciler's verdict (status + reason) for a ledger row.
func (s *integrationStore) MarkEvent(ctx context.Context, id, status, reason string) error {
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
UPDATE integration_events SET status=$2, reason=$3, updated_at=now() WHERE id=$1`, id, status, reason)
		return err
	})
}
