-- 0008_integration_correlation.sql — observability for the ITSM Integration
-- Platform (#43 §9). Adds a single correlation_id threaded end-to-end across the
-- sync chain: alert_id ↔ incident_id ↔ (provider, external_id) ↔ ledger event id.
-- One inbound webhook delivery (and the async apply it enqueues, plus any
-- resulting outbound re-push) carries the same correlation_id, so a NOC can grep
-- one id across every log hop and join the ledger to the incident timeline.
--
-- Additive + backfill-safe: existing rows default to '' (they predate the id).

ALTER TABLE integration_events
    ADD COLUMN IF NOT EXISTS correlation_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS integration_events_correlation_idx
    ON integration_events (tenant_id, correlation_id)
    WHERE correlation_id <> '';
