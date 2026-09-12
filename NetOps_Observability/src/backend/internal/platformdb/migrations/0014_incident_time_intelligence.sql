-- 0014_incident_time_intelligence.sql — RCA Time Intelligence persistence (#84 P1d).
-- Two tenant-isolated tables: manual/operator lifecycle events (the engine + ITSM
-- events stay DERIVED on read; only human-entered/imported ones persist here), and a
-- computed phase-metrics snapshot for backfill/rollup acceleration. Both carry RLS
-- (tenant_iso FORCE on app.tenant_id) identical to every other tenant table.

-- ── incident_timeline_events ──────────────────────────────────────────────────
-- Operator-supplied lifecycle timestamps (e.g. "service recovered at X",
-- "acknowledged at Y") that the engine/ITSM can't observe. The unique guard keeps
-- one row per (incident, event_type, source_system, source id) so an edit upserts.
CREATE TABLE IF NOT EXISTS incident_timeline_events (
    tenant_id         TEXT NOT NULL DEFAULT '',
    id                TEXT NOT NULL,
    correlation_id    TEXT NOT NULL,
    event_type        TEXT NOT NULL,                       -- timeintel.EventType
    event_time        TIMESTAMPTZ NOT NULL,
    timestamp_source  TEXT NOT NULL DEFAULT 'user_entered',-- observed|inferred|user_entered|itsm|synthetic|imported
    confidence        NUMERIC(4,3) NOT NULL DEFAULT 1.0,
    source_system     TEXT NOT NULL DEFAULT 'manual',
    source_signal_id  TEXT NOT NULL DEFAULT '',
    source_ticket_id  TEXT NOT NULL DEFAULT '',
    note              TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS incident_timeline_events_corr_idx
    ON incident_timeline_events (tenant_id, correlation_id);
-- one row per (incident, event_type, source_system, source ids) — edits upsert.
CREATE UNIQUE INDEX IF NOT EXISTS incident_timeline_events_guard
    ON incident_timeline_events (tenant_id, correlation_id, event_type, source_system, source_signal_id, source_ticket_id);

ALTER TABLE incident_timeline_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_timeline_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON incident_timeline_events;
CREATE POLICY tenant_iso ON incident_timeline_events
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

-- ── incident_time_metrics ─────────────────────────────────────────────────────
-- A computed phase-metrics snapshot per (incident, calculation_version). Idempotent:
-- the backfill upserts on the PK. Metrics are still computed on read for live views;
-- this table accelerates rollups/backfill beyond the live scan cap.
CREATE TABLE IF NOT EXISTS incident_time_metrics (
    tenant_id           TEXT NOT NULL DEFAULT '',
    correlation_id      TEXT NOT NULL,
    calculation_version TEXT NOT NULL,
    occurred_at         TIMESTAMPTZ,
    owner_domain        TEXT NOT NULL DEFAULT '',
    current_bottleneck  TEXT NOT NULL DEFAULT '',
    metrics             JSONB NOT NULL DEFAULT '[]'::jsonb, -- []timeintel.TimeMetric
    calculated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, correlation_id, calculation_version)
);
CREATE INDEX IF NOT EXISTS incident_time_metrics_occurred_idx
    ON incident_time_metrics (tenant_id, occurred_at);

ALTER TABLE incident_time_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_time_metrics FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON incident_time_metrics;
CREATE POLICY tenant_iso ON incident_time_metrics
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
