-- 0009_correlation_engine.sql — Correlation Engine v2 (#67), FROZEN at build
-- step ① (2026-06-11). Postgres holds the SMALL, TRANSACTIONAL, MUTABLE side
-- (active-object registry + ops lifecycle, hypothesis templates); ClickHouse
-- holds the large append-only replayable side (corr_signals/objects/edges/
-- evidence — see deployment/docker/clickhouse/init.sql). RLS-isolated per
-- tenant exactly like incidents/audit_events.

-- Active-object registry: one row per OPEN/recently-closed correlation object.
-- Claimed and updated by the engine (FOR UPDATE SKIP LOCKED, the report-queue
-- pattern); ack/close driven from the UI through the Go API.
CREATE TABLE IF NOT EXISTS corr_active (
    correlation_id  UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'open'
                    CHECK (state IN ('open','closed','merged')),
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_update     TIMESTAMPTZ NOT NULL DEFAULT now(),
    current_version INT  NOT NULL DEFAULT 1,
    quiesce_after   TIMESTAMPTZ NOT NULL,            -- close timer (all episodes clear)
    ack_by          TEXT NOT NULL DEFAULT '',        -- ops lifecycle, UI-driven
    incident_id     TEXT                             -- set once promoted to an incident
);

CREATE INDEX IF NOT EXISTS corr_active_tenant_state_idx
    ON corr_active (tenant_id, state, last_update DESC);
CREATE INDEX IF NOT EXISTS corr_active_quiesce_idx
    ON corr_active (quiesce_after) WHERE state = 'open';

ALTER TABLE corr_active ENABLE ROW LEVEL SECURITY;
ALTER TABLE corr_active FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON corr_active;
CREATE POLICY tenant_iso ON corr_active
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- Hypothesis templates — the failure-signature catalog AS DATA (declarative
-- predicates, docs/design/correlation-engine.md §4.5). tenant_id '' = built-in/
-- platform set; PK is (tenant_id, id) so a tenant can SHADOW a built-in
-- signature id with its own version without colliding (freeze deviation from
-- the draft's bare id PK, recorded in the design doc §2 freeze note).
-- catalog_version: every change to any row bumps the per-tenant catalog version
-- (engine snapshots pin it — replay contract, research C6).
CREATE TABLE IF NOT EXISTS corr_hypothesis_templates (
    tenant_id   TEXT NOT NULL DEFAULT '',
    id          TEXT NOT NULL,                       -- 'sig.wan_congestion'
    version     INT  NOT NULL DEFAULT 1,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    spec        JSONB NOT NULL,                      -- declarative predicate (§4.5)
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT NOT NULL DEFAULT 'system',
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE corr_hypothesis_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE corr_hypothesis_templates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON corr_hypothesis_templates;
-- Read: a tenant sees the built-in set ('') plus its own rows. Write: only its
-- own rows (WITH CHECK has no tenant_id='' carve-out — built-ins are platform-
-- managed, written only under app.current_tenant='*').
CREATE POLICY tenant_iso ON corr_hypothesis_templates
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true)
        OR tenant_id = '')
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));
