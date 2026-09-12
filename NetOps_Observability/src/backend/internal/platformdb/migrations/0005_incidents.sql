-- 0005_incidents.sql — first-class Incident system (the internal SYSTEM OF RECORD).
-- External ITSM (ServiceNow/Jira) is an optional async PROJECTION recorded in the
-- external_* columns; incident creation/lifecycle never depends on it. RLS-isolated
-- per tenant exactly like audit_events.

CREATE TABLE IF NOT EXISTS incidents (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL DEFAULT '',
    title              TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL DEFAULT 'info',   -- info | low | medium | high | critical
    status             TEXT NOT NULL DEFAULT 'open',   -- open | acknowledged | investigating | resolved | closed
    source_type        TEXT NOT NULL DEFAULT 'manual', -- alert | log | anomaly | manual
    source_id          TEXT,                           -- nullable finding/alert reference
    dedup_key          TEXT NOT NULL DEFAULT '',
    owner              TEXT NOT NULL DEFAULT '',        -- user/team id
    occurrences        INT  NOT NULL DEFAULT 1,         -- # detections folded in via dedup
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at        TIMESTAMPTZ,
    -- external ITSM projection (never the source of truth)
    external_ticket_id TEXT,
    external_url       TEXT,
    external_system    TEXT,                            -- jira | servicenow | other
    sync_status        TEXT NOT NULL DEFAULT 'none',    -- none | pending | synced | failed
    last_synced_at     TIMESTAMPTZ
);

-- Storm-proof dedup: at most ONE active (non-terminal) incident per
-- (tenant, dedup_key). Closed/resolved incidents release the key so a genuine
-- recurrence opens a fresh incident. Enforced at the DB so concurrent alert
-- bursts can't race past it (the upsert arbitrates on this exact partial index).
CREATE UNIQUE INDEX IF NOT EXISTS incidents_dedup_active_idx
    ON incidents (tenant_id, dedup_key)
    WHERE dedup_key <> '' AND status NOT IN ('resolved', 'closed');

CREATE INDEX IF NOT EXISTS incidents_tenant_status_idx ON incidents (tenant_id, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS incidents_severity_idx ON incidents (tenant_id, severity);

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON incidents;
CREATE POLICY tenant_iso ON incidents
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- Append-only timeline for UI reconstruction: created | status_change | note |
-- assignment | linkage | dedup | sync.
CREATE TABLE IF NOT EXISTS incident_events (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT '',
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    actor       TEXT NOT NULL DEFAULT 'system',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_events_incident_idx ON incident_events (incident_id, created_at);

ALTER TABLE incident_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON incident_events;
CREATE POLICY tenant_iso ON incident_events
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));
