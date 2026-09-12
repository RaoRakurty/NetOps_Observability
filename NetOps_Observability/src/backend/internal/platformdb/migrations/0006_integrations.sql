-- 0006_integrations.sql — the ITSM Integration Platform's correlation + ledger
-- tables (docs/design/itsm-integration-platform.md). Additive; nothing reads/writes
-- these until P2 wiring lands. RLS-isolated per tenant exactly like incidents/audit.
--
-- integration_mappings: the reverse external<->internal index INBOUND needs, plus
--   the ordering WATERMARK (applied_seq/applied_at, §4a) per external incident.
-- integration_events: the durable outbound+inbound ledger enforcing 3-level
--   idempotency (§4d) — the UNIQUE on provider_evt_id makes a redelivered webhook a
--   no-op insert (at-least-once -> exactly-once effect).
--
-- (integration_configs — the per-tenant/provider config table that supersedes the
--  itsm_config kv blob — lands with P2 config migration; kept out of this additive
--  step to avoid churning the just-shipped per-tenant ITSM config.)

CREATE TABLE IF NOT EXISTS integration_mappings (
    tenant_id            TEXT NOT NULL DEFAULT '',
    provider             TEXT NOT NULL,
    external_id          TEXT NOT NULL,              -- ticket/incident id in the external system
    internal_incident_id TEXT NOT NULL DEFAULT '',
    state                TEXT NOT NULL DEFAULT '',   -- last reconciled internal state
    applied_seq          BIGINT NOT NULL DEFAULT 0,  -- high-water mark: last orderKey seq applied (§4a)
    applied_at           TIMESTAMPTZ,                -- high-water mark: last orderKey time
    external_etag        TEXT NOT NULL DEFAULT '',
    last_synced_at       TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, provider, external_id)
);

CREATE INDEX IF NOT EXISTS integration_mappings_incident_idx
    ON integration_mappings (tenant_id, internal_incident_id);

ALTER TABLE integration_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_mappings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON integration_mappings;
CREATE POLICY tenant_iso ON integration_mappings
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

CREATE TABLE IF NOT EXISTS integration_events (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL,
    direction       TEXT NOT NULL,                  -- 'outbound' | 'inbound'
    type            TEXT NOT NULL DEFAULT '',       -- canonical EventType
    provider_evt_id TEXT NOT NULL DEFAULT '',       -- level-1 raw dedup key (§4d)
    external_id     TEXT NOT NULL DEFAULT '',       -- level-2 logical dedup + ordering
    external_seq    BIGINT NOT NULL DEFAULT 0,
    alert_id        TEXT NOT NULL DEFAULT '',       -- level-3 business dedup
    status          TEXT NOT NULL DEFAULT 'received', -- received | applied | dropped | failed | dead
    retry_count     INT  NOT NULL DEFAULT 0,
    reason          TEXT NOT NULL DEFAULT '',       -- reconciler verdict / error
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Level-1 raw dedup: a redelivered webhook (same provider event id) collapses to a
-- no-op via ON CONFLICT DO NOTHING. Partial: only when an id is present.
CREATE UNIQUE INDEX IF NOT EXISTS integration_events_evtid_idx
    ON integration_events (tenant_id, provider, provider_evt_id)
    WHERE provider_evt_id <> '';

CREATE INDEX IF NOT EXISTS integration_events_external_idx
    ON integration_events (tenant_id, provider, external_id, external_seq);

ALTER TABLE integration_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON integration_events;
CREATE POLICY tenant_iso ON integration_events
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));
