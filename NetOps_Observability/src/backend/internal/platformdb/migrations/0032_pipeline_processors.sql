-- 0032_pipeline_processors.sql — per-tenant ingest processor rules (tracker
-- item 121, the "UI processor editor" remnant).
--
-- One row per rule. Typed columns carry identity/routing; the data JSONB blob
-- carries the full structured rule (target field, pattern, match guard) — the
-- maintenance_windows/wireless storage pattern. Rules are STRUCTURED, never
-- free-form VRL: the api generates the router's processors.yaml from them
-- (src/backend/processors/generate.go), embedding user input only as escaped
-- string literals.
--
-- RLS: tenant_iso, FORCE — migration 0011 is the template; identical to 0031.
-- Additive migration — safe to apply forward.

CREATE TABLE IF NOT EXISTS pipeline_processors (
    tenant_id  TEXT NOT NULL DEFAULT '',
    rule_id    UUID NOT NULL,
    lane       TEXT NOT NULL
               CHECK (lane IN ('applogs','syslog','snmptrap','cloudlogs','flows')),
    rule_type  TEXT NOT NULL
               CHECK (rule_type IN ('redact_field','redact_pattern','drop_field','set_field')),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, rule_id)
);
CREATE INDEX IF NOT EXISTS pipeline_processors_enabled_idx
    ON pipeline_processors (tenant_id, enabled, lane);

ALTER TABLE pipeline_processors ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipeline_processors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON pipeline_processors;
CREATE POLICY tenant_iso ON pipeline_processors
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
