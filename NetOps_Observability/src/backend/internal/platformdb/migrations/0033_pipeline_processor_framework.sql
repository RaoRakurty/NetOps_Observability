-- 0033_pipeline_processor_framework.sql — the Pipeline Processors FRAMEWORK
-- layer (2026-07-31 spec) on top of the initial per-tenant processors (0032).
--
-- Adds:
--   pipeline_processors.rule_order  — explicit execution priority. Ordering was
--                                     implicit (created_at); the engine's
--                                     determinism contract needs it declared.
--   pipeline_processors.version     — bumps on every saved edit.
--   pipeline_processors.source      — provenance badge: custom | managed.
--   processor_versions              — immutable, append-only config history.
--                                     Rollback writes the old config FORWARD as
--                                     a new version; history is never rewound.
--   managed_rule_state              — per-tenant enable/disable of the curated
--                                     catalog.
--
-- Managed rule DEFINITIONS deliberately live in code (processors/managed.go),
-- not in a table: they are system-owned, read-only and versioned WITH the
-- binary, so a deploy can never leave a tenant referencing a pattern the
-- running engine doesn't have. Only the per-tenant enablement state is
-- persisted here. A tenant that wants to change a managed rule CLONES it,
-- which produces an ordinary tenant-owned processor row above.
--
-- RLS: tenant_iso, FORCE on every new table — migration 0011 is the template.
-- Additive and idempotent — safe to apply forward.

ALTER TABLE pipeline_processors
    ADD COLUMN IF NOT EXISTS rule_order INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS version    INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS source     TEXT    NOT NULL DEFAULT 'custom'
        CHECK (source IN ('custom','managed'));

-- Execution order is the read path's sort key.
CREATE INDEX IF NOT EXISTS pipeline_processors_order_idx
    ON pipeline_processors (tenant_id, lane, rule_order);

CREATE TABLE IF NOT EXISTS processor_versions (
    tenant_id    TEXT NOT NULL DEFAULT '',
    processor_id UUID NOT NULL,
    version      INTEGER NOT NULL,
    config       JSONB NOT NULL,
    changed_by   TEXT NOT NULL DEFAULT '',
    change_kind  TEXT NOT NULL DEFAULT 'updated'
                 CHECK (change_kind IN ('created','updated','rolled_back')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, processor_id, version)
);
CREATE INDEX IF NOT EXISTS processor_versions_processor_idx
    ON processor_versions (tenant_id, processor_id, version DESC);

CREATE TABLE IF NOT EXISTS managed_rule_state (
    tenant_id  TEXT NOT NULL DEFAULT '',
    rule_id    TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, rule_id)
);

ALTER TABLE processor_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE processor_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON processor_versions;
CREATE POLICY tenant_iso ON processor_versions
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE managed_rule_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE managed_rule_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON managed_rule_state;
CREATE POLICY tenant_iso ON managed_rule_state
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

-- Backfill: existing processors are custom, version 1, ordered by age so the
-- pre-framework implicit order is preserved exactly.
UPDATE pipeline_processors SET source = 'custom' WHERE source IS NULL OR source = '';
