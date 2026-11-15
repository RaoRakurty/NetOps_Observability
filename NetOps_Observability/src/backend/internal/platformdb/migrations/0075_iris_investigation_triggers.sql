-- 0075_iris_investigation_triggers.sql — triggered Iris investigations (tracker
-- 337 N-I2, design of record D16). A tenant admin asks Iris to run its
-- read-only Investigator on its own: when a new incident matches a filter, or
-- on a schedule. Three tables, all tenant-owned:
--
--   iris_investigation_trigger_settings  the workspace switch (default OFF) and
--                                        its daily caps (runs, tokens)
--   iris_investigation_triggers          what to run and when
--   iris_investigation_trigger_runs      every run, admitted or skipped, with
--                                        its reason — one per (trigger, dedupe
--                                        key): one per incident, one per slot
--
-- The UNIQUE (tenant_id, trigger_id, dedupe_key) is the dedupe: two detections
-- of one incident, or two scheduler ticks in one interval, cannot both start a
-- run even across replicas. The CHECKs refuse a skipped run without a reason
-- and a schedule faster than 15 minutes, whatever the application does.
--
-- RLS: tenant_iso, FORCE — the API reads and writes through WithTenant so the
-- policy always has its GUC; only the scheduler's due-trigger read uses the
-- platform scope ('*'), and every run it starts is written back under the
-- trigger's own tenant.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS iris_investigation_trigger_settings (
    tenant_id           TEXT PRIMARY KEY,
    enabled             BOOLEAN NOT NULL DEFAULT false,
    max_runs_per_day    INTEGER NOT NULL DEFAULT 20 CHECK (max_runs_per_day BETWEEN 1 AND 100),
    max_tokens_per_day  INTEGER NOT NULL DEFAULT 200000 CHECK (max_tokens_per_day BETWEEN 1000 AND 1000000),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iris_investigation_triggers (
    tenant_id      TEXT NOT NULL,
    id             UUID NOT NULL,
    name           TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    kind           TEXT NOT NULL CHECK (kind IN ('incident','schedule')),
    enabled        BOOLEAN NOT NULL DEFAULT true,
    min_severity   TEXT NOT NULL DEFAULT '' CHECK (min_severity IN ('','info','notice','warning','error','critical')),
    signature      TEXT NOT NULL DEFAULT '' CHECK (char_length(signature) <= 100),
    site           TEXT NOT NULL DEFAULT '' CHECK (char_length(site) <= 100),
    device_role    TEXT NOT NULL DEFAULT '' CHECK (char_length(device_role) <= 100),
    every_minutes  INTEGER NOT NULL DEFAULT 0,
    question       TEXT NOT NULL DEFAULT '' CHECK (char_length(question) <= 300),
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    -- A schedule runs every 15 minutes at most and once a day at least; an
    -- incident trigger has no interval.
    CONSTRAINT iris_trigger_schedule CHECK (
        (kind = 'schedule' AND every_minutes BETWEEN 15 AND 1440)
        OR (kind = 'incident' AND every_minutes = 0)),
    -- An incident trigger names at least one condition.
    CONSTRAINT iris_trigger_filter CHECK (
        kind <> 'incident' OR min_severity <> '' OR signature <> '' OR site <> '' OR device_role <> '')
);

CREATE TABLE IF NOT EXISTS iris_investigation_trigger_runs (
    tenant_id         TEXT NOT NULL,
    id                UUID NOT NULL,
    trigger_id        UUID NOT NULL,
    trigger_name      TEXT NOT NULL DEFAULT '' CHECK (char_length(trigger_name) <= 80),
    incident_id       TEXT NOT NULL DEFAULT '' CHECK (char_length(incident_id) <= 100),
    dedupe_key        TEXT NOT NULL CHECK (char_length(dedupe_key) BETWEEN 1 AND 200),
    status            TEXT NOT NULL CHECK (status IN ('running','done','skipped','failed')),
    reason            TEXT NOT NULL DEFAULT '' CHECK (char_length(reason) <= 40),
    investigation_id  TEXT NOT NULL DEFAULT '' CHECK (char_length(investigation_id) <= 64),
    tokens            INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    summary           TEXT NOT NULL DEFAULT '' CHECK (char_length(summary) <= 500),
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, trigger_id, dedupe_key),
    -- A skipped run says why.
    CONSTRAINT iris_trigger_run_skip_reason CHECK (status <> 'skipped' OR reason <> '')
);

CREATE INDEX IF NOT EXISTS iris_trigger_runs_started_idx
    ON iris_investigation_trigger_runs (tenant_id, started_at DESC);

ALTER TABLE iris_investigation_trigger_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_investigation_trigger_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_investigation_trigger_settings;
CREATE POLICY tenant_iso ON iris_investigation_trigger_settings
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE iris_investigation_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_investigation_triggers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_investigation_triggers;
CREATE POLICY tenant_iso ON iris_investigation_triggers
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE iris_investigation_trigger_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_investigation_trigger_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_investigation_trigger_runs;
CREATE POLICY tenant_iso ON iris_investigation_trigger_runs
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
