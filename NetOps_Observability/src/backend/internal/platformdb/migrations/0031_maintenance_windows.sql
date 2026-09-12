-- 0031_maintenance_windows.sql — maintenance windows (tracker item 121, the
-- #53 remnant: "no maintenance handling in the alert path").
--
-- One row per declared window. Typed columns carry identity/lifecycle; the
-- data JSONB blob carries the full window shape (scope lists, one-shot bounds,
-- recurring schedule) — the wireless-inventory storage pattern (0030). The
-- schedule is evaluated in Go (maintenance.Window.Covers); SQL never needs to
-- reason about recurrence.
--
-- Also adds the `maintenance` stamp to incident_time_metrics (0027 precedent:
-- additive rollup-source column). timeintel.IncidentSummary.Maintenance existed
-- since the rollup spec but NOTHING ever set it — MTBF and chronic-offender
-- math counted every planned reboot as an unplanned failure. The backfill now
-- stamps each snapshot by asking the window store "was this incident's
-- occurred_at inside a covering window?".
--
-- RLS: tenant_iso, FORCE — migration 0011 is the template; identical to 0024.
-- Additive migration — safe to apply forward.

CREATE TABLE IF NOT EXISTS maintenance_windows (
    tenant_id  TEXT NOT NULL DEFAULT '',
    window_id  UUID NOT NULL,
    name       TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, window_id)
);
CREATE INDEX IF NOT EXISTS maintenance_windows_enabled_idx
    ON maintenance_windows (tenant_id, enabled);

ALTER TABLE maintenance_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE maintenance_windows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON maintenance_windows;
CREATE POLICY tenant_iso ON maintenance_windows
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

-- Idempotent (IF NOT EXISTS); RLS already FORCE-enabled on the table from 0014.
ALTER TABLE incident_time_metrics
    ADD COLUMN IF NOT EXISTS maintenance BOOLEAN NOT NULL DEFAULT FALSE;
