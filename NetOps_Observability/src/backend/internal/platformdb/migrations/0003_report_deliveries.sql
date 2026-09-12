-- 0003_report_deliveries.sql — per-recipient delivery outcomes, so a report
-- retry can resend only to recipients that previously failed (not the whole
-- group). One row per (execution, recipient); once 'ok' it stays 'ok'. Same
-- audit_events RLS pattern.
CREATE TABLE IF NOT EXISTS report_execution_deliveries (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT '',
    execution_id TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    channel      TEXT NOT NULL DEFAULT 'email',
    status       TEXT NOT NULL DEFAULT 'failed', -- ok | failed
    attempt      INT  NOT NULL DEFAULT 1,
    error        TEXT,
    at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (execution_id, recipient)
);
CREATE INDEX IF NOT EXISTS report_execution_deliveries_exec_idx
    ON report_execution_deliveries (execution_id);
ALTER TABLE report_execution_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_execution_deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON report_execution_deliveries;
CREATE POLICY tenant_iso ON report_execution_deliveries
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));
