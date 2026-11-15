-- 0077_flow_declared_sampling.sql — the sampling rate an operator DECLARES for
-- a flow exporter (tracker 401 (c)).
--
-- An exporter that samples but reports no rate reads 1:1 on the Flows page
-- (tracker 387: never guess a rate). A workspace admin who knows the device's
-- configuration (e.g. "1 in 1000") records it here; the flow views then
-- multiply ONLY that exporter's records that carried no reported rate by it,
-- and say "declared, not reported" beside every figure it touched. A rate the
-- exporter does report always wins.
--
-- One row per (tenant, exporter address): two tenants behind one exporter
-- address declare independently. Stamped from the caller's token, never the
-- request body; the API refuses an exporter the workspace does not own.
--
-- RLS: tenant_iso, FORCE (0071 is the template); the API reads and writes
-- exclusively through WithTenant. Additive and idempotent.

CREATE TABLE IF NOT EXISTS flow_declared_sampling (
    tenant_id     TEXT NOT NULL DEFAULT '',
    exporter_addr TEXT NOT NULL CHECK (char_length(exporter_addr) BETWEEN 2 AND 45),
    rate          INTEGER NOT NULL CHECK (rate BETWEEN 2 AND 1000000),
    note          TEXT NOT NULL DEFAULT '' CHECK (char_length(note) <= 200),
    updated_by    TEXT NOT NULL DEFAULT '',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, exporter_addr)
);

ALTER TABLE flow_declared_sampling ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_declared_sampling FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON flow_declared_sampling;
CREATE POLICY tenant_iso ON flow_declared_sampling
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
