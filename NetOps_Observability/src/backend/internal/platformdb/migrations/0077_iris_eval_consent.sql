-- 0077_iris_eval_consent.sql — who agreed to share their Iris questions with
-- their workspace's eval set (tracker 337 N-H3, consented pooling).
--
-- One row per (tenant, person). Opt-in, default off: no row means not
-- consented. A row is written only by the person themselves (the API takes the
-- principal from the token); revoking sets consented = false and takes effect
-- at the next export, because the export reads this table at export time.
--
-- RLS: tenant_iso, FORCE — the API reads and writes exclusively through
-- WithTenant so the policy always has its GUC.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS iris_eval_consent (
    tenant_id   TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 128),
    principal   TEXT NOT NULL CHECK (char_length(principal) BETWEEN 1 AND 256),
    consented   BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, principal)
);

CREATE INDEX IF NOT EXISTS iris_eval_consent_on_idx
    ON iris_eval_consent (tenant_id) WHERE consented;

ALTER TABLE iris_eval_consent ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_eval_consent FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_eval_consent;
CREATE POLICY tenant_iso ON iris_eval_consent
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
