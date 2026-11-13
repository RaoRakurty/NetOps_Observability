-- 0071_rca_resolutions.sql — HOW an RCA case was resolved (tracker 337 N-F4
-- residue). When an operator closes a case they may record what fixed it, from
-- a closed vocabulary, with an optional short note and the linked change id.
-- Similar-incident recall then says "last time this was fixed by …" as
-- HISTORICAL evidence — never a claim about the present cause.
--
-- Distinct from rca_feedback (0036: was the engine right?) and from
-- rca_action_items (work still to do): a resolution is what already happened.
--
-- Append-only: an operator who corrects themselves adds a NEW row and the
-- newest leads (bounded at the API, MaxPerCase = 20).
--
-- PRIVACY: `note` is operator text, ≤ 500 characters, refused at the API when it
-- carries control or invisible characters. It is never copied into audit
-- details or sent to an AI provider (only the kind is).
--
-- RLS: tenant_iso, FORCE — 0036/0059 are the template; the API reads and writes
-- exclusively through WithTenant so the policy always has its GUC.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS rca_resolutions (
    tenant_id      TEXT NOT NULL DEFAULT '',
    id             UUID NOT NULL,
    correlation_id UUID NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('config_rollback','hardware_replace','provider_ticket',
                                                 'reboot','routing_change','capacity_add',
                                                 'no_action_transient','other')),
    note           TEXT NOT NULL DEFAULT '' CHECK (char_length(note) <= 500),
    change_id      TEXT NOT NULL DEFAULT '' CHECK (char_length(change_id) <= 64),
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- Newest resolution per case (the recall's read and the per-case list).
CREATE INDEX IF NOT EXISTS rca_resolutions_case_idx
    ON rca_resolutions (tenant_id, correlation_id, created_at DESC);

ALTER TABLE rca_resolutions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rca_resolutions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON rca_resolutions;
CREATE POLICY tenant_iso ON rca_resolutions
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
