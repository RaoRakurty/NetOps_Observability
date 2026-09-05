-- 0045_tac_templates.sql — the per-tenant TAC command templates (tracker 250,
-- owner 2026-09-05): the command sets a NOC admin saves per vendor dialect and
-- loads into the review step before a TAC collection runs.
--
-- Small (tens per tenant, capped at 200 in the store), write-rare, read on the
-- review step and on the Iris → Knowledge templates tab.
--
-- CORRELIX DEFAULTS ARE NOT ROWS HERE. They are generated from the authored
-- plans (internal/tac/templatedefaults.go), identical for every tenant, and
-- immutable — storing a copy per tenant would let a release and a tenant's copy
-- drift apart, which is the failure this table exists to avoid.
--
-- RLS: tenant_iso, FORCE — migration 0011 is the template; the api reads and
-- writes exclusively through WithTenant so the policy always has its GUC. There
-- is deliberately NO platform-scope consumer: nothing in this feature reads the
-- fleet's templates, so nothing may.
--
-- Shape: identity + the columns a query orders or filters on are typed; the
-- command list and the metadata live in `data` JSONB, which is byte-for-byte the
-- API's Template JSON so both backends answer identically.
--
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS tac_templates (
    tenant_id   TEXT NOT NULL DEFAULT '',
    template_id TEXT NOT NULL,
    -- The CLI dialect the set is written for (arista-eos, cisco-iosxe, …). The
    -- review step offers a template only for the device's own dialect: a set of
    -- EOS commands is meaningless at a Junos router, and offering it would be
    -- the "render another vendor's commands" mistake the plan preview refuses.
    dialect     TEXT NOT NULL,
    name        TEXT NOT NULL,
    -- The Correlix default this set was forked from, when it was. It is what the
    -- Knowledge tab diffs against; empty for a set written from scratch.
    based_on    TEXT NOT NULL DEFAULT '',
    -- Increments on every update, and is stamped into the bundle MANIFEST, so a
    -- stored bundle names the exact revision that ran.
    version     INTEGER NOT NULL DEFAULT 1,
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, template_id)
);

-- The review step asks for one tenant's templates for ONE dialect.
CREATE INDEX IF NOT EXISTS tac_templates_dialect_idx ON tac_templates (tenant_id, dialect);

ALTER TABLE tac_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE tac_templates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON tac_templates;
CREATE POLICY tenant_iso ON tac_templates
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
