-- 0037_security_control_plane.sql — the small MUTABLE control-plane state behind
-- the Security (CTEM) surface, per
-- docs/design/SECURITY_FINDINGS_STORE_DECISION_2026-08-28.md.
--
-- The DURABLE findings store is OpenSearch (netops-secfindings-<seg>-*): findings
-- are immutable, time-stamped, append-heavy verdicts, read through
-- TenantIndexPattern + TenantFilter. What does NOT belong there is the handful of
-- rows an operator EDITS: which detection rules their tenant runs, and the filter
-- sets they saved. Those are mutable, tiny, relational and per-tenant — the PG
-- FORCE-RLS half of the split the decision record picks explicitly.
--
-- security_rule_state — per-tenant enable/disable for one catalog rule id
--   (hardening rules + seam-aware exposure probes + threatlane detections +
--   advisory providers). ABSENT means DEFAULT-ON: the catalog ships enabled, so
--   a tenant that has never touched the page runs the full ruleset and the table
--   stays empty. Only a deliberate override is stored, which also means a new
--   catalog rule is live for everyone the moment it ships (no backfill, and no
--   silent "not enabled because nobody inserted a row" gap — the failure mode
--   that would read as "we assessed you" while assessing nothing).
--   updated_by/updated_at are the audit shoulder: who last changed the ruleset.
--
-- security_saved_views — a named filter set for the findings list. `filters` is
--   JSONB and is treated as OPAQUE, CALLER-SUPPLIED DATA: it is validated for
--   size and shape at the API boundary and is NEVER interpolated into SQL or a
--   query DSL without going back through the same validated filter parser a URL
--   goes through (§3 zero trust — stored input is still untrusted input).
--
-- RLS: tenant_iso, FORCE — migration 0011/0031/0036 is the template. The API
-- reads and writes exclusively through WithTenant so the policy always has its
-- GUC. Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS security_rule_state (
    tenant_id   TEXT NOT NULL DEFAULT '',
    rule_id     TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, rule_id)
);

CREATE TABLE IF NOT EXISTS security_saved_views (
    id          UUID NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    filters     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- One view name per tenant: the list is a picker, and two identically named
-- views are indistinguishable to the operator who has to choose between them.
CREATE UNIQUE INDEX IF NOT EXISTS security_saved_views_name_idx
    ON security_saved_views (tenant_id, lower(name));

ALTER TABLE security_rule_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_rule_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON security_rule_state;
CREATE POLICY tenant_iso ON security_rule_state
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE security_saved_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_saved_views FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON security_saved_views;
CREATE POLICY tenant_iso ON security_saved_views
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
