-- 0042_security_framework_state.sql — WHICH COMPLIANCE FRAMEWORKS A TENANT HAS
-- OPTED INTO (owner direction, 2026-09-03: "compliance is analyzed per customer
-- requirement" — the platform must not assess every framework for everybody).
--
-- The companion of 0037's security_rule_state, and deliberately the OPPOSITE
-- default. A DETECTION ships enabled, because a rule nobody enabled would read
-- as "nothing is wrong" while nothing ran. A FRAMEWORK ships mostly OFF, because
-- a scorecard for a regulation the customer is not subject to is noise at best
-- and an implied compliance claim at worst. The shipped default set is stated in
-- code (compliancemodel.DefaultEnabled) rather than seeded here, so a tenant with
-- NO rows means "has not chosen" and gets the default — the same no-backfill
-- property 0037 has, in the other direction.
--
-- ROW SEMANTICS. A row is written for EVERY known framework the moment a tenant
-- saves a selection (enabled true AND false), so "this tenant has configured its
-- frameworks" is observable as "this tenant has at least one row". Without that,
-- a tenant that deliberately turned everything off would be indistinguishable
-- from one that never chose, and would silently get the defaults back.
--
-- framework_id is the stable, VERSIONED slug from internal/compliancemodel
-- (nist-800-53-r5, cis-controls-v8, nist-csf-2.0, hipaa-security-rule,
-- pci-dss-v4). The API refuses an id outside that closed vocabulary, so this
-- table cannot grow rows nothing ever reads.
--
-- RLS: tenant_iso, FORCE — migration 0011/0031/0036/0037 is the template. The
-- API reads and writes exclusively through WithTenant so the policy always has
-- its GUC. Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS security_framework_state (
    tenant_id    TEXT NOT NULL DEFAULT '',
    framework_id TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by   TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, framework_id)
);

ALTER TABLE security_framework_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_framework_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON security_framework_state;
CREATE POLICY tenant_iso ON security_framework_state
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
