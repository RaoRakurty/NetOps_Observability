-- 0041_bgp_alert_policy.sql — the per-tenant BGP ALERT POLICY (BGP ops tracker
-- rows #5/#10): which origin ASNs a tenant expects to announce its watched
-- prefixes, which upstreams it buys transit from, and the two detection
-- thresholds. It is the DECLARED INTENT the watchlist evaluator classifies
-- against; the verdicts themselves are derived on every pass and are never
-- stored here.
--
-- Shape: ONE row per tenant, the policy as JSONB. It is a small, write-rare,
-- read-per-evaluation document with no per-field query need — the same shape
-- and the same reasoning as security_saved_views.filters (migration 0037). The
-- blob is treated as OPAQUE, CALLER-SUPPLIED DATA: it is validated for size and
-- shape at the API boundary (bgpwatch.TenantPolicy.Normalize — every ASN
-- parsed, every prefix key canonicalized, both sets bounded) and is NEVER
-- interpolated into SQL (§3: stored input is still untrusted input).
--
-- RLS: tenant_iso, FORCE — migration 0035 (bgp_watchlist) is the template, and
-- the API reads and writes exclusively through WithTenant so the policy always
-- has its GUC. Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS bgp_alert_policy (
    tenant_id  TEXT NOT NULL DEFAULT '',
    policy     JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id)
);

ALTER TABLE bgp_alert_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_alert_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON bgp_alert_policy;
CREATE POLICY tenant_iso ON bgp_alert_policy
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
