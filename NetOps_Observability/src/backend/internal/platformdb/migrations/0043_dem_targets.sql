-- 0043_dem_targets.sql — the Digital Experience Monitoring target catalogue
-- (S17, 2026-09-05): the per-tenant set of synthetic checks (ICMP / TCP / DNS /
-- HTTP) whose results become the experience score. Small (tens to a few hundred
-- rows per tenant, capped at 500 in the store), write-rare, read on every page
-- load and on every work-queue projection.
--
-- RLS: tenant_iso, FORCE — migration 0011 is the template; the api reads and
-- writes exclusively through WithTenant so the policy always has its GUC. The
-- projector's fleet-wide read runs under the '*' platform scope, which is the
-- same escape hatch every platform read uses and is unreachable from HTTP.
--
-- Shape: identity + the columns a query orders or filters on are typed; the
-- settings (host, port, resolver, interval, budgets, expected status) live in
-- `data` JSONB, which is byte-for-byte the API's Target JSON so both backends
-- answer identically.
--
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS dem_targets (
    tenant_id  TEXT NOT NULL DEFAULT '',
    target_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    -- The check type. CHECKed here as well as in the store: the store is the
    -- first line, the database is the line that still holds if a future writer
    -- bypasses it.
    kind       TEXT NOT NULL CHECK (kind IN ('icmp','tcp','dns','http')),
    site       TEXT NOT NULL DEFAULT '',
    app        TEXT NOT NULL DEFAULT '',
    -- Paused stops the prober scheduling the target WITHOUT deleting its
    -- history, so a noisy target can be silenced without losing the record.
    paused     BOOLEAN NOT NULL DEFAULT false,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, target_id)
);

-- The projector reads the whole fleet's ACTIVE rows every minute; the page
-- reads one tenant's rows grouped by site.
CREATE INDEX IF NOT EXISTS dem_targets_active_idx ON dem_targets (tenant_id, paused);
CREATE INDEX IF NOT EXISTS dem_targets_site_idx   ON dem_targets (tenant_id, site);

ALTER TABLE dem_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE dem_targets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON dem_targets;
CREATE POLICY tenant_iso ON dem_targets
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
