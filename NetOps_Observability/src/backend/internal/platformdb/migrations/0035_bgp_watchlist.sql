-- 0035_bgp_watchlist.sql — BGP Operations watchlist (product wave item 10,
-- 2026-08-25): the per-tenant set of prefixes/ASNs the BGP operations page
-- monitors. Resources are the operator's OWN address space — small (tens of
-- rows), write-rare, read-per-page-load.
--
-- RLS: tenant_iso, FORCE — migration 0011 is the template; the api reads and
-- writes exclusively through WithTenant so the policy always has its GUC.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS bgp_watchlist (
    tenant_id  TEXT NOT NULL DEFAULT '',
    -- "193.0.0.0/21" or "AS3333" — validated at the API boundary; kind is
    -- derivable but stored so listing needs no re-parse.
    resource   TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('prefix','asn')),
    note       TEXT NOT NULL DEFAULT '',
    added_by   TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, resource)
);

ALTER TABLE bgp_watchlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_watchlist FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON bgp_watchlist;
CREATE POLICY tenant_iso ON bgp_watchlist
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
