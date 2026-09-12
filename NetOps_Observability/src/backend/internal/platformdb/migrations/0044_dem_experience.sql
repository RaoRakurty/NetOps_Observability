-- 0044_dem_experience.sql — the Digital Experience causality domain's two
-- PERSISTED objects (S17 slice 1, 2026-09-05):
--
--   dem_journeys       the workflows an operator declared (branching graph,
--                      business importance, SLO, step→target bindings). Small
--                      (tens per tenant, capped at 100 in the store),
--                      write-rare, read on every experience page load.
--   dem_change_events  the normalized "what changed" feed from every producer
--                      (config capture/drift, cloud, BGP, deployments, flags).
--                      Append-only and IMMUTABLE: a change is a fact, and the
--                      insert is ON CONFLICT DO NOTHING so a replayed producer
--                      cannot rewrite history.
--
-- Everything else in the domain — evidence, hypotheses, incidents, scores — is
-- DERIVED from immutable facts at read time and is deliberately NOT stored:
-- there is then no window in which a stored conclusion contradicts the evidence
-- beneath it. See docs/design/dem-architecture.md.
--
-- RLS: tenant_iso, FORCE — migration 0011/0043 are the template; the api reads
-- and writes exclusively through WithTenant so the policy always has its GUC.
--
-- Shape: identity plus the columns a query orders or filters on are typed; the
-- object itself lives in `data` JSONB, byte-for-byte the API's JSON, so the
-- Postgres and file backends answer identically.
--
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS dem_journeys (
    tenant_id  TEXT NOT NULL DEFAULT '',
    journey_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    app        TEXT NOT NULL DEFAULT '',
    -- Business importance drives triage order and the coverage model. CHECKed
    -- here as well as in the store: the store is the first line, the database
    -- is the line that still holds if a future writer bypasses it.
    importance TEXT NOT NULL DEFAULT 'normal'
        CHECK (importance IN ('critical','high','normal','low')),
    -- Version increments on every definition change; an observation records the
    -- version it traversed, so a redesign never silently rewrites history.
    version    INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, journey_id)
);

CREATE INDEX IF NOT EXISTS dem_journeys_app_idx ON dem_journeys (tenant_id, app);

ALTER TABLE dem_journeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE dem_journeys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON dem_journeys;
CREATE POLICY tenant_iso ON dem_journeys
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS dem_change_events (
    tenant_id   TEXT NOT NULL DEFAULT '',
    change_id   TEXT NOT NULL,
    change_type TEXT NOT NULL CHECK (change_type IN (
        'APPLICATION_DEPLOY','CONFIG_CHANGE','FEATURE_FLAG_CHANGE','CLOUD_CHANGE',
        'NETWORK_CHANGE','SECURITY_POLICY_CHANGE','DNS_CHANGE','ROUTE_CHANGE',
        'INFRASTRUCTURE_CHANGE')),
    app         TEXT NOT NULL DEFAULT '',
    site        TEXT NOT NULL DEFAULT '',
    -- event_at is when the CHANGE happened, not when we learned of it. The
    -- distinction is the whole basis of the change-before-effect rule, so it is
    -- the indexed column rather than a field inside the JSON.
    event_at    TIMESTAMPTZ NOT NULL,
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, change_id)
);

-- The incident view reads one tenant's changes over a bounded lookback, newest
-- first; that is the only access pattern this table has.
CREATE INDEX IF NOT EXISTS dem_change_events_time_idx ON dem_change_events (tenant_id, event_at DESC);

ALTER TABLE dem_change_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE dem_change_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON dem_change_events;
CREATE POLICY tenant_iso ON dem_change_events
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
