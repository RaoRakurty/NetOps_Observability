-- 0046_metering_daily.sql — the METERING data contract (tracker 258, owner
-- strategy 2026-09-05): one row per (UTC day, tenant) recording what the
-- installation actually consumed.
--
-- This is deliberately NOT the licence. Entitlement ("what is this customer
-- allowed to do?") is a signed file read by internal/entitlement; metering
-- ("what did they actually use?") is these rows. Nothing gates on this table:
-- no admission path reads it, and a metering outage can only lose a usage
-- report, never refuse a device.
--
-- RLS: tenant_iso, FORCE — migration 0011 is the template; the api reads and
-- writes exclusively through WithTenant so the policy always has its GUC.
--
-- THE INSTALLATION ROW. tenant_id = '' holds the meters that describe the whole
-- installation (tenant and org counts, the configured retention windows, the
-- pipeline-wide diagnostic counters). A tenant id is never empty, so the policy
-- predicate `tenant_id = current_setting('app.tenant_id')` never matches it for
-- a tenant-scoped read: only the '*' platform scope sees those rows, which is
-- the isolation posture they need — how many tenants an installation has is the
-- provider's number, not a tenant's.
--
-- Shape: the identity and the columns a query orders, ranges or counts on are
-- typed; the meters live in `data` JSONB, which is byte-for-byte the API's
-- DailyRecord JSON so the file backend and this one answer identically.
--
-- Retention is bounded to 400 daily rows (metering.RetentionDays), swept by the
-- api's own prune. Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS metering_daily (
    tenant_id  TEXT NOT NULL DEFAULT '',
    -- The UTC day key, YYYY-MM-DD. TEXT rather than DATE so the ordering, the
    -- range predicate and the API's day keys are one representation with no
    -- conversion anywhere; the CHECK is what keeps it a real day.
    day        TEXT NOT NULL CHECK (day ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'),
    -- How many hourly snapshots folded into the row. A reader can tell a full
    -- day from one where the api was down for twenty hours.
    samples    INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, day)
);

-- Every read is a day RANGE (a report period), across one tenant or all of
-- them; the prune is a range over every tenant.
CREATE INDEX IF NOT EXISTS metering_daily_day_idx ON metering_daily (day);

ALTER TABLE metering_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE metering_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON metering_daily;
CREATE POLICY tenant_iso ON metering_daily
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
