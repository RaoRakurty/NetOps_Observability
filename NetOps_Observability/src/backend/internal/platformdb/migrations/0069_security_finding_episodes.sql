-- 0069_security_finding_episodes.sql — per-tenant finding-EPISODE state for the
-- security lane's findings-on-change emission (owner decision D2, 2026-11-11;
-- internal/seclane/episodes.go).
--
-- The lane scans every interval and still writes every scan's verdicts to the
-- findings store (OpenSearch netops-secfindings-<seg>-*, the audit trail). What
-- it sends the CORRELATION ENGINE is only the transitions: a finding that
-- appears, changes or clears. Telling a transition from a re-confirmation needs
-- the last verdict the engine was told about, and that state must survive an
-- api restart — otherwise every restart would re-announce every standing
-- finding as new. This is that state: mutable, small, relational and
-- per-tenant, the PG FORCE-RLS half of the findings-store split (0037).
--
-- security_finding_episodes — one row per OPEN episode.
--   native_id        the finding identity (secbus.nativeIDOf: tenant, evidence
--                    class, control, subject device, finding id) — the same key
--                    the findings store collapses current state on.
--   first_seen       when the current episode opened (basis 'observed'), or the
--                    earliest retained verdict when tracking started with the
--                    episode already open (basis 'seed').
--   subject          the last verdict's classification: the material fields a
--                    change is detected on (severity, verdict, seam exposure)
--                    and what a clear event is built from. Producer-generated,
--                    bounded in Go (8 KiB cap), no config excerpt, no log line.
--   A closed episode is DELETED: absence means "not open".
--
-- security_finding_episode_seeds — one row per tenant whose change tracking has
--   started. A tenant without one is seeded from the findings store before its
--   first classified scan, so an upgrade never emits a wave of "appear" events.
--
-- RLS: tenant_iso, FORCE — 0037 is the template. The lane reads and writes only
-- through WithTenant(<scanned tenant>, cross=false), and every statement also
-- carries an explicit tenant_id predicate. The platform/global tenant is never
-- scanned, so a platform-owned row is refused outright. Additive and idempotent.

CREATE TABLE IF NOT EXISTS security_finding_episodes (
    tenant_id         TEXT NOT NULL,
    native_id         TEXT NOT NULL,
    first_seen        TIMESTAMPTZ NOT NULL,
    first_seen_basis  TEXT NOT NULL DEFAULT 'observed',
    subject           JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, native_id),
    CONSTRAINT security_finding_episodes_owner CHECK (tenant_id <> '' AND tenant_id <> 'global'),
    CONSTRAINT security_finding_episodes_basis CHECK (first_seen_basis IN ('observed', 'seed')),
    CONSTRAINT security_finding_episodes_nid CHECK (length(native_id) BETWEEN 1 AND 512),
    CONSTRAINT security_finding_episodes_subject CHECK (jsonb_typeof(subject) = 'object')
);

CREATE TABLE IF NOT EXISTS security_finding_episode_seeds (
    tenant_id  TEXT NOT NULL PRIMARY KEY,
    source     TEXT NOT NULL,
    seeded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT security_finding_episode_seeds_owner CHECK (tenant_id <> '' AND tenant_id <> 'global'),
    CONSTRAINT security_finding_episode_seeds_source CHECK (source IN ('index', 'scan'))
);

ALTER TABLE security_finding_episodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_finding_episodes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON security_finding_episodes;
CREATE POLICY tenant_iso ON security_finding_episodes
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE security_finding_episode_seeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_finding_episode_seeds FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON security_finding_episode_seeds;
CREATE POLICY tenant_iso ON security_finding_episode_seeds
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
