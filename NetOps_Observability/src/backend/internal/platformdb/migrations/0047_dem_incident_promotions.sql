-- 0047_dem_incident_promotions.sql — the durable link between a DERIVED
-- experience incident and the platform incident record it was promoted into
-- (tracker 255; design docs/design/DEM_2026-09-05.md §M.2).
--
-- WHY A TABLE AT ALL, when §M.2's whole point is that experience incidents are
-- derived at read time and never stored. Because a PROMOTION is not a
-- derivation: it is an operator's decision that a particular window was real,
-- and a decision is a fact. What is stored here is exactly that fact plus the
-- evidence packet AS IT STOOD when the decision was made — never a conclusion
-- that will be recomputed. The live derivation still governs what the screen
-- shows; `data` is what the operator acted on, so a later disagreement between
-- the two is REPORTABLE (experience.DriftSince) rather than invisible.
--
-- The incident LIFECYCLE (status, assignment, ticketing, resolution) lives in
-- `incidents` with source_type = 'experience'. It is deliberately NOT duplicated
-- here: two owners for one lifecycle is how drift starts.
--
-- RLS: tenant_iso, FORCE — migrations 0011/0043/0044 are the template; the api
-- reads and writes exclusively through WithTenant so the policy always has its
-- GUC.
--
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS dem_incident_promotions (
    tenant_id     TEXT NOT NULL DEFAULT '',
    -- experience_id is the DERIVED incident's deterministic id (tenant + kind +
    -- subject + window start). It is both the join key and the dedup key, which
    -- is what makes promoting the same window twice fold into one incident
    -- instead of raising a second.
    experience_id TEXT NOT NULL,
    -- incident_id is the row in `incidents`. NOT NULL and non-empty: a
    -- promotion that cannot name its incident is not a promotion.
    incident_id   TEXT NOT NULL CHECK (incident_id <> ''),
    severity      TEXT NOT NULL DEFAULT ''
        CHECK (severity IN ('', 'info', 'low', 'medium', 'high', 'critical')),
    promoted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    promoted_by   TEXT NOT NULL DEFAULT '',
    -- The frozen evidence packet, byte-for-byte the API's JSON, so the Postgres
    -- and file backends answer identically.
    data          JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, experience_id)
);

-- The only access pattern besides the point lookup: one tenant's promotions,
-- newest first, for the Incidents surface.
CREATE INDEX IF NOT EXISTS dem_incident_promotions_time_idx
    ON dem_incident_promotions (tenant_id, promoted_at DESC);
-- And the reverse join: given a platform incident, which experience window did
-- it come from.
CREATE INDEX IF NOT EXISTS dem_incident_promotions_incident_idx
    ON dem_incident_promotions (tenant_id, incident_id);

ALTER TABLE dem_incident_promotions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dem_incident_promotions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON dem_incident_promotions;
CREATE POLICY tenant_iso ON dem_incident_promotions
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
