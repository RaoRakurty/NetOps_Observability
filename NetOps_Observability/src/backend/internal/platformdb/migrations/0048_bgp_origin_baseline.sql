-- 0048_bgp_origin_baseline.sql — the PERSISTED first-seen origin per watched
-- prefix (tracker 281), and the reason a fully propagated origin change is
-- detectable at all.
--
-- WHY IT HAS TO BE STORED. The classifier is pure: it judges one measurement
-- against the tenant's declared intent. With no expected origin declared, which
-- is the shipped default, there was nowhere honest to get a baseline from, so
-- one was re-derived from the CURRENT pass's dominant origin. An origin change
-- that won every vantage point therefore became the baseline in the same pass
-- and classified clean. Only a minority unexpected origin was ever detectable.
-- One row per (tenant, prefix) that does not move between passes is what turns
-- a new origin into a CHANGE.
--
-- WHAT A ROW IS. `source` is the closed vocabulary that keeps a remembered
-- observation ('first_observation', recorded from the first corroborated
-- measurement, confirmed by nobody) distinct from a decision a person made
-- ('operator_accepted', which is how a legitimate re-homing stops alerting).
-- `vantages` is how many distinct collector peers corroborated the set when it
-- was recorded, and it is 0 on an accepted row on purpose: an operator's
-- decision is not a measurement and must not borrow a measurement's authority.
-- `first_seen` is when we first measured the prefix and SURVIVES an accept; the
-- baseline moves, the history of when we started watching does not.
--
-- `origins` is JSONB rather than a column per ASN because a prefix legitimately
-- has more than one origin (anycast, multi-homing) and nothing queries inside
-- it: the api reads the whole row. It is treated as OPAQUE, CALLER-SUPPLIED
-- DATA — validated for shape and bounds at the boundary (bgpwatch's
-- sanitizeBaseline: every ASN parsed and deduped, AS0 refused, the set bounded,
-- the prefix canonicalized) and NEVER interpolated into SQL (§3: stored input
-- is still untrusted input).
--
-- RLS: tenant_iso, FORCE — migrations 0035/0041 are the template, and the api
-- reads and writes exclusively through WithTenant so the row always has its
-- GUC. A baseline is a fact about ONE customer's address space, so the store
-- never runs under the '*' scope even for the platform owner.
--
-- Additive and idempotent — safe to apply forward. Expand only: it adds a table
-- and touches no existing one, so the previous api release runs unchanged
-- against a database that has it (it simply never reads it).

CREATE TABLE IF NOT EXISTS bgp_origin_baseline (
    tenant_id  TEXT NOT NULL DEFAULT '',
    prefix     TEXT NOT NULL CHECK (prefix <> ''),
    origins    JSONB NOT NULL DEFAULT '[]'::jsonb,
    source     TEXT NOT NULL DEFAULT 'first_observation'
        CHECK (source IN ('first_observation', 'operator_accepted')),
    vantages   INTEGER NOT NULL DEFAULT 0 CHECK (vantages >= 0),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, prefix)
);

ALTER TABLE bgp_origin_baseline ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_origin_baseline FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON bgp_origin_baseline;
CREATE POLICY tenant_iso ON bgp_origin_baseline
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
