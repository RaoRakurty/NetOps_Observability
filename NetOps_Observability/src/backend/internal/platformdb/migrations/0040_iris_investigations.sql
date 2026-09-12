-- 0040_iris_investigations.sql — IRIS Phase B INVESTIGATION MEMORY
-- (docs/design/IRIS_TROUBLESHOOTING_MODEL_2026-09-02.md §3.5).
--
-- One row per CONCLUDED investigation: what it was about (device / BGP peer /
-- prefix / correlation case), which skill chain ran, what was concluded, the
-- citation ids that conclusion rested on, and how an OPERATOR judged it.
--
-- Distinct from the two feedback tables it sits beside:
--   * ai_feedback (0018) rates an Iris ANSWER and is deliberately content-free
--     (rating + intent only, no text at all);
--   * rca_feedback (0036) rates a CORRELATION OBJECT — the engine's verdict;
--   * this table remembers an INVESTIGATION so a future one can start from what
--     was already learned about the same entity.
--
-- WHAT IS STORED, AND WHY IT IS SAFE TO STORE IT. `verdict` is the assistant's
-- own narrative — model-written text about the tenant's own network. It is data
-- and only data: it is replayed as an escaped, cited evidence line, it drives no
-- rule, and it is capped at write (600 chars). `citations` are opaque evidence
-- ids the tenant already sees in its own answers. No device output, no log
-- lines, no credentials and no operator prose land here.
--
-- RETENTION. Bounded per tenant IN THE WRITE PATH (oldest conclusions evicted
-- past the store's MaxInvestigationsPerTenant), so this table cannot grow
-- without limit and memory stays recent enough to be relevant.
--
-- RLS: tenant_iso, FORCE — 0018/0036 are the template. The store reads and
-- writes exclusively through WithTenant, so the policy always has its GUC, and
-- a recall with no entity key returns nothing (there is no unscoped list).
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS iris_investigations (
    tenant_id      TEXT NOT NULL DEFAULT '',
    id             UUID NOT NULL,
    -- Entity keys. Any subset may be set; a recall matches on the ones supplied.
    device_id      TEXT NOT NULL DEFAULT '',
    device_name    TEXT NOT NULL DEFAULT '',
    peer           TEXT NOT NULL DEFAULT '',
    prefix         TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    -- The skill chain that produced the conclusion, in order.
    skills         TEXT[] NOT NULL DEFAULT '{}',
    -- The conclusion itself, and the evidence ids it rested on.
    verdict        TEXT NOT NULL,
    citations      TEXT[] NOT NULL DEFAULT '{}',
    -- The operator's judgement. 'unknown' = recorded without one; the CHECK is
    -- the storage half of the closed vocabulary the Go store also enforces.
    outcome        TEXT NOT NULL DEFAULT 'unknown'
                   CHECK (outcome IN ('confirmed','wrong','unknown')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- When the investigation CONCLUDED (when it was judged). This is the recall
    -- ordering key and the retention key — recency of the conclusion is what
    -- matters, not when the question was first asked.
    resolved_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- The three recall shapes (device, case, peer/prefix), each newest-conclusion
-- first, plus the retention sweep's own ordering.
CREATE INDEX IF NOT EXISTS iris_investigations_device_idx
    ON iris_investigations (tenant_id, lower(device_name), resolved_at DESC);
CREATE INDEX IF NOT EXISTS iris_investigations_device_id_idx
    ON iris_investigations (tenant_id, lower(device_id), resolved_at DESC);
CREATE INDEX IF NOT EXISTS iris_investigations_case_idx
    ON iris_investigations (tenant_id, lower(correlation_id), resolved_at DESC);
CREATE INDEX IF NOT EXISTS iris_investigations_peer_idx
    ON iris_investigations (tenant_id, lower(peer), resolved_at DESC);
CREATE INDEX IF NOT EXISTS iris_investigations_prefix_idx
    ON iris_investigations (tenant_id, lower(prefix), resolved_at DESC);
CREATE INDEX IF NOT EXISTS iris_investigations_retention_idx
    ON iris_investigations (tenant_id, resolved_at DESC, id);

ALTER TABLE iris_investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_investigations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_investigations;
CREATE POLICY tenant_iso ON iris_investigations
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
