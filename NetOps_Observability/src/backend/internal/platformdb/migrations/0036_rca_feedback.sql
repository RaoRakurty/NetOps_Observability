-- 0036_rca_feedback.sql — operator VERDICT feedback on an RCA case (Project 2
-- P7). This is the instrument behind the "false-positive RCA rate" success
-- metric and the design-partner loop: an operator who has read a case says
-- whether the engine got it right, and — when it did not — WHICH part was
-- wrong (cause / owner / affected / evidence / recovery).
--
-- Distinct from ai_feedback (0018): that rates an Iris ANSWER; this rates a
-- CORRELATION OBJECT. Distinct from rca_action_items: that is corrective work,
-- this is a judgement about the engine's output.
--
-- Append-only by design: a verdict is an observation at a point in time, never
-- edited. An operator who changes their mind adds a NEW row; the list is
-- newest-first so the latest judgement leads. correlation_version records the
-- object version the operator actually SAW (nullable — an older client, or a
-- caller that did not send one, records an honest NULL rather than a guess).
--
-- top_hypothesis / verdict_tier are copied from the object AT WRITE TIME (they
-- are the engine's own template id and confidence tier). They are denormalized
-- on purpose: the false-positive rate must be attributable to the template the
-- operator judged, and the object may be re-versioned or aged out of ClickHouse
-- long before the feedback is analysed.
--
-- PRIVACY: `reason` is free operator text, capped at 500 chars at the API
-- boundary. It is operator input, never device or user PII harvested by us.
--
-- RLS: tenant_iso, FORCE — migration 0011/0031 is the template; the API reads
-- and writes exclusively through WithTenant so the policy always has its GUC.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS rca_feedback (
    tenant_id           TEXT NOT NULL DEFAULT '',
    id                  UUID NOT NULL,
    correlation_id      UUID NOT NULL,
    verdict             TEXT NOT NULL CHECK (verdict IN ('correct','wrong','partial')),
    -- Which part was wrong. Empty for a 'correct' verdict (enforced at the API
    -- boundary); one of the five RCA claim surfaces otherwise.
    wrong_part          TEXT NOT NULL DEFAULT ''
                        CHECK (wrong_part IN ('','cause','owner','affected','evidence','recovery')),
    reason              TEXT NOT NULL DEFAULT '',
    -- The object version the operator saw. NULL = not supplied (honest unknown).
    correlation_version INTEGER,
    top_hypothesis      TEXT NOT NULL DEFAULT '',
    verdict_tier        TEXT NOT NULL DEFAULT '',
    created_by          TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- Per-case list (newest first) and the windowed summary aggregate.
CREATE INDEX IF NOT EXISTS rca_feedback_case_idx
    ON rca_feedback (tenant_id, correlation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rca_feedback_window_idx
    ON rca_feedback (tenant_id, created_at);

ALTER TABLE rca_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE rca_feedback FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON rca_feedback;
CREATE POLICY tenant_iso ON rca_feedback
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
