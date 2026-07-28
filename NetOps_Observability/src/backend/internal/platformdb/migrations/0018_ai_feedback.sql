-- 0018_ai_feedback.sql — Iris AI feedback loop (HLD Phase 5 / spec §14, §16).
-- Persists thumbs up/down on AI answers so answer quality can be measured over
-- time (the "feedback loop"). PRIVACY BY DESIGN: it stores only the rating + the
-- intent/mode/conversation id — NEVER the question text, the answer, evidence, or
-- any PII (same stance as the AI audit line). Tenant-isolated (tenant_iso FORCE
-- RLS on app.tenant_id) like every other tenant table.
CREATE TABLE IF NOT EXISTS ai_feedback (
    tenant_id       TEXT NOT NULL DEFAULT '',
    id              TEXT NOT NULL,
    conversation_id TEXT NOT NULL DEFAULT '',
    sub             TEXT NOT NULL DEFAULT '',           -- the rater (user id); not PII beyond identity
    intent          TEXT NOT NULL DEFAULT '',
    mode            TEXT NOT NULL DEFAULT '',
    rating          TEXT NOT NULL,                       -- up | down
    at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS ai_feedback_at_idx ON ai_feedback (tenant_id, at);

ALTER TABLE ai_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_feedback FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON ai_feedback;
CREATE POLICY tenant_iso ON ai_feedback
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
