-- 0053_iris_conversations.sql — Iris conversations (tracker 337 N-C7,
-- docs/architecture/iris-natural-language-platform.md §4.1.3).
--
-- The server-held state a follow-up question refers to ("that device", "what
-- else did they change"). What is stored is STRUCTURED REFERENCES — the last
-- validated query, entity ids, actors, change ids — plus each turn's question
-- and outcome; never model prose, and nothing the client can supply
-- (internal/irisconvo).
--
-- OWNERSHIP: one conversation belongs to one principal (owner_sub) in one
-- tenant scope. RLS confines every statement to the tenant; the store also
-- filters on owner_sub, so a colleague in the same tenant cannot read or
-- extend someone else's conversation (ErrNotFound, never a distinct refusal).
--
-- BOUNDS: turns per conversation and conversations per owner are capped by the
-- store; conversations idle for more than 7 days are deleted by the store on
-- write, inside the writing tenant's transaction.
--
-- Rollback: rollback/0053_iris_conversations.down.sql.

CREATE TABLE IF NOT EXISTS iris_conversations (
    tenant_id   TEXT NOT NULL,
    id          UUID NOT NULL,
    owner_sub   TEXT NOT NULL,
    turns       JSONB NOT NULL DEFAULT '[]'::jsonb,
    state       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS iris_conversations_owner_idx
    ON iris_conversations (tenant_id, owner_sub, updated_at DESC);
CREATE INDEX IF NOT EXISTS iris_conversations_retention_idx
    ON iris_conversations (tenant_id, updated_at);

ALTER TABLE iris_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_conversations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_conversations;
CREATE POLICY tenant_iso ON iris_conversations
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
