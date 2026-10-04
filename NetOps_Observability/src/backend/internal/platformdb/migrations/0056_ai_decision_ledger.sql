-- 0056_ai_decision_ledger.sql — the Iris AI decision ledger (tracker 337 N-A6,
-- docs/architecture/iris-natural-language-platform.md §5 Phase A; the event
-- vocabulary is Part 1 §35).
--
-- One row per step of one AI decision: the question was received, an
-- investigation started, a plan (a typed query, a next method) was made, the
-- Policy Engine was asked about a tool, a tool ran, evidence was cited, a
-- recommendation was made, the answer was returned. Each row carries the model
-- (provider, model name, router tier) and tool (name, version) that acted, and
-- the SHA-256 of the tool's arguments and of its result — HASHES ONLY. Raw
-- arguments, results, question text, model prose and secrets are never stored:
-- a hash proves WHAT an investigation saw (re-run it, hash it, compare) without
-- the ledger becoming a second copy of tenant data (internal/aidecision).
--
-- APPEND-ONLY, enforced HERE, not by convention:
--   1. UPDATE, DELETE and TRUNCATE are REVOKEd from PUBLIC and from the role
--      running this migration — the migrator connects as the application role
--      that owns the table (0050/0052 explain why), so that IS the app role.
--      A rewrite from the application fails with 42501 (permission denied).
--   2. A trigger refuses UPDATE and DELETE row by row and TRUNCATE per
--      statement. It holds where the REVOKE does not: for a superuser, and
--      after any later blanket GRANT ALL. The table owner could still drop the
--      trigger with DDL — this guards the application's data path, not against
--      a database administrator.
-- RETENTION: none — rows are kept. Removing a period of the ledger is an
-- operator decision (and a compliance one), never something the application
-- can do; there is deliberately no delete path in the store.
--
-- ISOLATION: FORCE-RLS tenant_iso, like every tenant table. The read API is
-- tenant admins (own tenant) and the platform owner (all tenants, '*').
--
-- Rollback: rollback/0056_ai_decision_ledger.down.sql.

CREATE TABLE IF NOT EXISTS ai_decision_ledger (
    tenant_id      TEXT NOT NULL,
    id             UUID NOT NULL,
    decision_id    UUID NOT NULL,
    seq            INTEGER NOT NULL CHECK (seq >= 0),
    event_type     TEXT NOT NULL,
    principal_sub  TEXT NOT NULL,
    surface        TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    incident_ref   TEXT NOT NULL DEFAULT '',
    intent         TEXT NOT NULL DEFAULT '',
    mode           TEXT NOT NULL DEFAULT '',
    skill          TEXT NOT NULL DEFAULT '',
    tool           TEXT NOT NULL DEFAULT '',
    tool_version   TEXT NOT NULL DEFAULT '',
    model_provider TEXT NOT NULL DEFAULT '',
    model_name     TEXT NOT NULL DEFAULT '',
    model_tier     TEXT NOT NULL DEFAULT '',
    args_sha256    TEXT NOT NULL DEFAULT '',
    result_sha256  TEXT NOT NULL DEFAULT '',
    item_count     INTEGER NOT NULL DEFAULT 0 CHECK (item_count >= 0),
    outcome        TEXT NOT NULL DEFAULT '',
    answer_id      TEXT NOT NULL DEFAULT '',
    query_log_id   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, decision_id, seq),
    -- The closed vocabulary: Part 1 §35's sixteen event types plus
    -- ANSWER_RETURNED (the answer the operator was shown). Checked here as well
    -- as in the store, so a future writer that bypasses the store still cannot
    -- invent one.
    CONSTRAINT ai_decision_ledger_event_type_check CHECK (event_type IN (
        'QUESTION_RECEIVED', 'INVESTIGATION_STARTED', 'PLAN_CREATED', 'TOOL_SELECTED',
        'TOOL_EXECUTED', 'EVIDENCE_ADDED', 'HYPOTHESIS_CREATED', 'HYPOTHESIS_REJECTED',
        'ROOT_CAUSE_SELECTED', 'RECOMMENDATION_CREATED', 'ACTION_REQUESTED',
        'POLICY_EVALUATED', 'APPROVAL_RECEIVED', 'EXECUTION_STARTED',
        'VERIFICATION_COMPLETED', 'ROLLBACK_EXECUTED', 'ANSWER_RETURNED')),
    -- Hashes are hashes: 64 lowercase hex, or absent. Nothing else fits.
    CONSTRAINT ai_decision_ledger_args_sha256_check
        CHECK (args_sha256 = '' OR args_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ai_decision_ledger_result_sha256_check
        CHECK (result_sha256 = '' OR result_sha256 ~ '^[0-9a-f]{64}$')
);

-- The read API: one tenant, newest first (keyset on created_at, id).
CREATE INDEX IF NOT EXISTS ai_decision_ledger_recent_idx
    ON ai_decision_ledger (tenant_id, created_at DESC, id);

ALTER TABLE ai_decision_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_decision_ledger FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON ai_decision_ledger;
CREATE POLICY tenant_iso ON ai_decision_ledger
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

-- (1) No rewrite grant for anyone, the owning application role included.
REVOKE UPDATE, DELETE, TRUNCATE ON ai_decision_ledger FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON ai_decision_ledger FROM CURRENT_USER;

-- (2) The trigger that still holds where a grant does not.
CREATE OR REPLACE FUNCTION ai_decision_ledger_append_only() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'ai_decision_ledger is append-only: % refused', TG_OP
        USING ERRCODE = '42501';
END
$fn$;

DROP TRIGGER IF EXISTS ai_decision_ledger_no_rewrite ON ai_decision_ledger;
CREATE TRIGGER ai_decision_ledger_no_rewrite
    BEFORE UPDATE OR DELETE ON ai_decision_ledger
    FOR EACH ROW EXECUTE FUNCTION ai_decision_ledger_append_only();

DROP TRIGGER IF EXISTS ai_decision_ledger_no_truncate ON ai_decision_ledger;
CREATE TRIGGER ai_decision_ledger_no_truncate
    BEFORE TRUNCATE ON ai_decision_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION ai_decision_ledger_append_only();
