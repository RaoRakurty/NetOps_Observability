-- 0057_ai_decision_ledger_tool_contract.sql — Iris tool contract v2 (tracker
-- 337 N-A8). Every tool call is ledgered with how long it took and whether its
-- result was cut to fit; a call that timed out, was rate-limited, or whose
-- output failed its declared schema is recorded with that outcome.
--
-- Additive: two columns with constant defaults. An ADD COLUMN is DDL, so the
-- 0056 append-only trigger (UPDATE/DELETE/TRUNCATE) does not fire, existing
-- rows read latency 0 / not truncated, and FORCE-RLS tenant_iso is unchanged.
--
-- Rollback: rollback/0057_ai_decision_ledger_tool_contract.down.sql.

ALTER TABLE ai_decision_ledger
    ADD COLUMN IF NOT EXISTS latency_ms INTEGER NOT NULL DEFAULT 0
        CONSTRAINT ai_decision_ledger_latency_check CHECK (latency_ms >= 0);

ALTER TABLE ai_decision_ledger
    ADD COLUMN IF NOT EXISTS truncated BOOLEAN NOT NULL DEFAULT false;
