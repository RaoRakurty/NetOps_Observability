-- Rollback of 0057_ai_decision_ledger_tool_contract.sql: drops the two tool
-- contract columns. The rows stay; only latency and truncation are lost.
ALTER TABLE ai_decision_ledger DROP COLUMN IF EXISTS truncated;
ALTER TABLE ai_decision_ledger DROP COLUMN IF EXISTS latency_ms;
DELETE FROM schema_migrations WHERE version = '0057_ai_decision_ledger_tool_contract.sql';
