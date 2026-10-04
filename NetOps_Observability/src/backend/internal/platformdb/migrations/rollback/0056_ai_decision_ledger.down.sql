-- Rollback for 0056_ai_decision_ledger.sql.
--
-- NOTE for the operator: this DESTROYS the AI decision ledger — it is an audit
-- record and nothing else holds it. Export it first if it may ever be needed:
--   COPY (SELECT * FROM ai_decision_ledger ORDER BY tenant_id, created_at, seq)
--     TO STDOUT WITH CSV HEADER;
-- (run with app.tenant_id = '*' set, or as a role that bypasses RLS).
--
-- DROP TABLE is DDL, not DELETE, so the append-only REVOKE and trigger do not
-- stand in its way; dropping the table drops its triggers with it.
DROP TABLE IF EXISTS ai_decision_ledger;
DROP FUNCTION IF EXISTS ai_decision_ledger_append_only();

-- The migrator is FORWARD-ONLY: db.go records each applied file in
-- schema_migrations and never removes a row. Without this delete a re-apply
-- after rollback would be skipped and the table never recreated.
DELETE FROM schema_migrations WHERE version = '0056_ai_decision_ledger.sql';
