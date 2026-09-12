-- Rollback for 0033_pipeline_processor_framework.sql.
DROP TABLE IF EXISTS managed_rule_state;
DROP TABLE IF EXISTS processor_versions;
DROP INDEX IF EXISTS pipeline_processors_order_idx;
ALTER TABLE pipeline_processors
    DROP COLUMN IF EXISTS rule_order,
    DROP COLUMN IF EXISTS version,
    DROP COLUMN IF EXISTS source;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0033_pipeline_processor_framework.sql';
