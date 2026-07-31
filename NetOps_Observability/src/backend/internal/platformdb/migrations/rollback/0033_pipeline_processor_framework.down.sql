-- Rollback for 0033_pipeline_processor_framework.sql.
DROP TABLE IF EXISTS managed_rule_state;
DROP TABLE IF EXISTS processor_versions;
DROP INDEX IF EXISTS pipeline_processors_order_idx;
ALTER TABLE pipeline_processors
    DROP COLUMN IF EXISTS rule_order,
    DROP COLUMN IF EXISTS version,
    DROP COLUMN IF EXISTS source;
