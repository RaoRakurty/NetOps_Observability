-- Rollback for 0075_iris_investigation_triggers.sql.
DROP TABLE IF EXISTS iris_investigation_trigger_runs;
DROP TABLE IF EXISTS iris_investigation_triggers;
DROP TABLE IF EXISTS iris_investigation_trigger_settings;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0075_iris_investigation_triggers.sql';
