-- Rollback for 0079_device_baselines.sql.
DROP TABLE IF EXISTS device_baselines;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0079_device_baselines.sql';
