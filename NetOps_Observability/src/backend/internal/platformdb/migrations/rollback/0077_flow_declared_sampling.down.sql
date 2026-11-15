-- Rollback for 0077_flow_declared_sampling.sql.
DROP TABLE IF EXISTS flow_declared_sampling;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0077_flow_declared_sampling.sql';
