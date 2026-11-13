-- Rollback for 0071_rca_resolutions.sql.
DROP TABLE IF EXISTS rca_resolutions;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0071_rca_resolutions.sql';
