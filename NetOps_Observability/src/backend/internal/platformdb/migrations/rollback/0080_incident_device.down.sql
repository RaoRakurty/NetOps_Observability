-- Rollback for 0080_incident_device.sql.
ALTER TABLE incidents DROP COLUMN IF EXISTS device_id;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0080_incident_device.sql';
