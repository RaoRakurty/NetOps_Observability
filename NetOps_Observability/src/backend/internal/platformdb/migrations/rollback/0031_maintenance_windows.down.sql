-- Rollback for 0031_maintenance_windows.sql.
DROP TABLE IF EXISTS maintenance_windows;
ALTER TABLE incident_time_metrics DROP COLUMN IF EXISTS maintenance;
