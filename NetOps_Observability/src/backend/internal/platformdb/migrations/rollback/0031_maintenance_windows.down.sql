-- Rollback for 0031_maintenance_windows.sql.
DROP TABLE IF EXISTS maintenance_windows;
ALTER TABLE incident_time_metrics DROP COLUMN IF EXISTS maintenance;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0031_maintenance_windows.sql';
