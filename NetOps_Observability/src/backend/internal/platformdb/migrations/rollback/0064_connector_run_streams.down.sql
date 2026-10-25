-- Rollback for 0064_connector_run_streams.sql. Dropping the column loses only
-- the per-stream detail of past runs; run status, error and counts stay.
ALTER TABLE connector_run_history DROP COLUMN IF EXISTS streams;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0064_connector_run_streams.sql';
