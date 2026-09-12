-- Rollback for 0027: drop the rollup-source columns from the snapshot table.
ALTER TABLE incident_time_metrics
    DROP COLUMN IF EXISTS owner,
    DROP COLUMN IF EXISTS state,
    DROP COLUMN IF EXISTS internal,
    DROP COLUMN IF EXISTS group_keys;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0027_incident_time_metrics_rollup_source.sql';
