-- Rollback for 0043_dem_targets.sql. Drops the DEM target catalogue; the
-- experience time series in VictoriaMetrics are unaffected and simply stop
-- being produced once no target is projected.
DROP TABLE IF EXISTS dem_targets;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0043_dem_targets.sql';
