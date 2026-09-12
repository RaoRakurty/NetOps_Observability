-- Rollback for 0044_dem_experience.sql. Drops the declared journeys and the
-- normalized change feed. Nothing derived is lost, because nothing derived was
-- stored: the evidence, hypotheses and incidents are computed from the
-- measurements, the path observations and the producers' own records, all of
-- which live elsewhere and are untouched.
DROP TABLE IF EXISTS dem_change_events;
DROP TABLE IF EXISTS dem_journeys;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0044_dem_experience.sql';
