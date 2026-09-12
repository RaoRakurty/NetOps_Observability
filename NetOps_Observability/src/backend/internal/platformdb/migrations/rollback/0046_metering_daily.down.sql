-- Rollback for 0046_metering_daily.sql. Drops the metering history. Nothing
-- else depends on it: no entitlement, gate or admission path reads this table,
-- so removing it costs the usage report its history and nothing more.
DROP TABLE IF EXISTS metering_daily;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0046_metering_daily.sql';
