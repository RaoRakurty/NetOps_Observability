-- Rollback for 0040_iris_investigations.sql.
--
-- NOTE for the operator: this drops the assistant's INVESTIGATION MEMORY — the
-- record of which prior conclusions an operator confirmed or rejected. Nothing
-- else depends on it (Iris degrades to answering with no prior context, which is
-- its pre-Phase-B behaviour), but the operator judgements themselves are not
-- recoverable from any other table: ai_feedback keeps the rating without the
-- investigation, and rca_feedback judges the engine's verdict, not the
-- assistant's. Export first if that history matters.
DROP TABLE IF EXISTS iris_investigations;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0040_iris_investigations.sql';
