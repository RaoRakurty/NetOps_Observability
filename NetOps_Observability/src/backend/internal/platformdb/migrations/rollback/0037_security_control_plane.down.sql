-- Rollback for 0037_security_control_plane.sql.
DROP TABLE IF EXISTS security_saved_views;
DROP TABLE IF EXISTS security_rule_state;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0037_security_control_plane.sql';
