-- Rollback for 0069_security_finding_episodes.sql.
--
-- Dropping the episode state is safe: an older binary never reads it, and a
-- newer binary that finds no seed row re-seeds each tenant from the findings
-- store, silently (no burst of "appear" events).
DROP TABLE IF EXISTS security_finding_episode_seeds;
DROP TABLE IF EXISTS security_finding_episodes;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0069_security_finding_episodes.sql';
