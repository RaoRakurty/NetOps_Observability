-- Rollback for 0074_iris_chatops.sql.
DROP TABLE IF EXISTS chatops_link_codes;
DROP TABLE IF EXISTS chatops_links;
DROP TABLE IF EXISTS chatops_connections;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0074_iris_chatops.sql';
