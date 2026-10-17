-- Rollback for 0058_org_context.sql. Dropping the store removes every
-- customer-written fact and its history; Iris then answers without them.
DROP TABLE IF EXISTS org_context_versions;
DROP TABLE IF EXISTS org_context_docs;
DROP FUNCTION IF EXISTS org_context_versions_guard();

-- The migrator records each applied file and never removes a row: without
-- this delete a re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0058_org_context.sql';
