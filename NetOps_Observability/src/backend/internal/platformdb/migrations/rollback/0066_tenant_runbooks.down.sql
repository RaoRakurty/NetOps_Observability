-- Rollback for 0066_tenant_runbooks.sql. Dropping the store removes every
-- customer-written runbook, its history and its links; Iris then runs only the
-- compiled methods.
DROP TABLE IF EXISTS tenant_runbook_links;
DROP TABLE IF EXISTS tenant_runbook_versions;
DROP TABLE IF EXISTS tenant_runbooks;
DROP FUNCTION IF EXISTS tenant_runbook_versions_guard();

-- The migrator records each applied file and never removes a row: without
-- this delete a re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0066_tenant_runbooks.sql';
