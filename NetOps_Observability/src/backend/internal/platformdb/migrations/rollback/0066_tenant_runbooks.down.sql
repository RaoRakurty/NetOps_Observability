-- Rollback for 0066_tenant_runbooks.sql. Dropping the store removes every
-- customer-written runbook, its history and its links; Iris then runs only the
-- compiled methods.
--
-- 0072's re-check table references tenant_runbook_versions, so it goes first,
-- and its migration row with it: otherwise a re-apply would skip 0072 and leave
-- the store without the table its reads expect.
DROP TABLE IF EXISTS tenant_runbook_reproofs;
DELETE FROM schema_migrations WHERE version = '0072_tenant_runbook_reproofs.sql';
DROP TABLE IF EXISTS tenant_runbook_links;
DROP TABLE IF EXISTS tenant_runbook_versions;
DROP TABLE IF EXISTS tenant_runbooks;
DROP FUNCTION IF EXISTS tenant_runbook_versions_guard();

-- The migrator records each applied file and never removes a row: without
-- this delete a re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0066_tenant_runbooks.sql';
