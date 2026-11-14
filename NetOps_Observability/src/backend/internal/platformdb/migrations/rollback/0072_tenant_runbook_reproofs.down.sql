-- Rollback for 0072_tenant_runbook_reproofs.sql. Dropping it removes the
-- re-check results only: every approved runbook keeps its frozen proof, and one
-- whose proof predates a platform change simply stops running until it is
-- re-checked (or resubmitted) on a version that has this table again.
DROP TABLE IF EXISTS tenant_runbook_reproofs;

-- The migrator records each applied file and never removes a row: without
-- this delete a re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0072_tenant_runbook_reproofs.sql';
