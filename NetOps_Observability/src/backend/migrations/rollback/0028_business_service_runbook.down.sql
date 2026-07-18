-- Rollback for 0028_business_service_runbook.sql
ALTER TABLE business_services DROP COLUMN IF EXISTS runbook_url;
