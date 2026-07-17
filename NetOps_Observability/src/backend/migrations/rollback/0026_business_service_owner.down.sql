-- Rollback for 0026_business_service_owner.sql
ALTER TABLE business_services DROP COLUMN IF EXISTS owner;
