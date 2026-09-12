-- ROLLBACK for 0024_business_service.sql — Business Service mapping.
--
-- The repo's migrator is forward-only (db.go applies migrations/*.sql in lexical
-- order and records them in schema_migrations). Rollbacks live HERE and are run
-- deliberately by an operator — never embedded, never automatic. Nothing else in
-- the schema references these tables, so the drop is self-contained.
--
--   psql "$DATABASE_URL" -f migrations/rollback/0024_business_service.down.sql
--
-- DATA LOSS: this discards every manual resource→service override an operator
-- confirmed. Export first if that mapping matters:
--   \copy (SELECT * FROM resource_mappings) TO 'resource_mappings.csv' CSV HEADER

DROP POLICY IF EXISTS tenant_iso ON resource_mappings;
DROP POLICY IF EXISTS tenant_iso ON business_services;

DROP INDEX IF EXISTS resource_mappings_svc_idx;
DROP INDEX IF EXISTS business_services_name_idx;

DROP TABLE IF EXISTS resource_mappings;
DROP TABLE IF EXISTS business_services;

DELETE FROM schema_migrations WHERE version = '0024_business_service.sql';
