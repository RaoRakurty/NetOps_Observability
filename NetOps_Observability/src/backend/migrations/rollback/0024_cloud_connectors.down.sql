-- ROLLBACK for 0024_cloud_connectors.sql — Cloud Connector framework.
--
-- The migrator is forward-only; rollbacks live here and are applied deliberately
-- by an operator (not embedded, never automatic). Nothing else references these
-- tables, so the drop is self-contained. Any legacy secret ciphertext they held
-- lived in the envelope Vault under per-tenant DEKs; dropping the reference rows
-- orphans that ciphertext (harmless — it is never decryptable without the ref).
--
--   psql "$DATABASE_URL" -f migrations/rollback/0024_cloud_connectors.down.sql

DROP POLICY IF EXISTS tenant_iso ON cloud_connectors;
DROP POLICY IF EXISTS tenant_iso ON cloud_secret_references;

DROP INDEX IF EXISTS cloud_connectors_tenant_idx;
DROP INDEX IF EXISTS cloud_connectors_tenant_prov_idx;
DROP INDEX IF EXISTS cloud_connectors_tenant_state_idx;
DROP INDEX IF EXISTS cloud_secret_refs_tenant_conn_idx;

DROP TABLE IF EXISTS cloud_connectors;
DROP TABLE IF EXISTS cloud_secret_references;

DELETE FROM schema_migrations WHERE version = '0024_cloud_connectors.sql';
