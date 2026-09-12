-- ROLLBACK for 0023_service_path_graph.sql — Service Path Graph, contract v1.
--
-- The repo's migrator is forward-only (db.go applies migrations/*.sql in lexical
-- order and records them in schema_migrations). Rollbacks therefore live HERE, in
-- migrations/rollback/, and are applied deliberately by an operator — they are not
-- embedded (the //go:embed pattern is `migrations/*.sql`, which does not match this
-- subdirectory) and never run automatically. Nothing else in the schema references
-- these tables, so the drop is self-contained.
--
-- POSTGRES half — run against the app database as the app role:
--
--   psql "$DATABASE_URL" -f migrations/rollback/0023_service_path_graph.down.sql
--
-- After it completes, delete the migration's row so a later re-apply is possible:
--
--   DELETE FROM schema_migrations WHERE version = '0023_service_path_graph.sql';
--   (included below)

DROP POLICY IF EXISTS tenant_iso ON path_endpoints;
DROP POLICY IF EXISTS tenant_iso ON path_definitions;

DROP INDEX IF EXISTS path_endpoints_tenant_idx;
DROP INDEX IF EXISTS path_endpoints_addr_idx;
DROP INDEX IF EXISTS path_endpoints_run_idx;
DROP INDEX IF EXISTS path_definitions_tenant_idx;
DROP INDEX IF EXISTS path_definitions_dst_idx;
DROP INDEX IF EXISTS path_definitions_run_idx;

DROP TABLE IF EXISTS path_endpoints;
DROP TABLE IF EXISTS path_definitions;

DELETE FROM schema_migrations WHERE version = '0023_service_path_graph.sql';

-- ---------------------------------------------------------------------------
-- CLICKHOUSE half (the immutable observation/hop streams). ClickHouse DDL is
-- converged on boot by path_schema.go → ensureCHRowPolicies(), so a rollback must
-- ALSO remove the pathSchemaDDL() call from clickhouse_policies.go (or ship an API
-- image that predates it) — otherwise the next API start recreates the tables.
--
-- Run against ClickHouse (tenant_scope=__all__ so no row policy filters the DDL):
--
--   curl -u "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" \
--        "$CLICKHOUSE_URL/?tenant_scope=__all__" --data-binary @- <<'SQL'
--   DROP ROW POLICY IF EXISTS tenant_iso_path_observations ON netops.path_observations;
--   DROP ROW POLICY IF EXISTS tenant_iso_path_hops ON netops.path_hops;
--   DROP ROW POLICY IF EXISTS tenant_iso_corr_path_edges ON netops.corr_path_edges;
--   DROP TABLE IF EXISTS netops.path_hops;
--   DROP TABLE IF EXISTS netops.path_observations;
--   DROP TABLE IF EXISTS netops.corr_path_edges;
--   SQL
--
-- corr_path_edges is the §5 TYPED-edge table the correlation engine writes behind
-- CORR_EDGES_V2=true. Dropping it WITHOUT unsetting that flag makes every engine
-- persist fail on the insert: set CORR_EDGES_V2=false FIRST, then drop. The legacy
-- netops.corr_edges table is untouched by this migration and keeps working — that
-- is exactly why the typed edges got their own table instead of a column overload.
--
-- DATA LOSS: the observation history is the point of the contract (§2.3). Export
-- before dropping if the history matters:
--
--   SELECT * FROM netops.path_observations FORMAT Parquet  →  path_observations.parquet
--   SELECT * FROM netops.path_hops         FORMAT Parquet  →  path_hops.parquet
-- ---------------------------------------------------------------------------
