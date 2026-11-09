-- Rollback for 0065_iris_source_authority.sql. Every tenant's custom order is
-- lost; Iris then answers with the platform default order.
DROP TABLE IF EXISTS iris_source_authority;

-- The migrator records each applied file and never removes a row: without
-- this delete a re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0065_iris_source_authority.sql';
