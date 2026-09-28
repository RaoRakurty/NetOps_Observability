-- Rollback for 0054_iris_query_log.sql. The query log is evaluation telemetry:
-- dropping it loses recorded questions and operator corrections (export them
-- first if an evaluation run still needs them).
DROP TABLE IF EXISTS iris_query_log;

-- The migrator applies each file once and records each version in
-- schema_migrations, and it never removes a row: without this delete a
-- re-apply after rollback would be skipped and the table never recreated.
DELETE FROM schema_migrations WHERE version = '0054_iris_query_log.sql';
