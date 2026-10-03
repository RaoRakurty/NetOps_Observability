-- Rollback for 0055_iris_query_log_query.sql. Drops the stored queries and
-- their authors; the records themselves (0054) are kept. Run it only together
-- with a rollback of the code that reads these columns.
ALTER TABLE iris_query_log DROP COLUMN IF EXISTS compiled_by;
ALTER TABLE iris_query_log DROP COLUMN IF EXISTS query;

-- The migrator applies each file once and records each version in
-- schema_migrations, and it never removes a row: without this delete a
-- re-apply after rollback would be skipped and the columns never recreated.
DELETE FROM schema_migrations WHERE version = '0055_iris_query_log_query.sql';
