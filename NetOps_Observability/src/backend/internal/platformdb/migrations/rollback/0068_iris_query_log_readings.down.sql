-- Rollback for 0068_iris_query_log_readings.sql. Drops the stored readings;
-- the records themselves (0054/0055) are kept. Run it only together with a
-- rollback of the code that reads this column.
ALTER TABLE iris_query_log DROP COLUMN IF EXISTS readings;

-- The migrator applies each file once and records each version in
-- schema_migrations, and it never removes a row: without this delete a
-- re-apply after rollback would be skipped and the column never recreated.
DELETE FROM schema_migrations WHERE version = '0068_iris_query_log_readings.sql';
