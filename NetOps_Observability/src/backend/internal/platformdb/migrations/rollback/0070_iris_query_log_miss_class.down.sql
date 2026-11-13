-- Rollback for 0070_iris_query_log_miss_class.sql. Drops the triage class and
-- the miss records that carried it (source 'ask'); every other record is kept.
-- Run it only together with a rollback of the code that writes this column.
DELETE FROM iris_query_log WHERE source = 'ask';
ALTER TABLE iris_query_log DROP COLUMN IF EXISTS miss_class;

-- The migrator applies each file once and records each version in
-- schema_migrations, and it never removes a row: without this delete a
-- re-apply after rollback would be skipped and the column never recreated.
DELETE FROM schema_migrations WHERE version = '0070_iris_query_log_miss_class.sql';
