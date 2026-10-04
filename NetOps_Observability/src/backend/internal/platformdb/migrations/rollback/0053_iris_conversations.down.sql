-- Rollback for 0053_iris_conversations.sql. Conversations are working state:
-- dropping them ends every open conversation (clients start a new one).
DROP TABLE IF EXISTS iris_conversations;

-- The migrator applies each file once and records each version in
-- schema_migrations, and it never removes a row: without this delete a
-- re-apply after rollback would be skipped and the table never recreated.
DELETE FROM schema_migrations WHERE version = '0053_iris_conversations.sql';
