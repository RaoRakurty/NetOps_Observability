-- Rollback for 0076_iris_action_requests.sql.
DROP TABLE IF EXISTS iris_action_requests;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0076_iris_action_requests.sql';
