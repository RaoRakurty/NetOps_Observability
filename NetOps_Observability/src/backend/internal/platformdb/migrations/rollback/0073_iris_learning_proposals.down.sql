-- Rollback for 0073_iris_learning_proposals.sql.
DROP TABLE IF EXISTS iris_learning_proposals;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0073_iris_learning_proposals.sql';
