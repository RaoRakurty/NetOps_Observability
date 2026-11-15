-- Rollback for 0077_iris_eval_consent.sql.
DROP TABLE IF EXISTS iris_eval_consent;

-- The migrator is FORWARD-ONLY and never removes its own row: leaving it would
-- record the migration as applied against a schema this file just removed.
DELETE FROM schema_migrations WHERE version = '0077_iris_eval_consent.sql';
