-- Rollback for 0038_config_backup.sql.
--
-- NOTE for the operator: dropping these tables removes the INDEX of captured
-- configurations, not the sealed blobs themselves — those live on the platform
-- volume under CONFIG_BACKUP_DIR and become unreferenced. Delete that directory
-- separately if the intent is to remove the stored configurations too.
DROP TABLE IF EXISTS config_drift_state;
DROP TABLE IF EXISTS config_backup_versions;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0038_config_backup.sql';
