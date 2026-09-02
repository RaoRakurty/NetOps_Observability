-- Rollback for 0038_config_backup.sql.
--
-- NOTE for the operator: dropping these tables removes the INDEX of captured
-- configurations, not the sealed blobs themselves — those live on the platform
-- volume under CONFIG_BACKUP_DIR and become unreferenced. Delete that directory
-- separately if the intent is to remove the stored configurations too.
DROP TABLE IF EXISTS config_drift_state;
DROP TABLE IF EXISTS config_backup_versions;
