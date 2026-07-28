-- Rollback for 0027: drop the rollup-source columns from the snapshot table.
ALTER TABLE incident_time_metrics
    DROP COLUMN IF EXISTS owner,
    DROP COLUMN IF EXISTS state,
    DROP COLUMN IF EXISTS internal,
    DROP COLUMN IF EXISTS group_keys;
