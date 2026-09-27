-- Rollback for 0052_change_ledger.sql.
--
-- NOTE for the operator, in the order it matters:
--
-- 1. Nothing a change record SAYS is lost: every ChangeEvent keeps its full
--    object — actor type, canonical actor, ticket, automation flag included —
--    inside the `data` column, byte-for-byte the API's JSON. What is lost is the
--    ability to FILTER on those fields in the database; the api of the release
--    before this one never did.
--
-- 2. The capture trigger on config_backup_versions IS lost: it is recorded only
--    in that column and in the audit log. Export
--    `SELECT tenant_id, device_id, version_sha, capture_trigger FROM
--    config_backup_versions` first if the intent is a version rollback rather
--    than a feature removal.
--
-- 3. Retention reverts to whatever the older api enforces. Rows the new api
--    already aged out are not restored.
DROP INDEX IF EXISTS dem_change_events_object_idx;
ALTER TABLE dem_change_events DROP CONSTRAINT IF EXISTS dem_change_events_actor_type_check;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS source_system;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS actor;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS actor_type;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS actor_id;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS actor_display;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS object;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS object_kind;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS ticket_ref;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS automation;
ALTER TABLE dem_change_events DROP COLUMN IF EXISTS detected_at;
ALTER TABLE config_backup_versions DROP COLUMN IF EXISTS capture_trigger;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0052_change_ledger.sql';
