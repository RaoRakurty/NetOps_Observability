-- Rollback for 0062_platform_owner_alias.sql. Dropping the alias only narrows:
-- the Provider scope ('global') stops seeing the platform's '' rows; tenant_iso
-- is untouched, so no tenant gains or loses a row. Run with the app on a build
-- older than tracker 365 (where Provider was cross-tenant), or the Provider view
-- loses its untagged rows until the migration is re-applied.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'incidents',
        'incident_events',
        'seams',
        'seam_groups',
        'topology_nodes',
        'topology_edges',
        'config_backup_versions',
        'config_drift_state',
        'metering_daily',
        'saved_objects'
    ]
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS platform_alias ON public.%I', t);
    END LOOP;
END $$;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0062_platform_owner_alias.sql';
