-- Rollback for 0067_discovery_scopes.sql. It removes every customer's discovery
-- scope AND the devices those scopes found.
--
-- Why the devices go too: the scans' memory (discovered_devices, 0063) holds one
-- row per (tenant, source, address). A binary older than tenant scopes keys its
-- scan memory by ADDRESS alone and, at restore, keeps only the most recently
-- answered row of an address — so a customer's copy of a box could displace the
-- platform's own copy, which would then vanish from the inventory. Before tenant
-- scopes the SNMP scanner only ever wrote tenant_id '' (the platform), so the
-- rows removed below are exactly the ones tenant scopes created. The platform's
-- rows ('' tenant) are kept. The customers' devices leave their inventories; a
-- re-applied 0067 plus re-created scopes find them again under the same ids.
--
-- discovered_devices is FORCE-RLS: without app.tenant_id = '*' a DELETE run as
-- the application role silently matches nothing. It is set for this session and
-- cleared at the end (a role that bypasses RLS is unaffected either way).
SELECT set_config('app.tenant_id', '*', false);
DELETE FROM discovered_devices WHERE source = 'snmp' AND tenant_id <> '';
SELECT set_config('app.tenant_id', '', false);

DROP TABLE IF EXISTS discovery_scopes;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0067_discovery_scopes.sql';
