-- Rollback for 0067_discovery_scopes.sql. Dropping the table removes every
-- customer's discovery scope: the platform scan is unaffected, and the devices
-- the scopes found stay in discovered_devices (0063) but leave the inventory at
-- the next sweep, because no scope reports their tenant any more.
DROP TABLE IF EXISTS discovery_scopes;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0067_discovery_scopes.sql';
