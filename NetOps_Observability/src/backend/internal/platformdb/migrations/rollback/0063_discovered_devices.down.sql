-- Rollback for 0063_discovered_devices.sql. The rows are what the SNMP sweep
-- has found: dropping them only means the next boot starts from an empty scan
-- memory, so a device that is not answering at that moment leaves the
-- inventory until it answers again (the pre-0063 behaviour).
DROP TABLE IF EXISTS discovered_devices;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0063_discovered_devices.sql';
