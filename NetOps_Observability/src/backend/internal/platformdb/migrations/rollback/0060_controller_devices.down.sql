-- Rollback for 0060_controller_devices.sql. The rows are a mirror of what the
-- controllers report: dropping them only means the next complete inventory
-- poll rebuilds them (the devices leave the inventory until then).
DROP TABLE IF EXISTS controller_devices;

-- The migrator never removes a schema_migrations row: without this delete a
-- re-apply after rollback would be skipped.
DELETE FROM schema_migrations WHERE version = '0060_controller_devices.sql';
