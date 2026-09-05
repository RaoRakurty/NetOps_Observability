-- Rollback for 0046_metering_daily.sql. Drops the metering history. Nothing
-- else depends on it: no entitlement, gate or admission path reads this table,
-- so removing it costs the usage report its history and nothing more.
DROP TABLE IF EXISTS metering_daily;
