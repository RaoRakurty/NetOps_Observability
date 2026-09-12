-- Rollback for 0030_wireless_inventory.sql — drops the wireless canonical
-- inventory (tracker #128 Phase 1). Order is children-first (indexes ride the
-- tables). Wireless telemetry in ClickHouse/VictoriaMetrics is NOT touched —
-- this reverses only the Postgres inventory.
DROP TABLE IF EXISTS bssids;
DROP TABLE IF EXISTS wlans;
DROP TABLE IF EXISTS ssids;
DROP TABLE IF EXISTS ap_radios;
DROP TABLE IF EXISTS access_points;
DROP TABLE IF EXISTS wireless_controller_members;
DROP TABLE IF EXISTS wireless_controllers;

-- The migrator is FORWARD-ONLY: db.go applies migrations/*.sql in lexical order
-- and records each version in schema_migrations, and it never removes a row.
-- Leaving the row behind is what makes a rollback silently unrecoverable — the
-- migration is still recorded as applied, so it never re-applies, and the API
-- boots HEALTHY against the schema this file just took away.
DELETE FROM schema_migrations WHERE version = '0030_wireless_inventory.sql';
