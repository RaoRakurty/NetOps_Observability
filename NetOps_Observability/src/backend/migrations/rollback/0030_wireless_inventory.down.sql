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
