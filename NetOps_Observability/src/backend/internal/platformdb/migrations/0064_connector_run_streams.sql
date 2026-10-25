-- 0064_connector_run_streams.sql — per-stream poll outcomes (NMS-first T1,
-- F10; src/backend/nms/run_integration.go StreamResult).
--
-- One poll run covers many streams (vManage: alarms, events, inventory,
-- approute, bfd, …). Before this column a single failed stream marked the
-- whole run "error" and a dead stream hid behind live ones. streams holds the
-- run's StreamResult list: [{stream, status, error, payloads, durationMs}],
-- status from the closed poll-result set (ok · error · auth_failed ·
-- unreachable · timeout · circuit_open · skipped_deadline). A run is now
-- ok | partial | error; partial counts as an error in connector_health
-- .error_rate and marks the connector unhealthy.
--
-- ISOLATION: connector_run_history already carries the FORCE-RLS tenant_iso
-- policy (0020); a new column inherits it — no policy change. The default
-- '[]' keeps every pre-0064 row readable.
ALTER TABLE connector_run_history
    ADD COLUMN IF NOT EXISTS streams JSONB NOT NULL DEFAULT '[]';
