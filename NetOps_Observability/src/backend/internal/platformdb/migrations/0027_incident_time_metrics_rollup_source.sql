-- 0027_incident_time_metrics_rollup_source.sql — RCA Time Intelligence #84 final tail.
-- Make the persisted phase-metric snapshot a COMPLETE rollup source, so the
-- reliability rollups (/api/reliability/rollups|trends|chronic-offenders) can read
-- persisted rows instead of a live ClickHouse scan capped at 5000 (which silently
-- under-reported once history exceeded the cap — a truthfulness problem).
--
-- The rollup needs, per incident: the raw seam owner (owner filter), the object
-- state (merged children are excluded from MTBF), the internal/platform flag
-- (customer-impacting default excludes platform self-monitoring), and the grouping
-- keys (device/interface/provider/signature → MTBF spacing, chronic offenders,
-- dimension filters). All four are derived by the backfill from the corr object and
-- were previously dropped on write. Rows written before this migration carry the
-- defaults until the next backfill pass upserts them (15m ticker, or
-- POST /api/reliability/time-metrics).
-- Idempotent (IF NOT EXISTS); RLS already FORCE-enabled on the table from 0014.
ALTER TABLE incident_time_metrics
    ADD COLUMN IF NOT EXISTS owner      TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS state      TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS internal   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS group_keys JSONB   NOT NULL DEFAULT '{}'::jsonb;
