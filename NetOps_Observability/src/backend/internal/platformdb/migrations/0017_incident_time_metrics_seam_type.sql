-- 0017_incident_time_metrics_seam_type.sql — RCA Time Intelligence #84 tail.
-- Persist the grounded seam TYPE (DIA / SDWAN / VPN / DX / CLOUD_BACKBONE) on the
-- computed phase-metrics snapshot, alongside owner_domain / current_bottleneck.
-- The value already surfaces live on the per-incident response (timeIntelResponse
-- .SeamType, derived from seamTypeFromHypotheses); persisting it lets the backfill
-- power seam-typed reliability rollups without re-parsing the hypotheses blob.
-- Idempotent (IF NOT EXISTS); RLS already on the table from 0014.
ALTER TABLE incident_time_metrics
    ADD COLUMN IF NOT EXISTS seam_type TEXT NOT NULL DEFAULT '';
