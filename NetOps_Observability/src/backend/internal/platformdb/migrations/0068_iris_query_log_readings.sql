-- 0068_iris_query_log_readings.sql — keep the READINGS on each Iris query
-- record (tracker 337 hybrid NLU plan A5).
--
-- `readings` is the list of reinterpretations the compiler applied to the
-- operator's words and disclosed with the answer: a repaired typo ("shwo" →
-- "show"), a severity word read as confirmed incidents, a superlative read as
-- the top 5. Each entry is {from, to, kind} with kind from a closed set; the
-- store bounds the list and every string (internal/irisquerylog). Offline
-- evaluation reads them to see which readings operators then corrected.
--
-- OWNERSHIP: unchanged — 0054's FORCE-RLS tenant_iso policy covers the new
-- column; the store filters principal_sub on top.
--
-- Rollback: rollback/0068_iris_query_log_readings.down.sql.

ALTER TABLE iris_query_log ADD COLUMN IF NOT EXISTS readings JSONB NOT NULL DEFAULT '[]'::jsonb;
