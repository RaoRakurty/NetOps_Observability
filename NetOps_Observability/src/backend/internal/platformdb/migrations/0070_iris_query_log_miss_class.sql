-- 0070_iris_query_log_miss_class.sql — the Iris miss triage (tracker 337,
-- model-first decision point 5, owner 2026-11-13).
--
-- Every non-data Iris answer that left the operator with nothing is recorded
-- in the existing query log (source 'ask', outcome 'miss') with WHY it missed:
-- miss_class is one of the closed set no_tool / no_data / wrong_route /
-- wrong_tool / wording / provider_error (internal/iristriage). The admin-only
-- triage view folds these with the data arm's own records, so the fix for a
-- family of questions is a tool, data or a route — never a phrase regex.
--
-- OWNERSHIP: unchanged — 0054's FORCE-RLS tenant_iso policy covers the new
-- column; the store filters principal_sub on top. Retention and the per-tenant
-- cap (irisquerylog.Retention / MaxPerTenant) bound these rows like every
-- other record.
--
-- Rollback: rollback/0070_iris_query_log_miss_class.down.sql.

ALTER TABLE iris_query_log ADD COLUMN IF NOT EXISTS miss_class TEXT NOT NULL DEFAULT '';
