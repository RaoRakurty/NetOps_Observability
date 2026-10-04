-- 0055_iris_query_log_query.sql — keep the validated query on each Iris query
-- record (tracker 337 N-C5: GET /api/ai/query/{id} and /explain,
-- docs/architecture/iris-natural-language-platform.md §4.3).
--
-- `query` is the VALIDATED (constrained) CorrelixQueryAST v1 the question
-- compiled to, in its canonical encoding — NULL when nothing validated. It is
-- the query, never its result: rows, series points and model prose are still
-- never stored. `compiled_by` says who wrote it: 'grammar' (the deterministic
-- question grammar), 'model' (the guarded model fallback — disclosed on every
-- read) or 'supplied' (a client-supplied query, the execute API); '' when there
-- is no query. The store enforces both (internal/irisquerylog), and decodes the
-- stored query strictly on every read.
--
-- OWNERSHIP: unchanged — 0054's FORCE-RLS tenant_iso policy covers the new
-- columns; the store filters principal_sub on top.
--
-- Rollback: rollback/0055_iris_query_log_query.down.sql.

ALTER TABLE iris_query_log ADD COLUMN IF NOT EXISTS query JSONB;
ALTER TABLE iris_query_log ADD COLUMN IF NOT EXISTS compiled_by TEXT NOT NULL DEFAULT '';
