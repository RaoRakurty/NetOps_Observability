-- 0054_iris_query_log.sql — Iris query capture + operator corrections
-- (tracker 337 N-C8, docs/architecture/iris-natural-language-platform.md,
-- Part 2 §22).
--
-- One row per compiled question: who asked, the question text (clipped), the
-- intent, the outcome, the query's hash and catalog version, the validator's
-- error codes, the entities resolved and how, row/series COUNTS, duration and
-- which surface answered. Result rows and model prose are NEVER stored.
-- `corrections` holds the operator's "that's not what I meant" entries (a
-- closed kind, an optional corrected query that was validated in the caller's
-- scope, a clipped note) — for OFFLINE evaluation only; nothing reads them back
-- into the compiler (internal/irisquerylog).
--
-- OWNERSHIP: RLS confines every statement to the tenant. Reads are the
-- principal's own rows (a tenant admin may list the tenant's); a correction is
-- accepted only on the principal's own row (the store filters principal_sub).
--
-- BOUNDS: rows older than 30 days, and a tenant's rows past its cap, are
-- deleted by the store on write, inside the writing tenant's transaction;
-- corrections per row are capped by the store under a row lock.
--
-- Rollback: rollback/0054_iris_query_log.down.sql.

CREATE TABLE IF NOT EXISTS iris_query_log (
    tenant_id        TEXT NOT NULL,
    id               UUID NOT NULL,
    principal_sub    TEXT NOT NULL,
    conversation_id  UUID,
    source           TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    question         TEXT NOT NULL DEFAULT '',
    intent           TEXT NOT NULL DEFAULT '',
    outcome          TEXT NOT NULL,
    query_type       TEXT NOT NULL DEFAULT '',
    ast_hash         TEXT NOT NULL DEFAULT '',
    catalog_version  TEXT NOT NULL DEFAULT '',
    validation_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
    entities         JSONB NOT NULL DEFAULT '[]'::jsonb,
    row_count        INTEGER NOT NULL DEFAULT 0,
    series_count     INTEGER NOT NULL DEFAULT 0,
    duration_ms      BIGINT NOT NULL DEFAULT 0,
    corrections      JSONB NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS iris_query_log_principal_idx
    ON iris_query_log (tenant_id, principal_sub, created_at DESC);
CREATE INDEX IF NOT EXISTS iris_query_log_retention_idx
    ON iris_query_log (tenant_id, created_at DESC, id);

ALTER TABLE iris_query_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE iris_query_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON iris_query_log;
CREATE POLICY tenant_iso ON iris_query_log
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
