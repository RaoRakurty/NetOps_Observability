-- 0072_tenant_runbook_reproofs.sql — re-checks of an APPROVED runbook against
-- the current platform (tracker 337 N-F2, "re-run all cases on a model, prompt
-- or tool-schema change").
--
-- A version's own harness result is FROZEN once submitted (0066's trigger) and
-- stays the record of what its reviewers approved. When the platform changes —
-- the models, the system prompt, a tool's contract — the fingerprint moves, the
-- frozen stamp no longer matches, and Iris stops running the runbook. A re-check
-- runs the same cases over the same approved text under the new fingerprint and
-- records the outcome HERE, beside the frozen one, never over it. Iris runs an
-- active version when either its frozen stamp or a passing re-check matches the
-- current fingerprint.
--
-- The text is unchanged and its approval (bound to the text's hash) still
-- holds, so a re-check needs no second person. A failed re-check is recorded so
-- the page can say why the runbook stopped.
--
-- BOUNDS: one row per (version, fingerprint); a re-run under the same
-- fingerprint replaces its row. Only active versions are re-checked, and a
-- runbook has at most 50 versions.
--
-- ISOLATION: FORCE-RLS tenant_iso, like the three 0066 tables.
--
-- Rollback: rollback/0072_tenant_runbook_reproofs.down.sql.

CREATE TABLE IF NOT EXISTS tenant_runbook_reproofs (
    tenant_id   TEXT NOT NULL,
    runbook_id  UUID NOT NULL,
    version     INTEGER NOT NULL CHECK (version >= 1),
    fingerprint TEXT NOT NULL CHECK (fingerprint <> '' AND octet_length(fingerprint) <= 128),
    passed      BOOLEAN NOT NULL,
    cases       INTEGER NOT NULL DEFAULT 0 CHECK (cases >= 0),
    problems    INTEGER NOT NULL DEFAULT 0 CHECK (problems >= 0),
    checked_by  TEXT NOT NULL DEFAULT '',
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, runbook_id, version, fingerprint),
    FOREIGN KEY (tenant_id, runbook_id, version)
        REFERENCES tenant_runbook_versions (tenant_id, runbook_id, version) ON DELETE RESTRICT
);

ALTER TABLE tenant_runbook_reproofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_runbook_reproofs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON tenant_runbook_reproofs;
CREATE POLICY tenant_iso ON tenant_runbook_reproofs
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
