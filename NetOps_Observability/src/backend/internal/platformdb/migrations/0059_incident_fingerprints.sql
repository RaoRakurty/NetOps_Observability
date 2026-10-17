-- 0059_incident_fingerprints.sql — historical incident intelligence (tracker
-- 337 N-F4, internal/incidentfp).
--
-- One fingerprint per incident: what it looked like (signature, domain, seam,
-- entities, causal-chain kinds, symptom kinds), so "have we seen this
-- before?" does not rebuild every past incident's analysis. Written through
-- when a fingerprint is computed for a CLOSED incident; an open incident's
-- fingerprint is never stored (it can still change).
--
-- ISOLATION: FORCE-RLS tenant_iso. Recall reads only the subject incident's own
-- tenant.
--
-- Rollback: rollback/0059_incident_fingerprints.down.sql.

CREATE TABLE IF NOT EXISTS incident_fingerprints (
    tenant_id      TEXT NOT NULL,
    correlation_id TEXT NOT NULL CHECK (octet_length(correlation_id) BETWEEN 1 AND 128),
    fp_version     INTEGER NOT NULL CHECK (fp_version >= 1),
    fingerprint    JSONB NOT NULL,
    signature      TEXT NOT NULL DEFAULT '',
    chain_key      TEXT NOT NULL DEFAULT '',
    occurred_at    TIMESTAMPTZ,
    computed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, correlation_id)
);

CREATE INDEX IF NOT EXISTS incident_fingerprints_signature_idx
    ON incident_fingerprints (tenant_id, signature);
CREATE INDEX IF NOT EXISTS incident_fingerprints_chain_idx
    ON incident_fingerprints (tenant_id, chain_key);

ALTER TABLE incident_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_fingerprints FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON incident_fingerprints;
CREATE POLICY tenant_iso ON incident_fingerprints
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
