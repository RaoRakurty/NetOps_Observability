-- 0024_cloud_connectors.sql — multi-tenant Cloud Connector framework (Phase 2).
--
-- Two tenant-owned tables, both FORCE-RLS under the tenant_iso policy (app.tenant_id):
--   cloud_connectors         — the connector: identity metadata, scopes, capability,
--                              lifecycle state, and SEPARATE identity/telemetry health.
--                              Stores NO plaintext secrets — only trust metadata
--                              (role ARN, client/tenant id, workload-identity provider,
--                              audience, issuer, ExternalId, cert thumbprint, SA email).
--   cloud_secret_references  — vault-backed handle for UNAVOIDABLE legacy secrets
--                              (static access key / SA key / client secret). Holds the
--                              envelope-Vault CIPHERTEXT (v1:...) + non-secret metadata
--                              only. Only the Identity Broker decrypts it.
--
-- Provider account/subscription/project ids are NOT globally unique, so every
-- key/constraint LEADS with tenant_id. The opaque ccn_/csr_ ids are the identity keys.
-- Connector security events are recorded in the existing audit_events trail
-- (audit.go / audit_pg.go) — no separate audit table is created here.

CREATE TABLE IF NOT EXISTS cloud_connectors (
    tenant_id        TEXT NOT NULL DEFAULT '',
    connector_id     TEXT NOT NULL,                 -- ccn_<opaque>
    provider         TEXT NOT NULL,                 -- aws | azure | gcp
    display_name     TEXT NOT NULL DEFAULT '',      -- human label; NEVER an identity key
    auth_method      TEXT NOT NULL DEFAULT '',      -- workload_identity_federation | cloud_role | ...
    pack_full_id     TEXT NOT NULL DEFAULT '',      -- immutable capability pack, e.g. aws-observer-v1
    state            TEXT NOT NULL DEFAULT 'DRAFT', -- lifecycle state
    identity         JSONB NOT NULL DEFAULT '{}'::jsonb,  -- trust metadata (NO secrets)
    scopes           JSONB NOT NULL DEFAULT '[]'::jsonb,  -- collection scopes
    identity_health  JSONB NOT NULL DEFAULT '{}'::jsonb,  -- can we authenticate? (separate)
    telemetry_health JSONB NOT NULL DEFAULT '{}'::jsonb,  -- is data flowing? (separate)
    last_validation  JSONB NOT NULL DEFAULT '{}'::jsonb,  -- last validation findings
    row_version      BIGINT NOT NULL DEFAULT 1,     -- optimistic concurrency (If-Match)
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, connector_id)
);
CREATE INDEX IF NOT EXISTS cloud_connectors_tenant_idx      ON cloud_connectors (tenant_id);
CREATE INDEX IF NOT EXISTS cloud_connectors_tenant_prov_idx ON cloud_connectors (tenant_id, provider);
CREATE INDEX IF NOT EXISTS cloud_connectors_tenant_state_idx ON cloud_connectors (tenant_id, state);

CREATE TABLE IF NOT EXISTS cloud_secret_references (
    tenant_id     TEXT NOT NULL DEFAULT '',
    secret_ref    TEXT NOT NULL,                    -- csr_<opaque>
    connector_id  TEXT NOT NULL,
    provider      TEXT NOT NULL,
    kind          TEXT NOT NULL,                    -- aws_secret_access_key | azure_client_secret | gcp_sa_key
    ciphertext    TEXT NOT NULL DEFAULT '',         -- envelope-Vault ciphertext (v1:...) — NEVER plaintext
    fields_set    TEXT[] NOT NULL DEFAULT '{}',     -- which secret fields are populated
    key_hint      TEXT NOT NULL DEFAULT '',         -- non-secret (AccessKeyId / SA key id) for age/rotation display
    secret_version BIGINT NOT NULL DEFAULT 1,       -- bumped on rotation (overlap-friendly)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, secret_ref)
);
CREATE INDEX IF NOT EXISTS cloud_secret_refs_tenant_conn_idx ON cloud_secret_references (tenant_id, connector_id);

-- FORCE-RLS tenant isolation (identical predicate to every other tenant_iso table,
-- keyed off the app.tenant_id GUC set by withTenant; '*' = platform owner).
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['cloud_connectors','cloud_secret_references'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso ON %I', t);
        EXECUTE format($f$CREATE POLICY tenant_iso ON %I
            USING (current_setting('app.tenant_id', true) = '*'
                OR tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (current_setting('app.tenant_id', true) = '*'
                OR tenant_id = current_setting('app.tenant_id', true))$f$, t);
    END LOOP;
END $$;
