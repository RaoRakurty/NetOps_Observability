-- 0007_integration_configs.sql — per-tenant, per-provider integration config for
-- the bidirectional control plane (docs/design §5). Holds the INBOUND settings
-- the outbound itsm_config kv blob doesn't: sync_mode, webhook enablement, the
-- opaque per-tenant webhook path token, the signing secret, and per-tenant state
-- map overrides. (Connector credentials stay in itsm_config for now; the full
-- merge is a later step — see the design's P5.)
--
-- webhook_secret is plaintext today; it moves under the #17 swtpm AES-GCM envelope
-- when that lands (the column name/seam is final). RLS-isolated like the rest.

CREATE TABLE IF NOT EXISTS integration_configs (
    tenant_id       TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL,                 -- servicenow | jira | pagerduty | slack
    enabled         BOOLEAN NOT NULL DEFAULT false,
    sync_mode       TEXT NOT NULL DEFAULT 'outbound', -- outbound | bidirectional
    webhook_enabled BOOLEAN NOT NULL DEFAULT false,
    webhook_token   TEXT NOT NULL DEFAULT '',      -- opaque per-tenant path token (globally unique)
    webhook_secret  TEXT NOT NULL DEFAULT '',      -- signing secret (write-only via API; #17 envelope later)
    state_map       JSONB NOT NULL DEFAULT '{}'::jsonb, -- external-state -> internal-state overrides
    status          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, provider)
);

-- The webhook endpoint is UNAUTHENTICATED (external systems can't carry our JWT);
-- it resolves (tenant, provider, secret) from this token, so it must be unique
-- across all tenants. Looked up at platform scope.
CREATE UNIQUE INDEX IF NOT EXISTS integration_configs_token_idx
    ON integration_configs (webhook_token)
    WHERE webhook_token <> '';

ALTER TABLE integration_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON integration_configs;
CREATE POLICY tenant_iso ON integration_configs
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));
