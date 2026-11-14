-- 0074_iris_chatops.sql — Iris in Slack and Microsoft Teams (tracker 337 N-I6).
--
-- chatops_connections: one tenant's chat app per platform. The opaque
--   webhook_token names the connection (and with it the tenant) on inbound
--   requests; the secrets are sealed by the platform vault before they reach
--   this table and are never returned by the API.
-- chatops_links: chat account → Correlix user, pending until a workspace admin
--   (never the linked user) approves. Only an approved link is answered.
-- chatops_link_codes: the one-time code an unlinked chat user is given; only
--   its tenant-bound SHA-256 is stored, it expires after 15 minutes and one
--   chat account holds at most one.
--
-- RLS: tenant_iso, FORCE, on all three (0036/0071 are the template). The API
-- reads and writes only through WithTenant; the inbound token lookup is the one
-- cross-tenant ('*') read.
-- Additive and idempotent — safe to apply forward.

CREATE TABLE IF NOT EXISTS chatops_connections (
    tenant_id       TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL CHECK (platform IN ('slack','teams')),
    workspace_id    TEXT NOT NULL DEFAULT '' CHECK (char_length(workspace_id) <= 64),
    app_id          TEXT NOT NULL DEFAULT '' CHECK (char_length(app_id) <= 64),
    app_tenant      TEXT NOT NULL DEFAULT '' CHECK (char_length(app_tenant) <= 64),
    webhook_token   TEXT NOT NULL CHECK (char_length(webhook_token) BETWEEN 16 AND 64),
    public_url      TEXT NOT NULL DEFAULT '' CHECK (char_length(public_url) <= 200),
    channel_replies TEXT NOT NULL DEFAULT 'private' CHECK (channel_replies IN ('private','public')),
    enabled         BOOLEAN NOT NULL DEFAULT false,
    signing_secret  TEXT NOT NULL DEFAULT '',
    bot_token       TEXT NOT NULL DEFAULT '',
    app_password    TEXT NOT NULL DEFAULT '',
    updated_by      TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, platform)
);
CREATE UNIQUE INDEX IF NOT EXISTS chatops_connections_token_uq ON chatops_connections (webhook_token);

CREATE TABLE IF NOT EXISTS chatops_links (
    tenant_id    TEXT NOT NULL DEFAULT '',
    id           UUID NOT NULL,
    platform     TEXT NOT NULL CHECK (platform IN ('slack','teams')),
    workspace_id TEXT NOT NULL CHECK (char_length(workspace_id) <= 64),
    chat_user_id TEXT NOT NULL CHECK (char_length(chat_user_id) BETWEEN 1 AND 128),
    chat_name    TEXT NOT NULL DEFAULT '' CHECK (char_length(chat_name) <= 64),
    user_id      TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('pending','approved','revoked')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by   TEXT NOT NULL DEFAULT '',
    decided_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);
-- One live (pending or approved) link per chat account.
CREATE UNIQUE INDEX IF NOT EXISTS chatops_links_active_uq
    ON chatops_links (tenant_id, platform, workspace_id, chat_user_id)
    WHERE status IN ('pending','approved');
CREATE INDEX IF NOT EXISTS chatops_links_user_idx ON chatops_links (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS chatops_link_codes (
    tenant_id    TEXT NOT NULL DEFAULT '',
    code_hash    TEXT NOT NULL CHECK (char_length(code_hash) = 64),
    platform     TEXT NOT NULL CHECK (platform IN ('slack','teams')),
    workspace_id TEXT NOT NULL CHECK (char_length(workspace_id) <= 64),
    chat_user_id TEXT NOT NULL CHECK (char_length(chat_user_id) BETWEEN 1 AND 128),
    chat_name    TEXT NOT NULL DEFAULT '' CHECK (char_length(chat_name) <= 64),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, code_hash)
);
CREATE UNIQUE INDEX IF NOT EXISTS chatops_link_codes_account_uq
    ON chatops_link_codes (tenant_id, platform, workspace_id, chat_user_id);

ALTER TABLE chatops_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE chatops_connections FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON chatops_connections;
CREATE POLICY tenant_iso ON chatops_connections
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE chatops_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE chatops_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON chatops_links;
CREATE POLICY tenant_iso ON chatops_links
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE chatops_link_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE chatops_link_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON chatops_link_codes;
CREATE POLICY tenant_iso ON chatops_link_codes
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
