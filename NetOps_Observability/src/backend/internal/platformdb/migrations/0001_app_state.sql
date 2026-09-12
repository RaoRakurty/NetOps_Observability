-- 0001_app_state.sql — normalized app-state with Row-Level Security (M0).
--
-- Each former blob store becomes a row-per-entity table. Tenant-scoped tables
-- carry a tenant_id column + RLS so the database refuses another tenant's rows
-- even if an app-layer filter is ever forgotten. The full object lives in a
-- JSONB `data` column (we filter/sort on the typed columns), so we get per-row
-- isolation without remapping every Go struct field up front.
--
-- The RLS policy reads the per-transaction GUC app.current_tenant (set by
-- db.go withTenant): '*' = platform owner (all rows); otherwise exact tenant.
-- current_setting(..., true) returns NULL when unset → denies (fail closed).

-- ---- helper: standard tenant policy is inlined per table below ----

-- tenants registry (a tenant sees its own row; the platform owner sees all).
CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT GENERATED ALWAYS AS (id) STORED,   -- self-scope for the policy
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON tenants;
CREATE POLICY tenant_iso ON tenants
    USING (current_setting('app.current_tenant', true) = '*'
        OR id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR id = current_setting('app.current_tenant', true));

-- users
CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,                 -- username
    tenant_id  TEXT NOT NULL DEFAULT '',
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS users_tenant_idx ON users (tenant_id);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON users;
CREATE POLICY tenant_iso ON users
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- api_keys
CREATE TABLE IF NOT EXISTS api_keys (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL DEFAULT '',
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON api_keys;
CREATE POLICY tenant_iso ON api_keys
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- saved_objects (searches / dashboards)
CREATE TABLE IF NOT EXISTS saved_objects (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL DEFAULT '',
    type       TEXT NOT NULL DEFAULT '',
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saved_objects_tenant_idx ON saved_objects (tenant_id);
ALTER TABLE saved_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_objects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON saved_objects;
CREATE POLICY tenant_iso ON saved_objects
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- snmp_credentials (secrets — RLS is the backstop under the app layer)
CREATE TABLE IF NOT EXISTS snmp_credentials (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL DEFAULT '',
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS snmp_credentials_tenant_idx ON snmp_credentials (tenant_id);
ALTER TABLE snmp_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE snmp_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON snmp_credentials;
CREATE POLICY tenant_iso ON snmp_credentials
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- audit_events (append-only; tenant-scoped read)
CREATE TABLE IF NOT EXISTS audit_events (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL DEFAULT '',
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    data       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_tenant_ts_idx ON audit_events (tenant_id, ts DESC);
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON audit_events;
CREATE POLICY tenant_iso ON audit_events
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- ---- global reference data (no tenant scope; readable by all, no RLS) ----

CREATE TABLE IF NOT EXISTS roles (
    id         TEXT PRIMARY KEY,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS snmp_profiles (
    id         TEXT PRIMARY KEY,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- fallback blob store for the not-yet-normalized stores ----
-- Singleton config objects (LDAP/TACACS/OIDC/token-policy/copilot/notify) and
-- collections without a normalized table yet (refresh tokens, report runs) keep
-- the original one-blob-per-key shape here. These are global app config, not
-- tenant-scoped row sets, so no RLS — they round-trip verbatim through pgStore's
-- blob path exactly as the file backend stores them.
CREATE TABLE IF NOT EXISTS app_kv (
    key        TEXT PRIMARY KEY,
    data       BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
