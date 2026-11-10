-- 0067_discovery_scopes.sql — tenant-owned SNMP discovery scopes (2026-11-10;
-- src/backend/internal/discoveryscope/pg_store.go).
--
-- WHY. The platform's subnet scan files every device it finds under the
-- platform. A customer whose devices the platform reaches had no channel of its
-- own, so its edges stayed the platform's. A scope is a scan the platform owner
-- points at a customer's network ON THAT CUSTOMER'S BEHALF, with the customer's
-- own SNMP profiles: every device it finds belongs to the customer. The scope IS
-- the channel — the tenant comes from this row, set by the platform owner, never
-- from anything a device answers.
--
-- One row per scope. The platform's own scan stays the operator config
-- (/api/discovery/config) and is never a row here: tenant_id is never '' or
-- 'global' (CHECK). ranges are validated IPv4 CIDRs; credential_refs are SNMP
-- profile ids the customer owns (empty = every profile the customer owns).
-- Collector tier C1 adds collector_group_id to this same table (one scope
-- model, not two).
--
-- ISOLATION: FORCE-RLS tenant_iso, the 0063 predicate. Writes run scoped to the
-- scope's own tenant, so WITH CHECK refuses a row filed under another tenant;
-- UNIQUE (id) means an id is never held by two tenants, so a scope cannot be
-- moved between them by a colliding id either.
--
-- Rollback: rollback/0067_discovery_scopes.down.sql.
CREATE TABLE IF NOT EXISTS discovery_scopes (
    tenant_id         TEXT NOT NULL CHECK (tenant_id <> '' AND tenant_id <> 'global'),
    id                TEXT NOT NULL CHECK (id ~ '^ds-[0-9a-f]{16}$'),
    name              TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    ranges            JSONB NOT NULL CHECK (jsonb_typeof(ranges) = 'array'),
    allow_non_private BOOLEAN NOT NULL DEFAULT false,
    credential_refs   JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(credential_refs) = 'array'),
    enabled           BOOLEAN NOT NULL DEFAULT false,
    created_by        TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (id)
);

ALTER TABLE discovery_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_scopes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON discovery_scopes;
CREATE POLICY tenant_iso ON discovery_scopes
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
