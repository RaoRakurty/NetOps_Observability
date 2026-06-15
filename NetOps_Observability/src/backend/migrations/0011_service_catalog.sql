-- 0011_service_catalog.sql — Service catalog (#69 §2, P2). The semantic lens over
-- the truth streams. Three deliberately split objects (owner decision 2026-06-11):
-- identity is stable, selection evolves, operations attach.
--   services           — stable identity (rename-safe; archive, never hard-delete:
--                         flow attribution history refers to it).
--   service_selectors  — the grouping rule, VERSIONED + append-only. Edits never
--                         rewrite history: rows attributed under v3 stay v3
--                         (deterministic/replayable, same rule as #67 snapshots).
--   service_bindings   — what we operate for the service (probes/paths/seams).
-- All tenant-isolated (RLS, like every tenant table). tenant_id is denormalized
-- onto selectors/bindings so the row policy is a simple per-table predicate.

CREATE TABLE IF NOT EXISTS services (
    service_id   UUID NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT '',
    name         TEXT NOT NULL,
    criticality  TEXT NOT NULL DEFAULT 'normal'
                 CHECK (criticality IN ('critical','high','normal','low')),
    description  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at  TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, service_id)
);
CREATE INDEX IF NOT EXISTS services_active_idx ON services (tenant_id) WHERE archived_at IS NULL;

CREATE TABLE IF NOT EXISTS service_selectors (
    tenant_id      TEXT NOT NULL DEFAULT '',
    service_id     UUID NOT NULL,
    version        INT  NOT NULL,                       -- monotonic per service
    effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),  -- attribution uses the version active at flow time
    spec           JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {dst_prefixes[],ports[],protocols[],remote_asns[],domains[],tags[]}
    created_by     TEXT NOT NULL DEFAULT 'system',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, service_id, version)
);

CREATE TABLE IF NOT EXISTS service_bindings (
    binding_id   UUID NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT '',
    service_id   UUID NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('probe','path','seam')),
    ref          TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, binding_id)
);
CREATE INDEX IF NOT EXISTS service_bindings_svc_idx ON service_bindings (tenant_id, service_id);

-- RLS: tenant_iso on all three ('*' = platform cross-tenant; FORCE so even the
-- table owner is bound). Mirrors every other tenant table.
ALTER TABLE services ENABLE ROW LEVEL SECURITY;
ALTER TABLE services FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON services;
CREATE POLICY tenant_iso ON services
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

ALTER TABLE service_selectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_selectors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON service_selectors;
CREATE POLICY tenant_iso ON service_selectors
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

ALTER TABLE service_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON service_bindings;
CREATE POLICY tenant_iso ON service_bindings
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));
