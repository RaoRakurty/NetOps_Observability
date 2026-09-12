-- 0024_business_service.sql — Business Service mapping (Azure optional-tags epic).
--
-- The read-only monitoring service principal (Reader + Monitoring Reader) CANNOT
-- write cloud tags, and the lab's Azure VMs arrive with empty tags. Attribution
-- therefore cannot depend on tags. Two tenant-isolated tables give a persistent,
-- operator-editable home for the service mapping the built-in inference produces
-- (service_infer.py) AND the manual overrides a human confirms on top of it:
--
--   business_services  — the named BusinessService registry (rename-safe identity).
--   resource_mappings  — resource_id → service, one row per resource per tenant,
--                        carrying source (inferred|manual), confidence, basis and
--                        is_manual_override. A manual override WINS over inference
--                        and is treated as confirmed.
--
-- Both are RLS-isolated (tenant_iso, FORCE) exactly like every other tenant table
-- (migration 0011 is the template). Additive migration — safe to apply forward.

CREATE TABLE IF NOT EXISTS business_services (
    business_service_id UUID NOT NULL,
    tenant_id           TEXT NOT NULL DEFAULT '',
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    criticality         TEXT NOT NULL DEFAULT 'normal'
                        CHECK (criticality IN ('critical','high','normal','low')),
    created_by          TEXT NOT NULL DEFAULT 'system',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, business_service_id)
);
-- One service name per tenant (case-insensitive) — assignment is by name.
CREATE UNIQUE INDEX IF NOT EXISTS business_services_name_idx
    ON business_services (tenant_id, lower(name));

CREATE TABLE IF NOT EXISTS resource_mappings (
    tenant_id           TEXT NOT NULL DEFAULT '',
    resource_id         TEXT NOT NULL,               -- ARM id / ARN / GCP path
    business_service_id UUID,                         -- NULL until bound to a named service
    service_name        TEXT NOT NULL DEFAULT '',     -- denormalized for display/attribution
    source              TEXT NOT NULL DEFAULT 'manual'
                        CHECK (source IN ('inferred','manual')),
    confidence          TEXT NOT NULL DEFAULT 'confirmed'
                        CHECK (confidence IN ('confirmed','strong','suspected','weak')),
    basis               TEXT NOT NULL DEFAULT '',
    -- TRUE when a human set/confirmed the mapping. A manual override is
    -- authoritative: it wins over the automatic inference and is never clobbered
    -- by a later poller refresh.
    is_manual_override  BOOLEAN NOT NULL DEFAULT true,
    created_by          TEXT NOT NULL DEFAULT 'system',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, resource_id)
);
CREATE INDEX IF NOT EXISTS resource_mappings_svc_idx
    ON resource_mappings (tenant_id, business_service_id);

-- RLS: tenant_iso on both ('*' = platform cross-tenant; FORCE so even the table
-- owner is bound). Mirrors migration 0011 exactly.
ALTER TABLE business_services ENABLE ROW LEVEL SECURITY;
ALTER TABLE business_services FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON business_services;
CREATE POLICY tenant_iso ON business_services
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE resource_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_mappings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON resource_mappings;
CREATE POLICY tenant_iso ON resource_mappings
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));
