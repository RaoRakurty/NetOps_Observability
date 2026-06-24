-- 0015_app_identity.sql — Application Identification (#81 P0 contract). The
-- data-plane identity layer (peer of device identity / EntityResolver and tenant
-- identity). Two new objects + one link:
--   applications  — a business "application" as a THIN PARENT over the #69
--                   technical services (we do NOT rebuild #69; services.application_id
--                   links up). Carries owner_team → powers owner=app_team RCA attribution.
--   app_catalog   — (match_kind,match_value) → app_label rows that the P1 LPM-trie
--                   resolver loads (vendor IP/prefix ranges, domains, ASN, ports).
--   services.application_id — nullable thin-parent link (FK-by-policy, like the rest).
-- Identification VERDICTS reuse the correlation engine's tier/evidence vocabulary
-- (appid/verdict.go) — no parallel confidence model.
--
-- Tenant isolation: tenant_iso FORCE on app.tenant_id, like every tenant table.
-- app_catalog additionally allows a SHARED GLOBAL row (tenant_id='') readable by
-- all tenants — public vendor IP-range feeds are the same data for everyone; only
-- per-tenant OVERRIDES are tenant-scoped, and a scoped tenant may never WRITE a
-- global row (WITH CHECK omits the '' branch — default-closed).

CREATE TABLE IF NOT EXISTS applications (
    application_id UUID NOT NULL,
    tenant_id      TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,
    owner_team     TEXT NOT NULL DEFAULT '',          -- owner=app_team attribution
    criticality    TEXT NOT NULL DEFAULT 'normal'
                   CHECK (criticality IN ('critical','high','normal','low')),
    description    TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at    TIMESTAMPTZ,                        -- archive, never hard-delete (attribution history)
    PRIMARY KEY (tenant_id, application_id)
);
CREATE INDEX IF NOT EXISTS applications_active_idx ON applications (tenant_id) WHERE archived_at IS NULL;

-- #69 service → application (thin-parent link; nullable, FK-by-policy not hard FK
-- since RLS makes cross-table FKs awkward — existence is checked under the policy).
ALTER TABLE services ADD COLUMN IF NOT EXISTS application_id UUID;
CREATE INDEX IF NOT EXISTS services_application_idx
    ON services (tenant_id, application_id) WHERE application_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS app_catalog (
    catalog_id   UUID NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT '',            -- '' = shared public feed; else per-tenant override
    match_kind   TEXT NOT NULL CHECK (match_kind IN ('prefix','domain','asn','port')),
    match_value  TEXT NOT NULL,                        -- CIDR | domain-suffix | ASN | port (loader-validated)
    app_label    TEXT NOT NULL,                        -- canonical app/CDN/service name
    confidence   DOUBLE PRECISION NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
    source       TEXT NOT NULL DEFAULT 'manual',       -- m365|aws|azure|gcp|asn|netbox|manual|...
    version      INT  NOT NULL DEFAULT 1,              -- catalog generation (hot-reload bump)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, catalog_id)
);
CREATE INDEX IF NOT EXISTS app_catalog_kind_idx ON app_catalog (tenant_id, match_kind);

ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE applications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON applications;
CREATE POLICY tenant_iso ON applications
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE app_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_catalog FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON app_catalog;
CREATE POLICY tenant_iso ON app_catalog
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true)
        OR tenant_id = '')                             -- shared public feed: readable by all tenants
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true)); -- a tenant writes only its own rows
