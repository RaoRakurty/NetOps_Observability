-- 0016_app_identity_fusion.sql — Application Identity Fusion Layer (#81), Phase 1
-- canonical model. ADDITIVE over 0015_app_identity.sql:
--   * enrich `applications` with the canonical taxonomy (provider/family/category/
--     component-hierarchy/lifecycle/catalog version/validity/scope) the fusion layer
--     needs — without rebuilding the thin-parent table or #69 services.
--   * add `app_aliases` — vendor-namespaced alias → canonical mappings (Palo Alto
--     `ms-teams`, Fortinet `Microsoft.Teams`, Cisco `Microsoft Teams` → "Microsoft
--     Teams"). The ORIGINAL vendor value is preserved (alias column); canonicalization
--     is a lookup, never a rewrite. review_status gates fuzzy-match SUGGESTIONS so an
--     operator must approve before they enter the hot path.
-- Tenant isolation mirrors 0015: tenant_iso FORCE; a SHARED GLOBAL row (tenant_id='')
-- is readable by all tenants (public vendor mappings are the same for everyone) but a
-- scoped tenant may only WRITE its own rows (default-closed WITH CHECK).
-- All statements are idempotent (re-runnable) per the repo's migration convention.

-- ── canonical taxonomy on applications ───────────────────────────────────────
ALTER TABLE applications ADD COLUMN IF NOT EXISTS provider        TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS family          TEXT NOT NULL DEFAULT '';   -- e.g. "Microsoft 365"
ALTER TABLE applications ADD COLUMN IF NOT EXISTS category        TEXT NOT NULL DEFAULT '';   -- e.g. "Collaboration"
ALTER TABLE applications ADD COLUMN IF NOT EXISTS subcategory     TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS parent_id       UUID;                        -- component → business-app
ALTER TABLE applications ADD COLUMN IF NOT EXISTS lifecycle       TEXT NOT NULL DEFAULT 'active';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS catalog_version INT  NOT NULL DEFAULT 1;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS valid_from      TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE applications ADD COLUMN IF NOT EXISTS valid_to        TIMESTAMPTZ;                 -- NULL = current
ALTER TABLE applications ADD COLUMN IF NOT EXISTS scope           TEXT NOT NULL DEFAULT 'tenant';

-- guard the enums idempotently (ADD CONSTRAINT has no IF NOT EXISTS in older PG).
DO $$ BEGIN
    ALTER TABLE applications ADD CONSTRAINT applications_lifecycle_chk
        CHECK (lifecycle IN ('active','deprecated','retired'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE applications ADD CONSTRAINT applications_scope_chk
        CHECK (scope IN ('global','tenant'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS applications_parent_idx
    ON applications (tenant_id, parent_id) WHERE parent_id IS NOT NULL;

-- ── vendor-namespaced alias → canonical mappings ─────────────────────────────
CREATE TABLE IF NOT EXISTS app_aliases (
    alias_id        UUID NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',            -- '' = shared global mapping; else per-tenant
    alias           TEXT NOT NULL,                        -- the ORIGINAL vendor/display value (never discarded)
    kind            TEXT NOT NULL DEFAULT 'vendor_name'
                    CHECK (kind IN ('vendor_app_id','vendor_name','display_alias')),
    vendor          TEXT NOT NULL DEFAULT '',             -- paloalto|fortinet|cisco|... ('' = vendor-neutral display alias)
    product         TEXT NOT NULL DEFAULT '',             -- panos|fortios|secure-firewall|nbar2|... (namespacing)
    vendor_catalog  TEXT NOT NULL DEFAULT '',             -- vendor content/app-db version, if known
    app_label       TEXT NOT NULL,                        -- canonical application this alias resolves to
    review_status   TEXT NOT NULL DEFAULT 'approved'
                    CHECK (review_status IN ('approved','suggested','rejected')),
    version         INT  NOT NULL DEFAULT 1,              -- catalog generation (hot-reload bump)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, alias_id)
);
-- fast canonicalization lookup: (vendor, alias) within a tenant scope; only APPROVED
-- rows are on the hot path (suggested/rejected are administrative).
CREATE INDEX IF NOT EXISTS app_aliases_lookup_idx
    ON app_aliases (tenant_id, vendor, alias) WHERE review_status = 'approved';

ALTER TABLE app_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_aliases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON app_aliases;
CREATE POLICY tenant_iso ON app_aliases
    USING (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true)
        OR tenant_id = '')                                -- shared global mappings readable by all tenants
    WITH CHECK (current_setting('app.tenant_id', true) = '*'
        OR tenant_id = current_setting('app.tenant_id', true)); -- a tenant writes only its own rows
