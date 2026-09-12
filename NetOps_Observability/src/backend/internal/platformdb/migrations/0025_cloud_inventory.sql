-- 0025_cloud_inventory.sql — Cloud App Observability inventory → Postgres
-- (WAVE 1 #1). Replaces the in-memory memCloudStore with a durable, per-row,
-- RLS-isolated store so the /api/cloud/resources surface can filter + paginate in
-- SQL instead of loading the whole tenant inventory into Go memory. This is the P0
-- root the scale features (free-text search, findings pagination, export, saved
-- views) all sit on.
--
-- Three tenant-owned tables, all FORCE-RLS under the tenant_iso policy
-- (app.tenant_id GUC set by withTenant; '*' = platform owner):
--   cloud_resources             — one discovered resource per row. Canonical
--                                 filter/sort fields are typed columns (provider,
--                                 account, region, type, confidence, source); the
--                                 lossless cloud.CloudResource is carried in JSONB
--                                 `data` (topology_nodes pattern) so a reader never
--                                 reconstructs a row from columns. `tags` is a
--                                 separate JSONB column, GIN-indexed, for tag filters.
--   cloud_identity_mappings     — the (match_key → app) attributions the flow/log
--                                 enrichment joins on (lossless JSONB `data`).
--   cloud_inventory_connectors  — inventory-source PROVENANCE (live poller vs hand
--                                 fixture) that drives the UI's data-mode badge.
--                                 Distinct from cloud_connectors (0024 — the connector
--                                 domain model); named apart to avoid collision.
--
-- Provider account/subscription/project ids are NOT globally unique, so every
-- key/index LEADS with tenant_id. '' is the global/platform namespace (untagged
-- fixture load), exactly like topology (0012).

CREATE TABLE IF NOT EXISTS cloud_resources (
    tenant_id      TEXT NOT NULL DEFAULT '',
    resource_id    TEXT NOT NULL,                       -- ARN / ARM id / GCP path
    cloud_provider TEXT NOT NULL DEFAULT '',            -- aws | azure | gcp
    account_id     TEXT NOT NULL DEFAULT '',            -- account | subscription | project
    region         TEXT NOT NULL DEFAULT '',
    resource_type  TEXT NOT NULL DEFAULT '',
    app_id         TEXT NOT NULL DEFAULT '',
    confidence     TEXT NOT NULL DEFAULT 'unknown',     -- confirmed|strong|suspected|weak|unknown
    source         TEXT NOT NULL DEFAULT 'unknown',
    discovered_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    tags           JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {key: value} for tag filters
    data           JSONB NOT NULL DEFAULT '{}'::jsonb,  -- lossless cloud.CloudResource
    PRIMARY KEY (tenant_id, resource_id)
);
-- Keyset pagination sorts by (tenant_id, resource_id) — the PK already backs it.
-- Per-column filter indexes keep provider/account/region/type/attribution filters
-- granule-pruned instead of a full per-tenant scan.
CREATE INDEX IF NOT EXISTS cloud_resources_tenant_prov_idx   ON cloud_resources (tenant_id, cloud_provider);
CREATE INDEX IF NOT EXISTS cloud_resources_tenant_acct_idx   ON cloud_resources (tenant_id, account_id);
CREATE INDEX IF NOT EXISTS cloud_resources_tenant_region_idx ON cloud_resources (tenant_id, region);
CREATE INDEX IF NOT EXISTS cloud_resources_tenant_type_idx   ON cloud_resources (tenant_id, resource_type);
CREATE INDEX IF NOT EXISTS cloud_resources_tenant_conf_idx   ON cloud_resources (tenant_id, confidence);
CREATE INDEX IF NOT EXISTS cloud_resources_tags_gin          ON cloud_resources USING GIN (tags);

CREATE TABLE IF NOT EXISTS cloud_identity_mappings (
    tenant_id      TEXT NOT NULL DEFAULT '',
    match_key_type TEXT NOT NULL DEFAULT '',
    match_key      TEXT NOT NULL DEFAULT '',
    app_id         TEXT NOT NULL DEFAULT '',
    data           JSONB NOT NULL DEFAULT '{}'::jsonb,  -- lossless cloud.CloudIdentityMapping
    PRIMARY KEY (tenant_id, match_key_type, match_key)
);
CREATE INDEX IF NOT EXISTS cloud_identity_mappings_tenant_idx ON cloud_identity_mappings (tenant_id);

CREATE TABLE IF NOT EXISTS cloud_inventory_connectors (
    tenant_id      TEXT NOT NULL DEFAULT '',
    provider       TEXT NOT NULL DEFAULT '',
    account_id     TEXT NOT NULL DEFAULT '',
    kind           TEXT NOT NULL DEFAULT 'fixture',     -- live | fixture
    collected_at   TIMESTAMPTZ,
    resource_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, provider, account_id)
);
CREATE INDEX IF NOT EXISTS cloud_inventory_connectors_tenant_idx ON cloud_inventory_connectors (tenant_id);

-- FORCE-RLS tenant isolation (identical predicate to every other tenant_iso table,
-- keyed off the app.tenant_id GUC set by withTenant; '*' = platform owner).
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['cloud_resources','cloud_identity_mappings','cloud_inventory_connectors'] LOOP
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
