-- 0023_service_path_graph.sql — Service Path Graph, frozen contract v1
-- (docs/design/service-path-graph-contract.md §2).
--
-- STORAGE SPLIT (justified, per the contract's own cardinality shape):
--
--   PostgreSQL  ← REGISTRIES. `Endpoint` (§2.1) and `PathDefinition` (§2.2) are
--                 low-cardinality, mutable-window, relational objects: an endpoint
--                 is a BINDING with a validity window that CLOSES and re-opens as
--                 the address moves, and a path definition is a stable identity row.
--                 They need row-level tenant isolation, referential lookups by
--                 (tenant, address, context), and update-in-place of valid_to —
--                 all of which are Postgres's job and none of which suit an OLAP
--                 append-only store.
--
--   ClickHouse  ← STREAMS. `PathObservation` (§2.3) and `PathHop` (§2.4) are
--                 IMMUTABLE, high-cardinality, append-only measurement records —
--                 one new observation per run, forever, per path, per vantage, per
--                 protocol. History IS the feature (route change = a new row, never
--                 an update). That is an OLAP workload; they live in
--                 netops.path_observations / netops.path_hops (see path_schema.go +
--                 deployment/docker/clickhouse/init.sql), tenant-partitioned with a
--                 strict row policy.
--
-- Every table carries the §1 provenance block (tenant_id, data_class, environment,
-- scenario_id, run_id, producer_id, provenance_id) and the contract version, so
-- cleanup can operate on (tenant_id, scenario_id/run_id) ALONE — never on naming
-- conventions, IP patterns, or substring matches.
--
-- ROLLBACK: migrations/rollback/0023_service_path_graph.down.sql (drops both tables
-- and their policies; the ClickHouse half has its own rollback in the same file).
-- Idempotent.

-- §2.1 Endpoint — a tenant-scoped, time-bounded binding of an address to an entity.
-- The SAME address in two tenants is two rows and they never join (the primary key
-- leads with tenant_id, and RLS makes that structural rather than aspirational).
CREATE TABLE IF NOT EXISTS path_endpoints (
    tenant_id           TEXT NOT NULL DEFAULT '',
    endpoint_id         TEXT NOT NULL,                    -- stable id of the BINDING, not of the address
    address             TEXT NOT NULL,
    address_family      TEXT NOT NULL DEFAULT 'ipv4',     -- ipv4 | ipv6
    network_context     TEXT NOT NULL DEFAULT '',         -- VRF / VPC / VNet / LAN segment — REQUIRED by the contract
    kind                TEXT NOT NULL DEFAULT 'unknown',  -- client|lan_gateway|wan_edge|nva|cloud_edge|app_endpoint|service_endpoint|transit|unknown
    resolved_entity_ref TEXT NOT NULL DEFAULT '',         -- device_id | cloud_resource_id | interface_id
    resolution_method   TEXT NOT NULL DEFAULT 'unresolved',
    confidence          TEXT NOT NULL DEFAULT 'unknown',  -- authoritative | strong | candidate | unknown
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,                      -- NULL = currently valid
    evidence_ref        TEXT NOT NULL DEFAULT '',
    -- §1 provenance (immutable)
    data_class          TEXT NOT NULL DEFAULT 'live',     -- live | synthetic | replay | lab
    environment         TEXT NOT NULL DEFAULT 'prod',
    scenario_id         TEXT NOT NULL DEFAULT '',
    run_id              TEXT NOT NULL DEFAULT '',
    producer_id         TEXT NOT NULL DEFAULT '',
    provenance_id       TEXT NOT NULL DEFAULT '',
    contract_version    INT  NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    data                JSONB NOT NULL DEFAULT '{}'::jsonb,  -- lossless record (same pattern as topology_nodes)
    PRIMARY KEY (tenant_id, endpoint_id)
);
CREATE INDEX IF NOT EXISTS path_endpoints_tenant_idx  ON path_endpoints (tenant_id);
-- The resolver's hot lookup: (tenant, address, context) within a validity window.
CREATE INDEX IF NOT EXISTS path_endpoints_addr_idx    ON path_endpoints (tenant_id, address, network_context);
-- Cleanup is keyed on tenant + scenario/run ONLY (§1) — this index is what makes
-- that the cheap path, so nobody is ever tempted to LIKE '%lab%' their way out.
CREATE INDEX IF NOT EXISTS path_endpoints_run_idx     ON path_endpoints (tenant_id, scenario_id, run_id);

-- §2.2 PathDefinition — the logical path being measured. Identity = (tenant, src,
-- dst, direction, protocol, dst_port, vantage, network_context): any difference is
-- a DIFFERENT path (an ICMP path and a TCP:443 path to the same host are distinct
-- objects and are ALLOWED to disagree — §8).
CREATE TABLE IF NOT EXISTS path_definitions (
    tenant_id           TEXT NOT NULL DEFAULT '',
    path_id             TEXT NOT NULL,                    -- deterministic hash of the identity fields
    src_endpoint_ref    TEXT NOT NULL DEFAULT '',
    dst_endpoint_ref    TEXT NOT NULL DEFAULT '',
    src_address         TEXT NOT NULL DEFAULT '',
    dst_address         TEXT NOT NULL DEFAULT '',
    direction           TEXT NOT NULL DEFAULT 'forward',  -- forward | reverse (never merged)
    protocol            TEXT NOT NULL DEFAULT 'icmp',     -- icmp | tcp | udp
    dst_port            INT  NOT NULL DEFAULT 0,
    vantage_id          TEXT NOT NULL DEFAULT '',
    network_context     TEXT NOT NULL DEFAULT '',
    -- §1 provenance (immutable)
    data_class          TEXT NOT NULL DEFAULT 'live',
    environment         TEXT NOT NULL DEFAULT 'prod',
    scenario_id         TEXT NOT NULL DEFAULT '',
    run_id              TEXT NOT NULL DEFAULT '',
    producer_id         TEXT NOT NULL DEFAULT '',
    provenance_id       TEXT NOT NULL DEFAULT '',
    contract_version    INT  NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    data                JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, path_id)
);
CREATE INDEX IF NOT EXISTS path_definitions_tenant_idx ON path_definitions (tenant_id);
CREATE INDEX IF NOT EXISTS path_definitions_dst_idx    ON path_definitions (tenant_id, dst_address, protocol, vantage_id);
CREATE INDEX IF NOT EXISTS path_definitions_run_idx    ON path_definitions (tenant_id, scenario_id, run_id);

-- RLS: the same tenant_iso FORCE-RLS policy every other tenant table carries.
-- '' = platform/untagged, '*' = the cross-tenant platform reader. FORCE so even the
-- table owner is bound by it (§9: no cross-tenant join, ever — enforced by the
-- database, not by a WHERE clause somebody might forget).
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['path_endpoints','path_definitions'] LOOP
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
