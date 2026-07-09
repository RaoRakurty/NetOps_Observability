-- ClickHouse schema for the OLAP/analytics layer.
--
-- Loaded on first container start via docker-entrypoint-initdb.d. The
-- tables are kept narrow on purpose; widen them as the flow analytics
-- and capacity-planning features grow.

CREATE DATABASE IF NOT EXISTS netops;

-- ---------------------------------------------------------------------------
-- NetFlow / IPFIX / sFlow records.
--
-- One row per flow record. Vector's clickhouse sink writes here with
-- skip_unknown_fields = true, so additional goflow2 fields can land
-- without a schema migration; just ALTER TABLE ADD COLUMN.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS netops.flows
(
    ts              DateTime64(3) DEFAULT now64(3),
    -- Codecs (#96): near-sorted ns timestamps delta-encode well; per-row
    -- counters shrink under T64 (values use few of their 64 bits); IP strings
    -- compress ~2x better under ZSTD than the LZ4 default. Measured -19% on
    -- 16.6M live rows; applied to the live table via ALTER, kept here for
    -- fresh installs.
    time_received_ns UInt64 CODEC(DoubleDelta, LZ4),
    sampler_address String,
    src_addr        String CODEC(ZSTD(1)),
    dst_addr        String CODEC(ZSTD(1)),
    src_port        UInt16,
    dst_port        UInt16,
    proto           UInt8,
    bytes           UInt64 CODEC(T64, LZ4),
    packets         UInt64 CODEC(T64, LZ4),
    in_if           UInt32,
    out_if          UInt32,
    src_as          UInt32,
    dst_as          UInt32,
    sampling_rate   UInt32 CODEC(T64, LZ4),
    vlan_id         UInt16,
    tcp_flags       UInt16 DEFAULT 0,  -- tcpControlBits (IPFIX IE6 / NetFlow TCP_FLAGS) via goflow2; 0 = none/not exported
    flow_type       LowCardinality(String) DEFAULT 'unknown',  -- netflow | ipfix | sflow
    tenant_id       LowCardinality(String) DEFAULT ''  -- #20: stamped at Vector ingest (device→tenant); '' = global
)
ENGINE = MergeTree
-- #20 Phase 3 — at-rest separation: tenant_id leads the partition key, so each
-- tenant's data lives in its own physical parts (independently droppable /
-- backup-able / per-tenant encryptable, ties into #16). Existing live tables are
-- rebuilt to this key by clickhouse/migrate-tenant-partition.sh (data preserved).
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (ts, sampler_address, src_addr, dst_addr)
-- ts is DateTime64(3); TTL expressions must be Date/DateTime, so cast it.
-- ttl_only_drop_parts: partitioning is daily, so expiry drops whole parts
-- (instant, no I/O) instead of rewriting rows out of live parts (#96, on every
-- TTL'd table here).
TTL toDateTime(ts) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- ---------------------------------------------------------------------------
-- (Removed: the flows_hourly materialized view.) #20 Phase 2 puts a tenant
-- row policy on netops.flows; an MV that reads flows re-evaluates that policy on
-- every INSERT (in the inserting connection's context, where getSetting(
-- 'tenant_scope') is unset → the insert ERRORS, breaking ingestion). The view
-- was unused by the app (top-talkers query netops.flows directly). If an hourly
-- rollup is wanted later, build it tenant-aware or off a policy-exempt pipeline.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Geo IP — query-time IP→country enrichment for the flow analytics.
--
-- An ip_trie dictionary over an operator-supplied CSV (network,country) at
-- user_files/geoip/country.csv — produced by scripts/geoip-prepare.py from a
-- GeoLite2 Country or DB-IP Lite download (licensing forbids bundling the
-- data itself). Lazy-loaded: creating it with the file absent is fine; the
-- Geo endpoints probe with dictGetOrDefault and degrade to an onboarding
-- hint until the file appears. Query-time (vs ingest-time) enrichment works
-- retroactively on stored flows and hot-reloads on file mtime (LIFETIME).
-- The API bootstrap (ensureCHRowPolicies) also creates this, so existing
-- deployments converge without manual SQL.
-- ---------------------------------------------------------------------------

CREATE DICTIONARY IF NOT EXISTS netops.geoip_country
(
    network String,
    country String
)
PRIMARY KEY network
SOURCE(FILE(path '/var/lib/clickhouse/user_files/geoip/country.csv' format 'CSVWithNames'))
LAYOUT(IP_TRIE())
LIFETIME(MIN 3600 MAX 7200);

-- ---------------------------------------------------------------------------
-- Overlay tunnels (IPsec / SD-WAN / GRE) between devices.
--
-- One row per collector poll of a tunnel. Populated from device telemetry —
-- SNMP (CISCO-IPSEC-FLOW-MONITOR-MIB cipSecTunnelTable), SD-WAN BFD/OMP
-- sessions, or gNMI/NETCONF YANG paths. The Tunnels view reads the latest
-- sample per tunnel id (ORDER BY ts DESC LIMIT 1 BY id). skip_unknown_fields
-- on the sink means new fields land with a plain ALTER TABLE ADD COLUMN.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS netops.tunnels
(
    ts             DateTime64(3) DEFAULT now64(3),
    id             String,                  -- stable tunnel id (local-remote-type)
    type           LowCardinality(String),  -- 'ipsec' | 'sdwan' | 'gre'
    local_device   String,
    local_addr     String,
    remote_device  String,
    remote_addr    String,
    status         LowCardinality(String),  -- 'up' | 'down'
    latency_ms     Float32,
    jitter_ms      Float32,
    loss_pct       Float32,
    qoe            Float32,                  -- quality-of-experience score 0..10
    uptime_s       UInt64,
    tenant_id      LowCardinality(String) DEFAULT ''  -- #20: owning tenant; '' = global
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (ts, id)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- ---------------------------------------------------------------------------
-- Correlation findings — populated by the Python correlation service.
-- Surfaces in the UI as ranked incident cards.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS netops.findings
(
    ts          DateTime64(3) DEFAULT now64(3),
    id          String,
    kind        LowCardinality(String),  -- 'anomaly' | 'rca' | 'correlation'
    severity    LowCardinality(String),  -- 'info' | 'warning' | 'critical'
    score       Float32,
    device      String,
    component   String,
    summary     String,
    description String,
    labels      Map(String, String),
    tenant_id   LowCardinality(String) DEFAULT ''  -- #20: stamped by the correlation service (device→tenant); '' = global
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (ts, severity, score)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1;

-- ---------------------------------------------------------------------------
-- #20 Phase 2 — DATABASE-ENFORCED per-tenant isolation (defense in depth under
-- the app-layer device matcher). The Go API injects the `tenant_scope` custom
-- setting on EVERY telemetry read (proxyClickHouse): '__all__' for the platform
-- owner, the tenant id for a scoped principal. A scoped reader sees ONLY its own
-- tagged rows plus untagged (tenant_id='') rows; the app layer further narrows
-- the untagged set by device. Another tenant's TAGGED rows are refused by the DB
-- even if a query's WHERE clause is ever forgotten.
--
-- Requires custom_settings_prefixes=tenant_ (config.d/custom-settings.xml). These
-- policies filter SELECT only (ClickHouse row policies don't gate INSERT), so
-- ingestion is unaffected — provided no materialized view reads a policy table
-- (see the removed flows_hourly note above). The Go API also ensures these exist
-- at startup (ensureCHRowPolicies) so existing deployments self-heal.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Correlation Engine v2 (#67) — FROZEN schema (build step ①, 2026-06-11).
-- docs/design/correlation-engine.md §2 is the authoritative spec; this DDL is
-- mirrored in src/backend/corr_schema.go (self-healing for live deployments)
-- and guarded by src/backend/corr_schema_test.go. Append-only by design:
-- never UPDATE/DELETE these rows; new state = new (correlation_id, version).
-- NO materialized view may read these tables (row policies break MV inserts —
-- see the flows_hourly note above).
-- ---------------------------------------------------------------------------

-- 2.1 Normalized signal spine (shared with the #53/#69 unified event feed).
-- The OBSERVER BLOCK is mandatory (owner review): confirmation depends on observer
-- independence, so observation provenance is non-optional — the normalizer
-- dead-letters records it cannot stamp; CHECK observer_id != '' backstops here.
CREATE TABLE IF NOT EXISTS netops.corr_signals
(
    tenant_id      LowCardinality(String) DEFAULT '',  -- '' = platform/global
    signal_id      UUID,                     -- deterministic: UUIDv5(source, native_id, ts)
    ts             DateTime64(3),            -- event time (source clock)
    ingest_ts      DateTime64(3) DEFAULT now64(3),
    source         Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,
                         'topology'=5,'syslog'=6,'sot_drift'=7,'trap'=8,'cloud'=9,
                         'app_identity'=10,'controller'=11),
    kind           LowCardinality(String),   -- e.g. probe_loss, if_errors, bgp_peer_down
    observer_id    LowCardinality(String),   -- WHO measured it (independence gate)
    observer_type  Enum8('device'=1,'vantage_agent'=2,'cloud_api'=3,
                         'flow_exporter'=4,'platform'=5,'controller'=6),
    observer_location     LowCardinality(String) DEFAULT '',  -- site / cloud region
    observer_trust_domain LowCardinality(String) DEFAULT '',  -- enterprise|cloud_tenant|platform
    collection_path       LowCardinality(String) DEFAULT 'direct', -- fate-sharing analysis:
                                              -- direct|via_controller|via_cloud_api|via_aggregator
    modality_class Enum8('active_probe'=1,'passive_flow'=2,
                         'control_plane'=3,'device_telemetry'=4,'management_plane'=5),  -- C4 verdict gate
    source_clock_quality LowCardinality(String) DEFAULT 'unknown', -- ntp|ptp|free_running|unknown
    entity_type    Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,
                         'site'=5,'service'=6,'prefix'=7,'app'=8,'cloud_resource'=9),
    entity_id      String,
    entity_tokens  Array(String),
    site           LowCardinality(String) DEFAULT '',
    path_id        LowCardinality(Nullable(String)),
    service_id     Nullable(String),         -- NULLABLE from day one (catalog fills at P2)
    severity       Enum8('info'=0,'warn'=1,'high'=2,'crit'=3),
    metric_name    LowCardinality(String) DEFAULT '',
    value          Float64 DEFAULT 0,
    baseline       Float64 DEFAULT 0,
    deviation      Float64 DEFAULT 0,
    attrs          String DEFAULT '{}',      -- JSON, bounded 4 KiB, schema-checked per kind
    CONSTRAINT observer_required CHECK observer_id != ''
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, ts, source, entity_type, entity_id)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- 2.1b Replay input archive (owner review — closes the replay/TTL gap): the FULL
-- window slice of every persisted object, written at pipeline stage [8] with the
-- snapshot. Whole window, not just attached signals — candidate-pool decisions
-- depend on non-attached episodes, so a participating-only archive would break
-- bit-perfect replay. NO TTL: objects are re-runnable forever; non-participating
-- hot-spine signals age out at 30 days (the honest, stated guarantee). Columns
-- mirror corr_signals exactly + archiving provenance.
CREATE TABLE IF NOT EXISTS netops.corr_signals_archive
(
    tenant_id      LowCardinality(String) DEFAULT '',
    signal_id      UUID,
    ts             DateTime64(3),
    ingest_ts      DateTime64(3) DEFAULT now64(3),
    source         Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,
                         'topology'=5,'syslog'=6,'sot_drift'=7,'trap'=8,'cloud'=9,
                         'app_identity'=10,'controller'=11),
    kind           LowCardinality(String),
    observer_id    LowCardinality(String),
    observer_type  Enum8('device'=1,'vantage_agent'=2,'cloud_api'=3,
                         'flow_exporter'=4,'platform'=5,'controller'=6),
    observer_location     LowCardinality(String) DEFAULT '',
    observer_trust_domain LowCardinality(String) DEFAULT '',
    collection_path       LowCardinality(String) DEFAULT 'direct',
    modality_class Enum8('active_probe'=1,'passive_flow'=2,
                         'control_plane'=3,'device_telemetry'=4,'management_plane'=5),
    source_clock_quality LowCardinality(String) DEFAULT 'unknown',
    entity_type    Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,
                         'site'=5,'service'=6,'prefix'=7,'app'=8,'cloud_resource'=9),
    entity_id      String,
    entity_tokens  Array(String),
    site           LowCardinality(String) DEFAULT '',
    path_id        LowCardinality(Nullable(String)),
    service_id     Nullable(String),
    severity       Enum8('info'=0,'warn'=1,'high'=2,'crit'=3),
    metric_name    LowCardinality(String) DEFAULT '',
    value          Float64 DEFAULT 0,
    baseline       Float64 DEFAULT 0,
    deviation      Float64 DEFAULT 0,
    attrs          String DEFAULT '{}',
    archived_for     UUID,                   -- correlation_id whose window slice this is
    archived_version UInt32 DEFAULT 0,        -- object version this slice belongs to (0 = legacy pre-fix rows)
    archived_at      DateTime64(3) DEFAULT now64(3),
    CONSTRAINT observer_required CHECK observer_id != ''
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(ts))
ORDER BY (tenant_id, ts, signal_id)
SETTINGS index_granularity = 8192;

-- 2.2 Correlation objects — versioned, append-only snapshots. No TTL: objects
-- are queryable forever (replay contract).
CREATE TABLE IF NOT EXISTS netops.corr_objects
(
    tenant_id        LowCardinality(String) DEFAULT '',
    correlation_id   UUID,
    version          UInt32,                 -- monotonic per object
    state            Enum8('open'=1,'closed'=2,'merged'=3),
    window_start     DateTime64(3),
    window_end       DateTime64(3),
    trigger_signal   UUID,
    top_hypothesis   String,                 -- template id, or 'undetermined'
    top_confidence   Float32,                -- heuristic rank, NOT probability
    verdict_tier     Enum8('undetermined'=0,'suspected'=1,'confirmed'=2),
    hypotheses       String,                 -- JSON ranked top-K incl. modality/observer coverage
    evidence_missing String DEFAULT '[]',    -- JSON: what would confirm (undetermined honesty)
    affected         String,                 -- JSON: {devices[],interfaces[],sites[],paths[],services[]}
    signal_count     UInt32,
    node_count       UInt16,
    engine_version   LowCardinality(String), -- semver + config hash → replay contract
    topology_version LowCardinality(String),
    catalog_version  LowCardinality(String), -- signature-catalog version scored against
    merged_into      Nullable(UUID),
    -- App-Identity fusion (#81) + layer coverage: added live via ALTER on the
    -- lab but MISSED here until the first virgin-host install 500'd the home
    -- page (UNKNOWN_IDENTIFIER o.app_impact, 2026-07-04). init.sql is the
    -- fresh-install schema authority — every live ALTER must land here too.
    layer_coverage   String DEFAULT '{}',    -- JSON: per-layer signal coverage
    app_impact       String DEFAULT '{}',    -- JSON: impacted app identities
    created_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(window_start))
ORDER BY (tenant_id, correlation_id, version);

-- "latest snapshot per object" convenience view (plain view: row policies on the
-- base table evaluate in the reader's context — safe, unlike an MV).
CREATE OR REPLACE VIEW netops.corr_objects_latest AS
SELECT * FROM netops.corr_objects
ORDER BY tenant_id, correlation_id, version DESC
LIMIT 1 BY tenant_id, correlation_id;

-- #100 hardening: HOT current-state projection — one NARROW row per object so
-- Command Center list pages read O(active objects), not O(history). NO wide
-- blob columns (hypotheses/layer_coverage/app_impact) by design; those are
-- fetched keyed from corr_objects for the picked page only. Maintained by
-- app-level dual-write from the correlation engine (NOT a materialized view —
-- row policies break MV inserts). ReplacingMergeTree keyed on created_at:
-- latest WRITE wins (self-heals the engine-restart version reset). Partitioned
-- by tenant ONLY — the dedup key (tenant, correlation_id) may not span
-- partitions or FINAL cannot collapse re-persists.
CREATE TABLE IF NOT EXISTS netops.corr_current
(
    tenant_id        LowCardinality(String) DEFAULT '',
    correlation_id   UUID,
    version          UInt32,
    state            Enum8('open'=1,'closed'=2,'merged'=3),
    window_start     DateTime64(3),
    window_end       DateTime64(3),
    top_hypothesis   String,
    top_confidence   Float32,
    verdict_tier     Enum8('undetermined'=0,'suspected'=1,'confirmed'=2),
    evidence_missing String DEFAULT '[]',
    affected         String DEFAULT '[]',
    signal_count     UInt32,
    node_count       UInt16,
    engine_version   LowCardinality(String) DEFAULT '',
    catalog_version  LowCardinality(String) DEFAULT '',
    merged_into      Nullable(UUID),
    created_at       DateTime64(3) DEFAULT now64(3),
    -- Triage badges, derived by the engine at persist time from the top
    -- hypothesis verdict — so the hot list path never JSONExtracts the wide
    -- hypotheses blob (that read alone was ~1.3 GiB/page at storm size).
    owner            LowCardinality(String) DEFAULT '',
    plane_count      UInt8 DEFAULT 0,
    debug_excluded   UInt8 DEFAULT 0,
    low_authority    UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY (tenant_id)
ORDER BY (tenant_id, correlation_id);

-- 2.3 Graph edges. The owner's grounded-edges hard constraint is enforced by the
-- CHECK constraint, not by non-Nullability alone: ClickHouse silently coerces an
-- inserted NULL to the column default ('') via input_format_null_as_default, so
-- only the CHECK actually rejects an ungrounded edge at the database layer
-- (verified live at freeze time).
CREATE TABLE IF NOT EXISTS netops.corr_edges
(
    tenant_id       LowCardinality(String) DEFAULT '',
    correlation_id  UUID,
    version         UInt32,
    from_node       String,                  -- episode key: entity_type:entity_id:kind
    to_node         String,
    grounding_kind  Enum8('seam'=1,'topo'=2),
    grounding_ref   String,                  -- seam_id or topology node id
    weight          Float32,
    w_temporal      Float32,
    w_topo          Float32,
    w_reinforce     Float32,
    direction_conf  Float32,                 -- 0 = undirected co-occurrence
    direction_basis LowCardinality(String),  -- onset_order|topo_updown|layer_prior|mixed
    created_at      DateTime64(3) DEFAULT now64(3),
    CONSTRAINT grounding_ref_nonempty CHECK grounding_ref != ''
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(created_at))
ORDER BY (tenant_id, correlation_id, version, from_node, to_node);

-- 2.3 Evidence log — human-readable "why" per edge/hypothesis, written in the
-- same batch as the snapshot.
CREATE TABLE IF NOT EXISTS netops.corr_evidence
(
    tenant_id       LowCardinality(String) DEFAULT '',
    correlation_id  UUID,
    version         UInt32,
    subject_kind    Enum8('edge'=1,'hypothesis'=2,'app'=3),  -- 'app' = #81 P5 app-impact evidence
    subject_id      String,
    signal_id       UUID,
    role            Enum8('supports'=1,'contradicts'=2,'discriminates'=3),
    note            String,
    created_at      DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(created_at))
ORDER BY (tenant_id, correlation_id, version, subject_kind, subject_id);

-- 2.4 Application Identity Fusion (#81) — high-volume, vendor-NEUTRAL.
-- app_observations: one upstream identity opinion with full provenance (the ORIGINAL
-- vendor values are preserved; the raw log stays in OpenSearch — only a ref+hash here).
CREATE TABLE IF NOT EXISTS netops.app_observations
(
    tenant_id        LowCardinality(String) DEFAULT '',
    observation_id   UUID,                     -- deterministic per (source, scope, app, event_time)
    event_time       DateTime64(3),
    ingest_time      DateTime64(3) DEFAULT now64(3),
    source_type      LowCardinality(String),   -- ngfw|ipfix|proxy|ndr|workload|cloud|dns|sni|...
    vendor           LowCardinality(String) DEFAULT '',
    product          LowCardinality(String) DEFAULT '',
    device           LowCardinality(String) DEFAULT '',
    collector_version LowCardinality(String) DEFAULT '',
    parser_version   LowCardinality(String) DEFAULT '',
    flow_id          String DEFAULT '',
    session_id       String DEFAULT '',
    src_ip           String DEFAULT '',
    dst_ip           String DEFAULT '',
    src_port         UInt16 DEFAULT 0,
    dst_port         UInt16 DEFAULT 0,
    proto            LowCardinality(String) DEFAULT '',
    vendor_app_id    String DEFAULT '',        -- ORIGINAL vendor app-id (never discarded)
    vendor_app_name  String DEFAULT '',        -- ORIGINAL vendor name
    vendor_category  LowCardinality(String) DEFAULT '',
    vendor_risk      LowCardinality(String) DEFAULT '',
    method           LowCardinality(String) DEFAULT '',
    source           LowCardinality(String) DEFAULT '',  -- mapped onto the appid trust ladder
    confidence       Float64 DEFAULT 0,
    site             LowCardinality(String) DEFAULT '',
    interface        LowCardinality(String) DEFAULT '',
    user             String DEFAULT '',
    workload         String DEFAULT '',
    path             String DEFAULT '',
    seam             LowCardinality(String) DEFAULT '',
    raw_ref          String DEFAULT '',        -- pointer to the raw event (OpenSearch doc id)
    raw_hash         String DEFAULT '',        -- integrity hash, NOT the raw body
    bytes            UInt64 DEFAULT 0,
    packets          UInt64 DEFAULT 0
)
ENGINE = ReplacingMergeTree(ingest_time)       -- dedup by observation_id (idempotent re-ingest)
PARTITION BY (tenant_id, toYYYYMMDD(event_time))
ORDER BY (tenant_id, observation_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- app_identities: the fused, explainable result per scope + fusion version. Keyed by
-- (scope, catalog_version, fusion_version) so a catalog/engine bump yields a NEW
-- versioned row (replay reproducible) rather than rewriting history.
CREATE TABLE IF NOT EXISTS netops.app_identities
(
    tenant_id        LowCardinality(String) DEFAULT '',
    fusion_id        UUID,
    fused_at         DateTime64(3) DEFAULT now64(3),
    flow_id          String DEFAULT '',
    session_id       String DEFAULT '',
    workload_id      String DEFAULT '',
    correlation_id   String DEFAULT '',
    src_ip           String DEFAULT '',
    dst_ip           String DEFAULT '',
    dst_port         UInt16 DEFAULT 0,
    proto            LowCardinality(String) DEFAULT '',
    canonical_app_id String DEFAULT '',
    app              String DEFAULT 'unknown',          -- canonical name; 'unknown' first-class
    provider         LowCardinality(String) DEFAULT '',
    component        String DEFAULT '',
    app_protocol     LowCardinality(String) DEFAULT '', -- QUIC (a protocol, not the business app)
    transport        LowCardinality(String) DEFAULT '',
    tier             Enum8('undetermined'=0,'suspected'=1,'confirmed'=2),
    band             Enum8('unresolved'=0,'low'=1,'medium'=2,'high'=3,'authoritative'=4),
    state            Enum8('unknown'=0,'observed'=1,'inferred'=2,'fused'=3,'conflicted'=4),
    confidence       Float64 DEFAULT 0,
    contradicted     UInt8 DEFAULT 0,
    explanations     Array(LowCardinality(String)),
    alternatives     String DEFAULT '[]',               -- JSON [{app,confidence,band,sources}]
    evidence_missing Array(String),
    catalog_version  UInt32 DEFAULT 0,
    fusion_version   LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(fused_at)
PARTITION BY (tenant_id, toYYYYMMDD(fused_at))
ORDER BY (tenant_id, fusion_id)
TTL toDateTime(fused_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE ROW POLICY IF NOT EXISTS tenant_iso_flows ON netops.flows
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = ''
    TO ALL;
CREATE ROW POLICY IF NOT EXISTS tenant_iso_findings ON netops.findings
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = ''
    TO ALL;
CREATE ROW POLICY IF NOT EXISTS tenant_iso_tunnels ON netops.tunnels
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = ''
    TO ALL;
-- STRICT (2026-07-02): no untagged-shared clause — correlation intel carries
-- device names/hypotheses and has NO app-layer device narrowing on its read
-- paths, so untagged rows are PLATFORM-ONLY (strict tenancy model).
CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_signals ON netops.corr_signals
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL;
CREATE ROW POLICY IF NOT EXISTS tenant_iso_app_observations ON netops.app_observations
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = ''
    TO ALL;
CREATE ROW POLICY IF NOT EXISTS tenant_iso_app_identities ON netops.app_identities
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = ''
    TO ALL;
-- STRICT (2026-07-02): no untagged-shared clause — correlation intel carries
-- device names/hypotheses and has NO app-layer device narrowing on its read
-- paths, so untagged rows are PLATFORM-ONLY (strict tenancy model).
CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_signals_archive ON netops.corr_signals_archive
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL;
-- STRICT (2026-07-02): no untagged-shared clause — correlation intel carries
-- device names/hypotheses and has NO app-layer device narrowing on its read
-- paths, so untagged rows are PLATFORM-ONLY (strict tenancy model).
CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_objects ON netops.corr_objects
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL;
-- STRICT (2026-07-02): no untagged-shared clause — correlation intel carries
-- device names/hypotheses and has NO app-layer device narrowing on its read
-- paths, so untagged rows are PLATFORM-ONLY (strict tenancy model).
CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_edges ON netops.corr_edges
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL;
-- STRICT (2026-07-02): no untagged-shared clause — correlation intel carries
-- device names/hypotheses and has NO app-layer device narrowing on its read
-- paths, so untagged rows are PLATFORM-ONLY (strict tenancy model).
CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_evidence ON netops.corr_evidence
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL;
-- STRICT (2026-07-02): no untagged-shared clause — correlation intel carries
-- device names/hypotheses and has NO app-layer device narrowing on its read
-- paths, so untagged rows are PLATFORM-ONLY (strict tenancy model).
CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_current ON netops.corr_current
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL;
