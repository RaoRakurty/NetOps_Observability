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
    time_received_ns UInt64,
    sampler_address String,
    src_addr        String,
    dst_addr        String,
    src_port        UInt16,
    dst_port        UInt16,
    proto           UInt8,
    bytes           UInt64,
    packets         UInt64,
    in_if           UInt32,
    out_if          UInt32,
    src_as          UInt32,
    dst_as          UInt32,
    sampling_rate   UInt32,
    vlan_id         UInt16,
    flow_type       LowCardinality(String) DEFAULT 'unknown',  -- netflow | ipfix | sflow
    tenant_id       LowCardinality(String) DEFAULT ''  -- #20: stamped at Vector ingest (device→tenant); '' = global
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, sampler_address, src_addr, dst_addr)
-- ts is DateTime64(3); TTL expressions must be Date/DateTime, so cast it.
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------------
-- Materialized rollups — top talkers per hour. Read off this for the
-- "Top Talkers (last 24h)" dashboard widget; ClickHouse keeps it warm.
-- ---------------------------------------------------------------------------

CREATE MATERIALIZED VIEW IF NOT EXISTS netops.flows_hourly
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, src_addr, dst_addr)
AS
SELECT
    toStartOfHour(ts)      AS hour,
    src_addr,
    dst_addr,
    sum(bytes  * sampling_rate) AS bytes_total,
    sum(packets * sampling_rate) AS packets_total,
    count()               AS flow_count
FROM netops.flows
GROUP BY hour, src_addr, dst_addr;

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
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, id)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

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
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, severity, score)
TTL toDateTime(ts) + INTERVAL 30 DAY;
