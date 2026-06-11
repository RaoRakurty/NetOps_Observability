package main

// corr_schema.go — Correlation Engine v2 (#67) ClickHouse schema, FROZEN at
// build step ① (2026-06-11). docs/design/correlation-engine.md §2 is the spec;
// deployment/docker/clickhouse/init.sql carries the same DDL for fresh installs;
// this file converges live deployments (ensureCHRowPolicies appends these
// statements to its self-healing bootstrap). Idempotent by construction.
//
// Freeze invariants (guarded by corr_schema_test.go):
//   - every table is tenant-partitioned (tenant_id leads the PARTITION BY)
//   - corr_signals carries observer_id (evidence-independence gate, §4.5)
//   - corr_objects carries catalog_version (replay contract, research C6)
//     and verdict_tier + evidence_missing (pre-freeze amendments)
//   - corr_edges grounding_ref carries a CHECK nonempty constraint — non-Nullable
//     alone is NOT enough (ClickHouse coerces NULL→default '' on insert via
//     input_format_null_as_default), so the grounded-edges hard constraint is
//     enforced by CHECK, verified live at freeze time
//   - NO materialized view reads these tables (row policies break MV inserts)

func corrSchemaDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS netops.corr_signals
(
    tenant_id      LowCardinality(String) DEFAULT '',
    signal_id      UUID,
    ts             DateTime64(3),
    ingest_ts      DateTime64(3) DEFAULT now64(3),
    source         Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,
                         'topology'=5,'syslog'=6,'sot_drift'=7),
    kind           LowCardinality(String),
    observer_id    LowCardinality(String) DEFAULT '',
    entity_type    Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,
                         'site'=5,'service'=6,'prefix'=7),
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
    attrs          String DEFAULT '{}'
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, ts, source, entity_type, entity_id)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192`,

		`CREATE TABLE IF NOT EXISTS netops.corr_objects
(
    tenant_id        LowCardinality(String) DEFAULT '',
    correlation_id   UUID,
    version          UInt32,
    state            Enum8('open'=1,'closed'=2,'merged'=3),
    window_start     DateTime64(3),
    window_end       DateTime64(3),
    trigger_signal   UUID,
    top_hypothesis   String,
    top_confidence   Float32,
    verdict_tier     Enum8('undetermined'=0,'suspected'=1,'confirmed'=2),
    hypotheses       String,
    evidence_missing String DEFAULT '[]',
    affected         String,
    signal_count     UInt32,
    node_count       UInt16,
    engine_version   LowCardinality(String),
    topology_version LowCardinality(String),
    catalog_version  LowCardinality(String),
    merged_into      Nullable(UUID),
    created_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(window_start))
ORDER BY (tenant_id, correlation_id, version)`,

		`CREATE VIEW IF NOT EXISTS netops.corr_objects_latest AS
SELECT * FROM netops.corr_objects
ORDER BY tenant_id, correlation_id, version DESC
LIMIT 1 BY tenant_id, correlation_id`,

		`CREATE TABLE IF NOT EXISTS netops.corr_edges
(
    tenant_id       LowCardinality(String) DEFAULT '',
    correlation_id  UUID,
    version         UInt32,
    from_node       String,
    to_node         String,
    grounding_kind  Enum8('seam'=1,'topo'=2),
    grounding_ref   String,
    weight          Float32,
    w_temporal      Float32,
    w_topo          Float32,
    w_reinforce     Float32,
    direction_conf  Float32,
    direction_basis LowCardinality(String),
    created_at      DateTime64(3) DEFAULT now64(3),
    CONSTRAINT grounding_ref_nonempty CHECK grounding_ref != ''
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(created_at))
ORDER BY (tenant_id, correlation_id, version, from_node, to_node)`,

		`CREATE TABLE IF NOT EXISTS netops.corr_evidence
(
    tenant_id       LowCardinality(String) DEFAULT '',
    correlation_id  UUID,
    version         UInt32,
    subject_kind    Enum8('edge'=1,'hypothesis'=2),
    subject_id      String,
    signal_id       UUID,
    role            Enum8('supports'=1,'contradicts'=2,'discriminates'=3),
    note            String,
    created_at      DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(created_at))
ORDER BY (tenant_id, correlation_id, version, subject_kind, subject_id)`,

		chRowPolicyDDL("corr_signals"),
		chRowPolicyDDL("corr_objects"),
		chRowPolicyDDL("corr_edges"),
		chRowPolicyDDL("corr_evidence"),
	}
}
