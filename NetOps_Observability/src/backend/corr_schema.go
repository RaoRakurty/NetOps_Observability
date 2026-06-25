package main

// corr_schema.go — Correlation Engine v2 (#67) ClickHouse schema, FROZEN at
// build step ① (2026-06-11). docs/design/correlation-engine.md §2 is the spec;
// deployment/docker/clickhouse/init.sql carries the same DDL for fresh installs;
// this file converges live deployments (ensureCHRowPolicies appends these
// statements to its self-healing bootstrap). Idempotent by construction.
//
// Freeze invariants (guarded by corr_schema_test.go):
//   - every table is tenant-partitioned (tenant_id leads the PARTITION BY)
//   - corr_signals carries the MANDATORY observer block (observer_id/type/
//     location/trust_domain, collection_path, modality_class,
//     source_clock_quality) with CHECK observer_id != '' — the evidence-
//     independence gate (§4.5) and fate-sharing analysis depend on it
//   - corr_signals_archive mirrors corr_signals + archiving provenance, NO TTL:
//     replay re-runs over signals, so every persisted object's full window
//     slice is archived forever while the hot spine keeps a 30-day TTL
//   - corr_objects carries catalog_version (replay contract, research C6)
//     and verdict_tier + evidence_missing (pre-freeze amendments)
//   - corr_edges grounding_ref carries a CHECK nonempty constraint — non-Nullable
//     alone is NOT enough (ClickHouse coerces NULL→default '' on insert via
//     input_format_null_as_default), so the grounded-edges hard constraint is
//     enforced by CHECK, verified live at freeze time
//   - NO materialized view reads these tables (row policies break MV inserts)

func corrSchemaDDL() []string {
	// Shared column block: corr_signals (hot spine, 30 d TTL) and
	// corr_signals_archive (replay input, no TTL) must stay structurally
	// identical — replay reads archive ∪ hot deduped by signal_id.
	const signalColumns = `    tenant_id      LowCardinality(String) DEFAULT '',
    signal_id      UUID,
    ts             DateTime64(3),
    ingest_ts      DateTime64(3) DEFAULT now64(3),
    source         Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,
                         'topology'=5,'syslog'=6,'sot_drift'=7,'trap'=8,'cloud'=9),
    kind           LowCardinality(String),
    observer_id    LowCardinality(String),
    observer_type  Enum8('device'=1,'vantage_agent'=2,'cloud_api'=3,
                         'flow_exporter'=4,'platform'=5),
    observer_location     LowCardinality(String) DEFAULT '',
    observer_trust_domain LowCardinality(String) DEFAULT '',
    collection_path       LowCardinality(String) DEFAULT 'direct',
    modality_class Enum8('active_probe'=1,'passive_flow'=2,
                         'control_plane'=3,'device_telemetry'=4),
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
    attrs          String DEFAULT '{}'`

	return []string{
		`CREATE TABLE IF NOT EXISTS netops.corr_signals
(
` + signalColumns + `,
    CONSTRAINT observer_required CHECK observer_id != ''
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, ts, source, entity_type, entity_id)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192`,

		// Replay input archive: the FULL window slice of every persisted object
		// (not just attached signals — candidate-pool decisions depend on
		// non-attached episodes). Written at pipeline stage [8]; never TTLed.
		`CREATE TABLE IF NOT EXISTS netops.corr_signals_archive
(
` + signalColumns + `,
    archived_for     UUID,
    archived_version UInt32 DEFAULT 0,
    archived_at      DateTime64(3) DEFAULT now64(3),
    CONSTRAINT observer_required CHECK observer_id != ''
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(ts))
ORDER BY (tenant_id, ts, signal_id)
SETTINGS index_granularity = 8192`,

		// Replay correctness (#67 basic-testing fix 2026-06-12): slices must be
		// version-scoped — replaying version N over the UNION of every version's
		// window reports spurious drift whenever the window changed shape between
		// persists. 0 = legacy pre-fix rows (replay falls back to the deduped
		// union for those, documented). Idempotent self-heal for live tables.
		`ALTER TABLE netops.corr_signals_archive
    ADD COLUMN IF NOT EXISTS archived_version UInt32 DEFAULT 0 AFTER archived_for`,

		// Cloud App Observability as an evidence producer (#81 P3G): cloud signals
		// flow as corr_signals into the SAME engine. Additive enum widening — source
		// gains 'cloud'=9, entity_type gains 'app'=8/'cloud_resource'=9. MODIFY COLUMN
		// is safe for an Enum8 value-add (existing rows keep their mapping). Idempotent
		// self-heal for live tables (both signals + archive share signalColumns).
		`ALTER TABLE netops.corr_signals MODIFY COLUMN source Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,'topology'=5,'syslog'=6,'sot_drift'=7,'trap'=8,'cloud'=9)`,
		`ALTER TABLE netops.corr_signals MODIFY COLUMN entity_type Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,'site'=5,'service'=6,'prefix'=7,'app'=8,'cloud_resource'=9)`,
		`ALTER TABLE netops.corr_signals_archive MODIFY COLUMN source Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,'topology'=5,'syslog'=6,'sot_drift'=7,'trap'=8,'cloud'=9)`,
		`ALTER TABLE netops.corr_signals_archive MODIFY COLUMN entity_type Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,'site'=5,'service'=6,'prefix'=7,'app'=8,'cloud_resource'=9)`,

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
    layer_coverage   String DEFAULT '{}',
    merged_into      Nullable(UUID),
    created_at       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(window_start))
ORDER BY (tenant_id, correlation_id, version)`,

		// C4: the causal-layer stack (engine ObjectSnapshot.layer_coverage) the RCA
		// Layer-Stack panel renders. Idempotent ADD for live deployments created
		// before C4 — a pure projection of the object's nodes, default '{}'.
		`ALTER TABLE netops.corr_objects
    ADD COLUMN IF NOT EXISTS layer_coverage String DEFAULT '{}' AFTER catalog_version`,

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
		chRowPolicyDDL("corr_signals_archive"),
		chRowPolicyDDL("corr_objects"),
		chRowPolicyDDL("corr_edges"),
		chRowPolicyDDL("corr_evidence"),
	}
}
