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
//   - corr_signals_archive mirrors corr_signals + archiving provenance. Hot
//     retention is bounded (#101, corr_retention.go): the archive keeps
//     CORR_RETENTION_ARCHIVE_DAYS hot for replay/Inspector, and ages to the
//     cold Parquet tier (scripts/ch-cold-export.sh) instead of growing forever
//     (it hit 29.9M rows in the 2026-07-09 storm era). The original "archived
//     forever" freeze note is superseded by the retention contract:
//     docs/design/correlation-data-contract.md
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
                         'control_plane'=3,'device_telemetry'=4,
                         'management_plane'=5),
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

		// Read-path performance (2026-07-09 incident): every per-object read
		// (sweeper loadCorrSlice, replay slice, cloud app-rca) filters the archive
		// by archived_for, which is NOT in the sort key (tenant_id, ts, signal_id)
		// — each lookup full-scanned the table. At 27.8M rows with the 60s
		// ticketing sweeper that meant ~8 full scans/minute: ClickHouse pinned,
		// UI queries timed out (502s). The bloom-filter skip index prunes an
		// archived_for equality lookup to the object's own granules. New parts
		// index on write; existing parts need a one-time MATERIALIZE INDEX
		// (applied operationally — safe to re-run, see docs/UPGRADE.md).
		`ALTER TABLE netops.corr_signals_archive
    ADD INDEX IF NOT EXISTS idx_archived_for archived_for TYPE bloom_filter(0.01) GRANULARITY 4`,

		// Cloud App Observability as an evidence producer (#81 P3G): cloud signals
		// flow as corr_signals into the SAME engine. Additive enum widening — source
		// gains 'cloud'=9, entity_type gains 'app'=8/'cloud_resource'=9. MODIFY COLUMN
		// is safe for an Enum8 value-add (existing rows keep their mapping). Idempotent
		// self-heal for live tables (both signals + archive share signalColumns).
		// #81 P5: source gains 'app_identity'=10 — fused application identity as an
		// enrichment evidence producer on the SAME spine (additive Enum8 value-add).
		// NMS P6: source gains 'controller'=11, observer_type gains 'controller'=6
		// (controller-intelligence signal class).
		//
		// HARD RULE (2026-07-09 outage): these ALTERs must always list the FULL
		// enum — the superset of every value any deployment has ever had, kept
		// identical to init.sql (TestCorrSignalEnumsConsistent enforces it).
		// ClickHouse refuses an enum ALTER on a key column that drops a value, so
		// a stale (subset) ALTER fails on EVERY boot against a live table that
		// already learned the newer value — and stalls the converge list behind it
		// (this is how corr_current failed to be created on 2026-07-09).
		`ALTER TABLE netops.corr_signals MODIFY COLUMN source Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,'topology'=5,'syslog'=6,'sot_drift'=7,'trap'=8,'cloud'=9,'app_identity'=10,'controller'=11)`,
		`ALTER TABLE netops.corr_signals MODIFY COLUMN observer_type Enum8('device'=1,'vantage_agent'=2,'cloud_api'=3,'flow_exporter'=4,'platform'=5,'controller'=6)`,
		`ALTER TABLE netops.corr_signals MODIFY COLUMN entity_type Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,'site'=5,'service'=6,'prefix'=7,'app'=8,'cloud_resource'=9)`,
		`ALTER TABLE netops.corr_signals MODIFY COLUMN modality_class Enum8('active_probe'=1,'passive_flow'=2,'control_plane'=3,'device_telemetry'=4,'management_plane'=5)`,
		`ALTER TABLE netops.corr_signals_archive MODIFY COLUMN source Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,'topology'=5,'syslog'=6,'sot_drift'=7,'trap'=8,'cloud'=9,'app_identity'=10,'controller'=11)`,
		`ALTER TABLE netops.corr_signals_archive MODIFY COLUMN observer_type Enum8('device'=1,'vantage_agent'=2,'cloud_api'=3,'flow_exporter'=4,'platform'=5,'controller'=6)`,
		`ALTER TABLE netops.corr_signals_archive MODIFY COLUMN entity_type Enum8('device'=1,'interface'=2,'path'=3,'segment'=4,'site'=5,'service'=6,'prefix'=7,'app'=8,'cloud_resource'=9)`,
		`ALTER TABLE netops.corr_signals_archive MODIFY COLUMN modality_class Enum8('active_probe'=1,'passive_flow'=2,'control_plane'=3,'device_telemetry'=4,'management_plane'=5)`,

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
    app_impact       String DEFAULT '{}',
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

		// #81 P5: named application impact + honest evidence_missing (engine
		// ObjectSnapshot.app_impact). Idempotent ADD for live deployments — a pure
		// projection of the object's matched fused identities, default '{}', NOT in
		// content_hash (never churns a version).
		`ALTER TABLE netops.corr_objects
    ADD COLUMN IF NOT EXISTS app_impact String DEFAULT '{}' AFTER layer_coverage`,

		// CREATE OR REPLACE (not IF NOT EXISTS): a SELECT * view freezes its column
		// list at creation, so adding a base column (e.g. #81 P5 app_impact) would
		// otherwise leave the view stale and queries selecting the new column fail.
		// Replacing on every boot keeps the view's columns in lockstep with the table.
		`CREATE OR REPLACE VIEW netops.corr_objects_latest AS
SELECT * FROM netops.corr_objects
ORDER BY tenant_id, correlation_id, version DESC
LIMIT 1 BY tenant_id, correlation_id`,

		// #100 hardening: current-state projection for HOT reads. corr_objects is
		// the append-only history (replay/audit/Inspector); corr_current holds ONE
		// narrow row per live object so Command Center list pages read O(active
		// objects), not O(history). By design it carries NO wide blob columns
		// (hypotheses/layer_coverage/app_impact) — wide columns are fetched keyed
		// from corr_objects for the picked page only. Maintained by app-level
		// dual-write from the engine's _persist_snapshot (NOT a materialized view
		// — row policies break MV inserts, see freeze invariant above), so it
		// inherits the #100 damping: a storm writes at the damped rate here too.
		// ReplacingMergeTree keyed on created_at: the latest WRITE wins, which
		// also self-heals the engine-restart version reset (in-memory versions
		// restart at 1; a version-keyed fold would resurrect the stale pre-restart
		// row). Partitioned by tenant ONLY: the dedup key (tenant, correlation_id)
		// must never span partitions or FINAL cannot collapse it.
		`CREATE TABLE IF NOT EXISTS netops.corr_current
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
    owner            LowCardinality(String) DEFAULT '',
    plane_count      UInt8 DEFAULT 0,
    debug_excluded   UInt8 DEFAULT 0,
    low_authority    UInt8 DEFAULT 0,
    chaos_fixture    LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY (tenant_id)
ORDER BY (tenant_id, correlation_id)`,

		// Triage badges as NARROW projection columns (#100 completion): the list
		// page's owner / plane-count / debug-excluded / low-authority badges used
		// to be JSONExtract'd from the ~5.7KB hypotheses blob per poll — reading
		// ~1.3 GiB of blob granules per page even with a keyed fetch (measured:
		// 130 MiB / 1.35 GiB read per query, over the 100 MiB endpoint budget).
		// The engine now derives them once at persist time; the hot list path
		// never touches the blob column at all. ADD COLUMN converges deployments
		// whose corr_current predates the badges.
		`ALTER TABLE netops.corr_current ADD COLUMN IF NOT EXISTS catalog_version LowCardinality(String) DEFAULT '' AFTER engine_version`,
		`ALTER TABLE netops.corr_current ADD COLUMN IF NOT EXISTS owner LowCardinality(String) DEFAULT '' AFTER created_at`,
		`ALTER TABLE netops.corr_current ADD COLUMN IF NOT EXISTS plane_count UInt8 DEFAULT 0 AFTER owner`,
		`ALTER TABLE netops.corr_current ADD COLUMN IF NOT EXISTS debug_excluded UInt8 DEFAULT 0 AFTER plane_count`,
		`ALTER TABLE netops.corr_current ADD COLUMN IF NOT EXISTS low_authority UInt8 DEFAULT 0 AFTER debug_excluded`,

		// #101 chaos-fixture visibility: a named, INTENTIONAL storm source (e.g.
		// the lab .120 target kept dead on purpose) is tagged by the engine at
		// persist time so Command Center badges it and the ticketing sweeper
		// skips it. Narrow LowCardinality column — '' means "real incident".
		`ALTER TABLE netops.corr_current ADD COLUMN IF NOT EXISTS chaos_fixture LowCardinality(String) DEFAULT '' AFTER low_authority`,

		// One-time backfill from history (idempotent: the NOT IN makes a re-run a
		// no-op). Sanctioned #100 shape: the FOLD picks narrow keys only; the wide
		// hypotheses badge-extracts run ONLY in the outer read, keyed by the folded
		// (tenant, id, version) set — no blob ever crosses a sort. Runs at
		// tenant_scope=__all__ (chExec) so every tenant's objects seed. The same
		// statement is the missing-row half of the corr_current reconciler
		// (corr_current_reconcile.go), which also repairs DRIFTED rows on a timer.
		corrCurrentBackfillSQL(),

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
    subject_kind    Enum8('edge'=1,'hypothesis'=2,'app'=3),
    subject_id      String,
    signal_id       UUID,
    role            Enum8('supports'=1,'contradicts'=2,'discriminates'=3),
    note            String,
    created_at      DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(created_at))
ORDER BY (tenant_id, correlation_id, version, subject_kind, subject_id)`,

		// #81 P5: subject_kind gains 'app'=3 — an app-impact supporting-evidence row
		// (the fused identity that named an affected app). Additive Enum8 value-add;
		// safe even though subject_kind is in the sort key (existing values keep their
		// numbers → no reorder), mirroring the corr_signals.source widening.
		`ALTER TABLE netops.corr_evidence MODIFY COLUMN subject_kind Enum8('edge'=1,'hypothesis'=2,'app'=3)`,

		// #101 tenant write-amplification rollup — bounded-cardinality storm
		// attribution. The correlation engine flushes one row per (tenant,
		// window) with raw/persisted/damped counts + the dominant kind/entity,
		// so operators can answer "which tenant/source is generating this
		// storm?" from SQL without per-tenant Prometheus label cardinality.
		// Small by construction (tenants × windows); fixed 30-day TTL.
		`CREATE TABLE IF NOT EXISTS netops.corr_tenant_write_amp
(
    tenant_id          LowCardinality(String) DEFAULT '',
    window_start       DateTime64(3),
    window_s           UInt32,
    raw_seen           UInt64,
    persisted          UInt64,
    damped             UInt64,
    damping_ratio      Float32,
    top_signal_kind    LowCardinality(String) DEFAULT '',
    top_entity         String DEFAULT '',
    open_objects       UInt32 DEFAULT 0,
    max_incident_age_s UInt32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(window_start))
ORDER BY (tenant_id, window_start)
TTL toDateTime(window_start) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		chRowPolicyDDL("corr_signals"),
		chRowPolicyDDL("corr_signals_archive"),
		chRowPolicyDDL("corr_objects"),
		chRowPolicyDDL("corr_edges"),
		chRowPolicyDDL("corr_evidence"),
		// STRICT policy (2026-07-02 model, matching init.sql's corr policies): NO
		// untagged-shared clause — correlation intel is platform-only when
		// untagged. The generic chRowPolicyDDL is the loose telemetry variant and
		// would leak platform-global objects into every tenant's Command Center.
		`CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_current ON netops.corr_current
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL`,
		// Same strict model for the write-amp rollup: a tenant may see its own
		// storm accounting; platform-global (untagged '') rows are platform-only.
		`CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_tenant_write_amp ON netops.corr_tenant_write_amp
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL`,
	}
}
