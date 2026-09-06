package chschema

// experience_schema.go — ClickHouse DDL for the DEM EXPERIENCE EVENT lane
// (tracker 254, design docs/design/DEM_2026-09-05.md §M.3). init.sql carries
// identical DDL for fresh installs and ConvergeStmts() appends these statements
// so live deployments converge on boot. KEEP THEM IN LOCKSTEP —
// ch_retention_test.go fails the build when the two disagree about a TTL.
//
// TWO TABLES, ONE LANE. Producers post to the api, which publishes onto the
// `netops.experience` topic; vector-router consumes it and splits on
// `record_type` into:
//
//	experience_events  one thing that happened to one actor (a page view, an
//	                   interaction, an api call, an error, a web vital). High
//	                   volume, short horizon.
//	business_events    one business outcome (a purchase, a booking, a claim).
//	                   Low volume, long horizon: it is the denominator of
//	                   "what did this outage cost", which is a question asked
//	                   months later.
//
// ROW POLICIES ARE STRICT. An experience event is per-tenant data about that
// tenant's own users — much of it classified `pseudonymous_user` — so an
// untagged row is platform-only and is NEVER shared into every tenant's view.
// The lenient telemetry policy (RowPolicyDDL) would be a cross-tenant leak here
// and must never be used for these two tables.
//
// PRIVACY (design §M.8, dem-privacy.md). `user_ref` is a per-tenant
// pseudonymous reference and the api REFUSES anything that looks like a direct
// identifier before it ever reaches the bus. `data_class` travels with every
// row so retention and the AI redactor read the same label the producer
// declared. The default horizon is 30 days for the same reason the wireless
// per-client tier's is: this is user-behaviour data, and a short default is a
// privacy decision, not merely a cost one.

// ExperienceSchemaDDL is the experience-event lane's tables and their STRICT
// tenant row policies.
func ExperienceSchemaDDL() []string {
	return []string{
		// One row per ExperienceEvent. `event_id` is the producer's id and the
		// engine is ReplacingMergeTree over (tenant, event_id): the bus is
		// at-least-once, so a redelivered beacon must collapse rather than
		// double-count a user's bad minute.
		//
		// The free-form maps (feature_flags, business_context) are Map(String,
		// String) rather than JSON columns: they are bounded at 24 entries at
		// the api boundary, they are filtered on by key, and a JSON column
		// would invite an unbounded document where a measurement belongs.
		`CREATE TABLE IF NOT EXISTS netops.experience_events
(
    tenant_id        LowCardinality(String) DEFAULT '',
    event_id         String,
    session_id       String DEFAULT '',
    user_ref         String DEFAULT '',
    app              LowCardinality(String) DEFAULT '',
    environment      LowCardinality(String) DEFAULT '',
    release          LowCardinality(String) DEFAULT '',
    event_type       LowCardinality(String) DEFAULT '',
    action           String DEFAULT '',
    route            String DEFAULT '',
    success          Bool DEFAULT false,
    duration_ms      Nullable(Float64),
    error            String DEFAULT '',
    status_code      UInt16 DEFAULT 0,
    lcp_ms           Nullable(Float64),
    inp_ms           Nullable(Float64),
    cls              Nullable(Float64),
    ttfb_ms          Nullable(Float64),
    fcp_ms           Nullable(Float64),
    journey_id       String DEFAULT '',
    step_id          String DEFAULT '',
    actor_type       LowCardinality(String) DEFAULT 'HUMAN',
    cohort_site      LowCardinality(String) DEFAULT '',
    cohort_isp       LowCardinality(String) DEFAULT '',
    cohort_region    LowCardinality(String) DEFAULT '',
    cohort_device    LowCardinality(String) DEFAULT '',
    cohort_browser   LowCardinality(String) DEFAULT '',
    cohort_version   LowCardinality(String) DEFAULT '',
    cohort_network   LowCardinality(String) DEFAULT '',
    feature_flags    Map(String, String),
    business_context Map(String, String),
    trace_id         String DEFAULT '',
    span_id          String DEFAULT '',
    source           LowCardinality(String) DEFAULT 'rum',
    producer         String DEFAULT '',
    observation      LowCardinality(String) DEFAULT 'observed',
    data_class       LowCardinality(String) DEFAULT 'customer_metadata',
    schema_name      LowCardinality(String) DEFAULT '',
    schema_version   UInt16 DEFAULT 0,
    event_at         DateTime64(3),
    observed_at      DateTime64(3),
    ingest_ts        DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMMDD(event_at))
ORDER BY (tenant_id, app, event_at, event_id)
TTL toDateTime(event_at) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// One row per BusinessEvent. `business_event_type` is deliberately a
		// free string (a tenant's business is not e-commerce by default), and
		// `value`/`currency` travel together — the api refuses a value with no
		// currency, because an unlabelled number is not an amount.
		`CREATE TABLE IF NOT EXISTS netops.business_events
(
    tenant_id           LowCardinality(String) DEFAULT '',
    event_id            String,
    business_event_type LowCardinality(String) DEFAULT '',
    app                 LowCardinality(String) DEFAULT '',
    journey_id          String DEFAULT '',
    session_id          String DEFAULT '',
    success             Bool DEFAULT false,
    value               Nullable(Float64),
    currency            LowCardinality(String) DEFAULT '',
    quantity            UInt32 DEFAULT 0,
    cohort_site         LowCardinality(String) DEFAULT '',
    cohort_isp          LowCardinality(String) DEFAULT '',
    cohort_region       LowCardinality(String) DEFAULT '',
    cohort_device       LowCardinality(String) DEFAULT '',
    cohort_browser      LowCardinality(String) DEFAULT '',
    cohort_version      LowCardinality(String) DEFAULT '',
    cohort_network      LowCardinality(String) DEFAULT '',
    attributes          Map(String, String),
    source              LowCardinality(String) DEFAULT 'manual',
    producer            String DEFAULT '',
    observation         LowCardinality(String) DEFAULT 'observed',
    data_class          LowCardinality(String) DEFAULT 'customer_metadata',
    schema_name         LowCardinality(String) DEFAULT '',
    schema_version      UInt16 DEFAULT 0,
    event_at            DateTime64(3),
    observed_at         DateTime64(3),
    ingest_ts           DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMMDD(event_at))
ORDER BY (tenant_id, app, event_at, event_id)
TTL toDateTime(event_at) + INTERVAL 400 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// STRICT policies: user-behaviour data, much of it pseudonymous_user.
		// An untagged row is platform-only, never every tenant's.
		StrictRowPolicyDDL("experience_events"),
		StrictRowPolicyDDL("business_events"),
	}
}
