package chschema

// wireless_schema.go — ClickHouse DDL for the wireless per-client event tier
// (tracker #128 Phase 1, design docs/Wireslessdesign.md §20). init.sql carries
// identical DDL for fresh installs, and ensureCHRowPolicies() appends these
// statements so live deployments converge on boot. KEEP THEM IN LOCKSTEP.
//
// The three-tier storage split (report §20) — this file is tier 3 only:
//   inventory        → Postgres (migration 0030)
//   aggregate series → VictoriaMetrics (per-AP / per-radio ONLY)
//   per-client events→ THESE tables
//
// THE RULE: no per-client series in VictoriaMetrics, ever. A client MAC is a
// ClickHouse COLUMN (plain String in the sort key), never a metric label —
// 5 000 randomized MACs/day would mint 5 000 new VM series/day. Per-client RF
// is sampled at EVENT BOUNDARIES (associate / roam / disassociate / onboarding
// phase transition) and on demand during an open episode — never continuously.
//
// MLO model (report §10): a session is the MLD; links are children, and a
// non-MLO client is an MLO client with exactly one link — every query is
// written against wireless_mlo_links from day one so Wi-Fi 7 is not a later
// schema break.
//
// Row policies are STRICT (the corr_current model): an untagged row is
// platform-only, never shared into every tenant's view.

func WirelessSchemaDDL() []string {
	return []string{
		// One row per client association session. session_id is deterministic:
		// sha256(tenant|bssid|client_mac|assoc_start_ms) — replayable, never
		// ambiguous. client_id is the confidence-tagged cross-session rollup
		// (report §9.3): for a randomized-MAC client identity_confidence is
		// 'unknown' and cross-session history honestly does not exist.
		`CREATE TABLE IF NOT EXISTS netops.wireless_sessions
(
    tenant_id           LowCardinality(String) DEFAULT '',
    session_id          String,
    client_mac          String,
    mld_mac             String DEFAULT '',
    client_id           String DEFAULT '',
    identity_confidence LowCardinality(String) DEFAULT 'unknown',
    identity_method     LowCardinality(String) DEFAULT '',
    bssid               String,
    ap_ref              String DEFAULT '',
    radio_ref           String DEFAULT '',
    wlan_ref            String DEFAULT '',
    ssid_name           LowCardinality(String) DEFAULT '',
    username            String DEFAULT '',
    ip_v4               String DEFAULT '',
    ip_v6               String DEFAULT '',
    is_mlo              Bool DEFAULT false,
    link_count          UInt8 DEFAULT 1,
    assoc_start         DateTime64(3),
    assoc_end           Nullable(DateTime64(3)),
    end_reason          LowCardinality(String) DEFAULT '',
    observer_id         LowCardinality(String) DEFAULT '',
    collection_path     LowCardinality(String) DEFAULT 'via_controller',
    data_class          LowCardinality(String) DEFAULT 'live',
    ingest_ts           DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMMDD(assoc_start))
ORDER BY (tenant_id, session_id)
TTL toDateTime(assoc_start) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// Applicability-aware onboarding episodes (report §16): phases carry
		// applicable + outcome so a skipped step is NEVER a failure. The signal
		// rule (§20): terminal failures become corr_signals; successes stay
		// here for troubleshooting and never enter correlation.
		`CREATE TABLE IF NOT EXISTS netops.wireless_onboarding_episodes
(
    tenant_id        LowCardinality(String) DEFAULT '',
    episode_id       String,
    session_ref      String DEFAULT '',
    client_mac       String,
    bssid            String,
    ap_ref           String DEFAULT '',
    wlan_ref         String DEFAULT '',
    attempt_start    DateTime64(3),
    phases           String DEFAULT '[]',
    terminal_phase   LowCardinality(String) DEFAULT '',
    terminal_outcome LowCardinality(String) DEFAULT 'unknown',
    total_duration_ms UInt32 DEFAULT 0,
    observer_id      LowCardinality(String) DEFAULT '',
    collection_path  LowCardinality(String) DEFAULT 'via_controller',
    data_class       LowCardinality(String) DEFAULT 'live',
    ingest_ts        DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMMDD(attempt_start))
ORDER BY (tenant_id, episode_id)
TTL toDateTime(attempt_start) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// Roam events. Both the old and new AP may report one roam — the
		// producer dedupes on (client_mac, to_bssid, ts±uncertainty) before
		// insert; ReplacingMergeTree on the deterministic roam_id backstops it.
		`CREATE TABLE IF NOT EXISTS netops.wireless_roams
(
    tenant_id       LowCardinality(String) DEFAULT '',
    roam_id         String,
    client_mac      String,
    session_ref     String DEFAULT '',
    from_bssid      String DEFAULT '',
    to_bssid        String,
    from_ap_ref     String DEFAULT '',
    to_ap_ref       String DEFAULT '',
    roam_type       LowCardinality(String) DEFAULT 'unknown',
    duration_ms     UInt32 DEFAULT 0,
    ts              DateTime64(3),
    observer_id     LowCardinality(String) DEFAULT '',
    collection_path LowCardinality(String) DEFAULT 'via_controller',
    data_class      LowCardinality(String) DEFAULT 'live',
    ingest_ts       DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, roam_id)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// Wi-Fi 7 MLO links (report §10). One row per link per session;
		// link_state transitions re-insert with a fresh ingest_ts. Per-link RF
		// is NEVER averaged across links.
		`CREATE TABLE IF NOT EXISTS netops.wireless_mlo_links
(
    tenant_id         LowCardinality(String) DEFAULT '',
    link_id           String,
    session_ref       String,
    link_index        UInt8 DEFAULT 0,
    band              LowCardinality(String) DEFAULT '',
    radio_ref         String DEFAULT '',
    bssid_ref         String DEFAULT '',
    link_state        LowCardinality(String) DEFAULT 'active',
    rssi_dbm          Float32 DEFAULT 0,
    snr_db            Float32 DEFAULT 0,
    mcs               UInt8 DEFAULT 0,
    nss               UInt8 DEFAULT 0,
    channel           UInt16 DEFAULT 0,
    channel_width_mhz UInt16 DEFAULT 0,
    valid_from        DateTime64(3),
    valid_to          Nullable(DateTime64(3)),
    data_class        LowCardinality(String) DEFAULT 'live',
    ingest_ts         DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMM(valid_from))
ORDER BY (tenant_id, session_ref, link_id)
TTL toDateTime(valid_from) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// Per-client RF snapshots at EVENT BOUNDARIES only (report §20) —
		// associate, roam, disassociate, onboarding transition, or on-demand
		// while an episode is open on that client's AP. Never a continuous
		// series; that is what the per-AP/per-radio VictoriaMetrics tier is for.
		`CREATE TABLE IF NOT EXISTS netops.wireless_client_rf
(
    tenant_id       LowCardinality(String) DEFAULT '',
    client_mac      String,
    session_ref     String DEFAULT '',
    link_ref        String DEFAULT '',
    bssid           String DEFAULT '',
    ap_ref          String DEFAULT '',
    trigger         LowCardinality(String) DEFAULT '',
    rssi_dbm        Float32 DEFAULT 0,
    snr_db          Float32 DEFAULT 0,
    mcs             UInt8 DEFAULT 0,
    nss             UInt8 DEFAULT 0,
    tx_rate_mbps    Float32 DEFAULT 0,
    rx_rate_mbps    Float32 DEFAULT 0,
    retry_pct       Float32 DEFAULT 0,
    ts              DateTime64(3),
    observer_id     LowCardinality(String) DEFAULT '',
    collection_path LowCardinality(String) DEFAULT 'via_controller',
    data_class      LowCardinality(String) DEFAULT 'live',
    ingest_ts       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, client_mac, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// STRICT tenant policies — client sessions and RF are per-tenant PII
		// (report B5); an untagged row is platform-only, never shared.
		StrictRowPolicyDDL("wireless_sessions"),
		StrictRowPolicyDDL("wireless_onboarding_episodes"),
		StrictRowPolicyDDL("wireless_roams"),
		StrictRowPolicyDDL("wireless_mlo_links"),
		StrictRowPolicyDDL("wireless_client_rf"),
	}
}
