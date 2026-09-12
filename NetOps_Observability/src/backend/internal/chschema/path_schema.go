// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

import "strconv"

// path_schema.go — Service Path Graph ClickHouse schema (frozen contract v1,
// docs/design/service-path-graph-contract.md §2.3/§2.4). Same converge-on-boot
// contract as corr_schema.go: deployment/docker/clickhouse/init.sql carries the
// identical DDL for fresh installs, and ensureCHRowPolicies() appends these
// statements so live deployments converge with no manual SQL. Idempotent.
//
// WHY CLICKHOUSE (and not Postgres) for these two:
//   - PathObservation is IMMUTABLE and one row is written PER MEASUREMENT RUN, per
//     path, per vantage, per protocol, forever. Route-change history IS the feature
//     (§8) — there is no update-in-place, ever.
//   - PathHop multiplies that by the hop count.
// That is an append-only, high-cardinality, time-ordered analytical stream: an OLAP
// shape. The registries it references (Endpoint, PathDefinition) have mutable
// validity windows and relational lookups, so they stay in Postgres (migration
// 0023) under FORCE-RLS.
//
// Column types are LowCardinality(String), NOT Enum8, on purpose: the 2026-07-09
// outage was an enum ALTER on a key column stalling the whole converge list. A
// string with a documented value set costs a little compression and buys immunity
// from that class of failure.

// pathRetentionDays bounds the hot observation history. The contract wants history,
// not immortality: the cold tier (scripts/ch-cold-export.sh) is where old runs go.
const pathRetentionDays = 90

func PathSchemaDDL() []string {
	return []string{
		// §2.3 — one IMMUTABLE row per measurement run. ReplacingMergeTree keyed on
		// ingest_ts makes RE-INGEST of the same observation_id idempotent (§9
		// reliability) without ever mutating the measurement itself: a re-delivered
		// run collapses onto itself, two different runs never collapse (distinct
		// observation_id).
		`CREATE TABLE IF NOT EXISTS netops.path_observations
(
    tenant_id        LowCardinality(String) DEFAULT '',
    observation_id   String,
    path_id          String,
    observed_at      DateTime64(3),
    method           LowCardinality(String),   -- traceroute_icmp|traceroute_tcp|stamp|transaction|flow_stitch
    vantage_id       LowCardinality(String),
    status           LowCardinality(String),   -- complete|partial|failed
    hop_count        UInt16,
    src_address      String DEFAULT '',
    dst_address      String DEFAULT '',
    protocol         LowCardinality(String) DEFAULT '',
    dst_port         UInt16 DEFAULT 0,
    direction        LowCardinality(String) DEFAULT 'forward',
    network_context  LowCardinality(String) DEFAULT '',
    -- §1 provenance (immutable; run_id REQUIRED on an observation)
    data_class       LowCardinality(String) DEFAULT 'live',   -- live|synthetic|replay|lab
    environment      LowCardinality(String) DEFAULT 'prod',
    scenario_id      LowCardinality(String) DEFAULT '',
    run_id           String DEFAULT '',
    producer_id      LowCardinality(String) DEFAULT '',
    provenance_id    String DEFAULT '',
    contract_version UInt16 DEFAULT 1,
    ingest_ts        DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMM(observed_at))
ORDER BY (tenant_id, path_id, observed_at, observation_id)
TTL toDateTime(observed_at) + INTERVAL ` + strconv.Itoa(pathRetentionDays) + ` DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// §2.4 — ordered hops. hop_index is the SPINE ORDER: it is data, not layout.
		// A non-responding hop is PRESERVED with state=missing and an empty address —
		// the sort key keeps it in place, and nothing downstream may drop it.
		`CREATE TABLE IF NOT EXISTS netops.path_hops
(
    tenant_id           LowCardinality(String) DEFAULT '',
    observation_id      String,
    hop_index           UInt16,
    state               LowCardinality(String),          -- responding|missing|filtered
    observed_address    String DEFAULT '',               -- '' when state != responding (the hop is PRESERVED)
    resolved_entity_ref String DEFAULT '',
    resolution_method   LowCardinality(String) DEFAULT 'unresolved',
    confidence          LowCardinality(String) DEFAULT 'unknown',
    kind                LowCardinality(String) DEFAULT 'unknown',
    network_context     LowCardinality(String) DEFAULT '',
    seam_id             LowCardinality(String) DEFAULT '',
    rtt_ms              Float32 DEFAULT 0,
    loss_pct            Float32 DEFAULT 0,
    transformation      LowCardinality(String) DEFAULT 'none', -- none|nat|proxy|load_balancer|tunnel_ingress|tunnel_egress
    candidate_ref       String DEFAULT '',               -- rank-7 lead ONLY; never an edge (§3)
    evidence_ref        String DEFAULT '',
    observed_at         DateTime64(3),
    data_class          LowCardinality(String) DEFAULT 'live',
    ingest_ts           DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY (tenant_id, toYYYYMM(observed_at))
ORDER BY (tenant_id, observation_id, hop_index)
TTL toDateTime(observed_at) + INTERVAL ` + strconv.Itoa(pathRetentionDays) + ` DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		// STRICT row policy (the corr_current model, NOT the loose telemetry one):
		// path data is never shared with a tenant just because it is untagged. An
		// untagged ('') row is platform-only. §9: no endpoint resolution, edge,
		// observation or API response crosses tenants. CREATE OR REPLACE (atomic,
		// never DROP+CREATE) so a drifted/legacy policy is upgraded in place.
		StrictRowPolicyDDL("path_observations"),
		StrictRowPolicyDDL("path_hops"),
	}
}
