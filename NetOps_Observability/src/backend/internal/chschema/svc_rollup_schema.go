// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

// svc_rollup_schema.go — #69 P2 service flow attribution rollup schema
// (front-page.md §3). Same converge-on-boot contract as corr_schema.go /
// path_schema.go: deployment/docker/clickhouse/init.sql carries the identical
// DDL for fresh installs and ensureCHRowPolicies() appends these statements so
// live deployments converge with no manual SQL. Idempotent.
//
// HARD RULE (the flows_hourly regression, see init.sql + flows_services.go):
// NO materialized view may read netops.flows — its tenant row policy is
// re-evaluated on every INSERT in the inserting connection's context (where
// tenant_scope is unset), erroring the insert and breaking ingestion. The
// rollup is therefore populated by a scheduled Go worker
// (svc_rollup_worker.go) that scans CLOSED minutes per tenant, and by the
// explicit audited selector-backfill job (svc_backfill.go). Never convert
// this into an MV.
//
// Contract pins (guarded by svc_rollup_schema_test.go):
//   - tenant_id leads PARTITION BY and ORDER BY (at-rest separation, #20 Ph3;
//     one rollup row can only ever belong to one tenant).
//   - service_id is Nullable(UUID) from day one (§3.2 no-schema-churn: Phase-1
//     heuristic rows may be NULL) — it sits in the sort key, hence
//     allow_nullable_key = 1.
//   - selector_version stamps WHICH selector version attributed the row (§3.3:
//     selector edits never rewrite history; backfill inserts NEW rows under
//     the new version, readers resolve latest-version-wins per minute).
//   - rolled_by ∈ {live, backfill}: the live roller's idempotency checkpoint
//     is max(minute) over rolled_by='live' rows, so a backfill of an old
//     window can never fast-forward the live checkpoint.
//   - seam_id is '' until flows carry seam attribution (#68) — honest, never
//     faked.
//   - STRICT row policy: attributed per-service traffic is tenant data; an
//     untagged row is platform-only, never shared into every tenant's view.

func SvcRollupSchemaDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS netops.svc_flow_rollup_1m
(
    tenant_id        LowCardinality(String) DEFAULT '',
    minute           DateTime,
    service_id       Nullable(UUID),
    selector_version UInt32,
    seam_id          LowCardinality(String) DEFAULT '',
    rolled_by        LowCardinality(String) DEFAULT 'live',
    bytes            UInt64,
    packets          UInt64,
    flows            UInt64
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY (tenant_id, toYYYYMMDD(minute))
ORDER BY (tenant_id, minute, service_id, selector_version, seam_id, rolled_by)
TTL minute + INTERVAL 90 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1, allow_nullable_key = 1`,

		StrictRowPolicyDDL("svc_flow_rollup_1m"),
	}
}
