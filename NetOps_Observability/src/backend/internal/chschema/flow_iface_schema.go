// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

// flow_iface_schema.go — tracker 401 (a)(b): the per-interface flow rollup and
// the flow columns it is built from. Same converge-on-boot contract as
// svc_rollup_schema.go: deployment/docker/clickhouse/init.sql carries the
// identical DDL for fresh installs and ConvergeStmts appends these statements so
// live deployments converge with no manual SQL. Idempotent and additive: no
// existing row is rewritten or dropped.
//
// HARD RULE (the flows_hourly regression): NO materialized view may read
// netops.flows. The rollup is written by the flowquery Roller with INSERT …
// SELECT at the platform scope (internal/flowquery/rollup.go). Never convert it
// into an MV.
//
// Contract pins (guarded by flow_iface_schema_test.go):
//   - Every row keeps its SOURCE record's tenant_id and sampler_address, under
//     the same column names as netops.flows, so a read predicate written for
//     raw rows (the stricter links ownership rule) works on rollup rows
//     unchanged. tenant_id leads PARTITION BY and ORDER BY.
//   - LENIENT row policy, exactly like netops.flows: untagged ('') rows exist
//     in both, and the app-layer ownership clause narrows them identically.
//   - ReplacingMergeTree(version): the Roller re-rolls a received minute that
//     late records reached by inserting the WHOLE minute again under a higher
//     version; readers use FINAL.
//   - records counts each source record once (in its received minute, on both
//     direction rows); bytes/packets are split across the minutes the flow
//     covered (flowquery/source.go). bytes/packets are scaled by the REPORTED
//     sampling rate only (rate_reported = 1); declared sampling is applied at
//     read time, so a changed declaration needs no re-roll.
//   - platform_sig: the platform-address set the `platform` flag was computed
//     with; rows from another set are never read and get re-rolled.
//   - Retention follows netops.flows (RetentionDDL, keyed on recv_minute).

// FlowColumnsDDL adds the tracker 401 (b) columns to netops.flows. goflow2
// already sends observation_domain_id and time_flow_start_ns/end_ns;
// vector-router maps them to these columns and Vector's clickhouse sink
// (skip_unknown_fields) starts filling them as soon as they exist. A row older
// than the columns reads odid 0 and an epoch-0 start/end ("no duration").
func FlowColumnsDDL() []string {
	return []string{
		"ALTER TABLE netops.flows ADD COLUMN IF NOT EXISTS odid UInt32 DEFAULT 0 AFTER sampler_address",
		"ALTER TABLE netops.flows ADD COLUMN IF NOT EXISTS flow_start DateTime64(3) DEFAULT toDateTime64(0, 3) CODEC(DoubleDelta, LZ4)",
		"ALTER TABLE netops.flows ADD COLUMN IF NOT EXISTS flow_end DateTime64(3) DEFAULT toDateTime64(0, 3) CODEC(DoubleDelta, LZ4)",
	}
}

// FlowIfaceSchemaDDL is the rollup table and its row policy.
func FlowIfaceSchemaDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS netops.flow_iface_1m
(
    tenant_id       LowCardinality(String) DEFAULT '',
    minute          DateTime,
    recv_minute     DateTime,
    sampler_address String,
    odid            UInt32,
    ifindex         UInt32,
    direction       LowCardinality(String),
    flow_type       LowCardinality(String) DEFAULT 'unknown',
    rate_reported   UInt8,
    platform        UInt8,
    platform_sig    UInt64,
    bytes           UInt64,
    packets         UInt64,
    records         UInt64,
    version         UInt64
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY (tenant_id, toYYYYMMDD(recv_minute))
ORDER BY (tenant_id, recv_minute, sampler_address, ifindex, direction, minute, odid, flow_type, rate_reported, platform, platform_sig)
TTL recv_minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		RowPolicyDDL("flow_iface_1m"),
	}
}
