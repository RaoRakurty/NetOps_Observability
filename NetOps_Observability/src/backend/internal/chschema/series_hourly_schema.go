// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

// series_hourly_schema.go — tracker 337 N-H6 PR 2: the hourly roll-up of the
// metric series Iris's seasonal baselines read, so a profile can reach further
// back than VictoriaMetrics' retention (30 d by default) and an estate-wide
// "what is abnormal for this time of week" can be answered from one table.
// Same converge-on-boot contract as flow_iface_schema.go: both init.sql copies
// carry the identical DDL for fresh installs and ConvergeStmts appends it so
// live deployments converge with no manual SQL.
//
// Contract pins (series_hourly_schema_test.go):
//   - tenant_id leads PARTITION BY and ORDER BY; the worker stamps it from the
//     device's inventory owner and NEVER writes '' — an unowned series is
//     skipped and counted.
//   - STRICT row policy: a row is visible only to its own tenant or to an
//     explicit cross-tenant scope (there are no untagged rows to share).
//   - ReplacingMergeTree(version): re-rolling an hour inserts it again under a
//     higher version, so a re-run replaces instead of adding; readers use FINAL.
//   - Retention 63 days (nine weeks: the seasonal profile's four weeks with
//     room to spare), fixed like iface_names — a roll-up, cheap to rebuild.

// SeriesHourlySchemaDDL is the roll-up table and its STRICT row policy.
func SeriesHourlySchemaDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS netops.series_hourly
(
    tenant_id   LowCardinality(String),
    metric      LowCardinality(String),
    entity_key  String,
    hour        DateTime,
    p10         Float64,
    p50         Float64,
    p90         Float64,
    n           UInt32,
    version     UInt64
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY (tenant_id, toYYYYMM(hour))
ORDER BY (tenant_id, metric, entity_key, hour)
TTL hour + INTERVAL 63 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,

		StrictRowPolicyDDL("series_hourly"),
	}
}
