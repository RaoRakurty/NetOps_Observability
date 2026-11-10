// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

// iface_names_schema.go: the interface-name table flows are named through at
// query time (tracker 387 PR 13b). Same converge-on-boot contract as
// svc_rollup_schema.go: deployment/docker/clickhouse/init.sql (and the helm
// copy) carry the identical DDL for fresh installs, and ConvergeStmts appends
// these so a live install converges with no manual SQL. Idempotent.
//
// One row per (tenant, exporter address, ifIndex): the name the device's own
// IF-MIB reports for that index today. The API owns every write
// (iface_names_export.go), from the ifIndex bridge the SNMP collector already
// publishes; tenant_id is the DEVICE's tenant from inventory, never a request
// value. exporter_addr is the device's management address, which is the
// sampler_address the flows lane keys its tenant on.
//
// WHY A TABLE AND A JOIN, NOT A DICTIONARY (measured 2026-11-09 against the
// deployed clickhouse-server 24.8 image): a dictionary's SOURCE(CLICKHOUSE)
// load runs as the `default` user, which our installs do not have (the image
// keeps only CLICKHOUSE_USER), so it loads as FAILED/AUTHENTICATION_FAILED; the
// only fix is a USER/PASSWORD clause, which writes the ClickHouse credential
// into the dictionary's on-disk metadata (CLAUDE.md §8). A FILE source is the
// geoip_country failure mode (FILE_DOESNT_EXIST on the lab). So the flows
// queries LEFT JOIN this table, which also means its row policy applies to the
// names themselves under the caller's tenant_scope: stricter than a dictionary,
// whose internal load bypasses row policies.
//
// The JOIN key is the flow ROW's own tenant_id, sampler_address and ifIndex,
// so a lookup can only ever return a name of the tenant that owns the row; the
// policy below then also drops another tenant's names from a scoped caller.
//
// Row policy: LENIENT, like netops.flows. A platform device's names (the
// empty tenant) must name the platform-owned flow rows every tenant may already see;
// the app-layer address clause on the flows side is what narrows those rows.
// TTL: a row a feeder stops refreshing (a device removed, an index gone) ages
// out after 8 days; the exporter re-writes every live row well inside that.
func IfaceNamesSchemaDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS netops.iface_names
(
    tenant_id     LowCardinality(String) DEFAULT '',
    device_id     String,
    exporter_addr String,
    ifindex       UInt32,
    ifname        String,
    ifalias       String DEFAULT '',
    source        LowCardinality(String) DEFAULT 'snmp',
    updated       DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY (tenant_id, exporter_addr, ifindex)
TTL updated + INTERVAL 8 DAY
SETTINGS index_granularity = 8192`,

		RowPolicyDDL("iface_names"),
	}
}
