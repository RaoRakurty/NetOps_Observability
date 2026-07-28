package chschema

// chRowPolicyDDL is the LENIENT telemetry policy: untagged (tenant_id = ”)
// rows are shared into every tenant's view. Correct ONLY for the shared
// telemetry tables (flows, findings, tunnels) whose data model depends on
// untagged rows. NEVER use it for the correlation family — see
// StrictRowPolicyDDL.
// RowPolicyDDL renders the tenant row-policy DDL for one table.
func RowPolicyDDL(table string) string {
	return "CREATE ROW POLICY IF NOT EXISTS tenant_iso_" + table + " ON netops." + table +
		" USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = '' TO ALL"
}

// StrictRowPolicyDDL is the STRICT tenant policy (the 2026-07-02 init.sql
// model): NO untagged-shared clause — an untagged row is platform-only, never
// leaked into every tenant's view. It deliberately uses CREATE OR REPLACE
// (atomic in ClickHouse: no policyless window, unlike DROP+CREATE) so boot
// convergence UPGRADES a pre-2026-07-02 lenient policy in place instead of
// no-opping past it, and re-heals if /var/lib/clickhouse/access is ever reset.
// NOTE ON GRAMMAR (2026-07-21): the modifier goes AFTER "ROW POLICY" —
// `CREATE ROW POLICY OR REPLACE name ON ...`. The natural-looking
// `CREATE OR REPLACE ROW POLICY ...` is NOT valid ClickHouse: it parses as
// CREATE OR REPLACE {TABLE|VIEW|DICTIONARY|FUNCTION} and dies at 'ROW'. That
// typo shipped and every strict policy failed 1,560 times with SYNTAX_ERROR
// and never once succeeded, so boot convergence silently never ran: cloud_costs
// (per-tenant financial data) was left with NO row policy — the DB-layer
// backstop CLAUDE.md §3a rule 4 requires — and any install predating
// 2026-07-02 kept its lenient untagged-shared policy forever.
// chConvergeStmts is the complete, ordered boot-convergence DDL list. No
// network IO (env-only inputs) so tests can assert over the exact statements
// the boot path emits — e.g. that no correlation-family row policy carries
// the lenient untagged-shared escape.
// ConvergeStmts is the idempotent boot-convergence DDL set (#20 Phase 2
// policies + additive columns + the flows_hourly MV drop). extra lets the
// integrator append domain-owned converge DDL (e.g. the cloud-cost store's).
func ConvergeStmts(extra ...[]string) []string {
	stmts := []string{
		"DROP VIEW IF EXISTS netops.flows_hourly",
		// Build-order #7: tcpControlBits (IPFIX IE6) from goflow2. Vector's
		// clickhouse sink uses skip_unknown_fields, so the field starts landing
		// as soon as the column exists — no ingest change needed on upgrade.
		"ALTER TABLE netops.flows ADD COLUMN IF NOT EXISTS tcp_flags UInt16 DEFAULT 0 AFTER vlan_id",
		// Build-order #8: query-time IP→country enrichment. Lazy ip_trie
		// dictionary over the operator-supplied CSV (scripts/geoip-prepare.py);
		// safe to create with the file absent — the Geo endpoints probe and
		// degrade to an onboarding hint until it loads. Mirrors init.sql.
		`CREATE DICTIONARY IF NOT EXISTS netops.geoip_country
 (network String, country String)
 PRIMARY KEY network
 SOURCE(FILE(path '/var/lib/clickhouse/user_files/geoip/country.csv' format 'CSVWithNames'))
 LAYOUT(IP_TRIE())
 LIFETIME(MIN 3600 MAX 7200)`,
		RowPolicyDDL("flows"),
		RowPolicyDDL("findings"),
		RowPolicyDDL("tunnels"),
	}
	// Correlation Engine v2 (#67) frozen schema — tables + view + row policies
	// (corr_schema.go). Same converge-on-boot contract as everything above.
	stmts = append(stmts, CorrSchemaDDL()...)
	// #101 retention contract: profile-driven hot TTLs for the correlation
	// history tables (corr_retention.go). Metadata-only ALTERs; expiry happens
	// as background part drops. Cold Parquet export runs ahead of the horizon.
	stmts = append(stmts, CorrRetentionDDL(CorrRetentionConfig())...)
	// Service Path Graph (frozen contract v1) — the immutable observation/hop
	// streams + their STRICT tenant row policies (path_schema.go). Same
	// converge-on-boot contract; init.sql carries the identical DDL for fresh
	// installs.
	stmts = append(stmts, PathSchemaDDL()...)
	// Cloud cost store (Wave 5 #18) — table + STRICT tenant row policy
	// (cloud_costs.go). Billing data is per-tenant financial data.
	// #69 P2 service flow rollup (svc_rollup_schema.go, STRICT policy) and the
	// Path Behavior Health V1 hour-of-week baselines (path_health_baselines.go,
	// lenient policy — see that file for why). Same converge-on-boot contract.
	stmts = append(stmts, SvcRollupSchemaDDL()...)
	// Wireless per-client event tier (#128 Phase 1, wireless_schema.go, STRICT
	// policies — client MAC/session data is per-tenant PII). Same converge-on-
	// boot contract; init.sql carries identical DDL for fresh installs.
	stmts = append(stmts, WirelessSchemaDDL()...)
	// F-58 retention contract for the TELEMETRY family. Must come LAST: every
	// MODIFY TTL above targets a table the statements before it create, and a
	// converge list that ALTERs before it CREATEs fails on a fresh volume.
	// Same metadata-only, idempotent contract as CorrRetentionDDL.
	stmts = append(stmts, RetentionDDL(RetentionConfig())...)
	for _, e := range extra {
		stmts = append(stmts, e...)
	}
	return stmts
}
