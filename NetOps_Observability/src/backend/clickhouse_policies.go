package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// clickhouse_policies.go — self-healing bootstrap for the #20 Phase 2
// database-enforced tenant row policies AND additive schema columns. Runs on
// every API start so existing deployments (where init.sql only ran on a fresh
// data dir) converge to the same state as a fresh install, with NO manual SQL.
// Idempotent (IF NOT EXISTS / IF EXISTS); best-effort + retried (ClickHouse may
// start after the API); never fatal — the policies are a backstop under the
// app-layer tenant matcher, and a missing column only blanks its panel.
//
// It also DROPs the unused flows_hourly materialized view: with a row policy on
// netops.flows, that MV would re-evaluate the policy on every INSERT (in the
// inserting connection's context, where `tenant_scope` is unset → the insert
// ERRORS, breaking ingestion). See deployment/docker/clickhouse/init.sql.

// chRowPolicyDDL is the LENIENT telemetry policy: untagged (tenant_id = ”)
// rows are shared into every tenant's view. Correct ONLY for the shared
// telemetry tables (flows, findings, tunnels) whose data model depends on
// untagged rows. NEVER use it for the correlation family — see
// chStrictRowPolicyDDL.
func chRowPolicyDDL(table string) string {
	return "CREATE ROW POLICY IF NOT EXISTS tenant_iso_" + table + " ON netops." + table +
		" USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = '' TO ALL"
}

// chStrictRowPolicyDDL is the STRICT tenant policy (the 2026-07-02 init.sql
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
func chStrictRowPolicyDDL(table string) string {
	return "CREATE ROW POLICY OR REPLACE tenant_iso_" + table + " ON netops." + table +
		" USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' TO ALL"
}

// chConvergeStmts is the complete, ordered boot-convergence DDL list. No
// network IO (env-only inputs) so tests can assert over the exact statements
// the boot path emits — e.g. that no correlation-family row policy carries
// the lenient untagged-shared escape.
func chConvergeStmts() []string {
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
		chRowPolicyDDL("flows"),
		chRowPolicyDDL("findings"),
		chRowPolicyDDL("tunnels"),
	}
	// Correlation Engine v2 (#67) frozen schema — tables + view + row policies
	// (corr_schema.go). Same converge-on-boot contract as everything above.
	stmts = append(stmts, corrSchemaDDL()...)
	// #101 retention contract: profile-driven hot TTLs for the correlation
	// history tables (corr_retention.go). Metadata-only ALTERs; expiry happens
	// as background part drops. Cold Parquet export runs ahead of the horizon.
	stmts = append(stmts, corrRetentionDDL(corrRetentionConfig())...)
	// Service Path Graph (frozen contract v1) — the immutable observation/hop
	// streams + their STRICT tenant row policies (path_schema.go). Same
	// converge-on-boot contract; init.sql carries the identical DDL for fresh
	// installs.
	stmts = append(stmts, pathSchemaDDL()...)
	// Cloud cost store (Wave 5 #18) — table + STRICT tenant row policy
	// (cloud_costs.go). Billing data is per-tenant financial data.
	stmts = append(stmts, cloudCostsSchemaDDL()...)
	// #69 P2 service flow rollup (svc_rollup_schema.go, STRICT policy) and the
	// Path Behavior Health V1 hour-of-week baselines (path_health_baselines.go,
	// lenient policy — see that file for why). Same converge-on-boot contract.
	stmts = append(stmts, svcRollupSchemaDDL()...)
	stmts = append(stmts, pathBaselineSchemaDDL()...)
	return stmts
}

// ensureCHRowPolicies converges the telemetry row policies in the background.
func ensureCHRowPolicies() {
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return // no ClickHouse configured (file/dev backend)
	}
	stmts := chConvergeStmts()
	go func() {
		var errs []string
		for attempt := 0; attempt < 10; attempt++ {
			errs = chExecAll(base, stmts)
			if len(errs) == 0 {
				log.Printf("clickhouse: tenant row policies ensured (#20 Phase 2)")
				return
			}
			time.Sleep(6 * time.Second)
		}
		// Name every failing statement (2026-07-09 outage: this warning used to
		// be generic while a stale enum ALTER silently blocked the rest of the
		// converge list on every boot — undiagnosable from the log alone).
		log.Printf("clickhouse: WARNING — could not ensure tenant row policies after retries; telemetry isolation relies on the app layer until ClickHouse is reachable")
		for _, e := range errs {
			log.Printf("clickhouse: converge failure: %s", e)
		}
	}()
}

// chExecAll runs every statement and returns a description of each failure.
// It deliberately does NOT stop at the first error: every statement is
// independently idempotent, and aborting early lets one permanently-failing
// statement block every statement after it (2026-07-09: a stale enum ALTER
// kept corr_current from ever being created). Dependent statements (e.g. the
// corr_current backfill after its CREATE) just fail the same attempt and
// converge on a later one.
func chExecAll(base string, stmts []string) []string {
	var errs []string
	for _, s := range stmts {
		if msg := chExecErr(base, s); msg != "" {
			errs = append(errs, msg)
		}
	}
	return errs
}

// chExec runs one DDL statement against ClickHouse over HTTP. Passes
// tenant_scope=__all__ so the statement is never itself filtered by a policy.
func chExec(base, sql string) bool {
	return chExecErr(base, sql) == ""
}

// chExecErr is chExec returning a diagnosable failure description ("" = ok):
// the head of the statement plus ClickHouse's own error line, so a converge
// failure names its cause in the log instead of a bare false.
func chExecErr(base, sql string) string {
	head := sql
	if len(head) > 80 {
		head = head[:80] + "…"
	}
	head = strings.Join(strings.Fields(head), " ")
	u, err := url.Parse(base)
	if err != nil {
		return "bad CLICKHOUSE_URL: " + err.Error()
	}
	q := u.Query()
	q.Set("tenant_scope", "__all__")
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader([]byte(sql)))
	if err != nil {
		return head + ": " + err.Error()
	}
	req.SetBasicAuth(envOr("CLICKHOUSE_USER", "netops"), envOr("CLICKHOUSE_PASSWORD", ""))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := backendHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return head + ": " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Body read best-effort: the status line alone still identifies the
		// failing statement; ClickHouse puts the DB::Exception in the body.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return head + ": HTTP " + resp.Status + ": " + strings.Join(strings.Fields(string(body)), " ")
	}
	return ""
}
