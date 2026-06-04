package main

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
	"time"
)

// clickhouse_policies.go — self-healing bootstrap for the #20 Phase 2
// database-enforced tenant row policies. Runs on every API start so existing
// deployments (where init.sql only ran on a fresh data dir) converge to the same
// state as a fresh install, with NO manual SQL. Idempotent (IF NOT EXISTS / IF
// EXISTS); best-effort + retried (ClickHouse may start after the API); never
// fatal — the policies are a backstop under the app-layer tenant matcher.
//
// It also DROPs the unused flows_hourly materialized view: with a row policy on
// netops.flows, that MV would re-evaluate the policy on every INSERT (in the
// inserting connection's context, where `tenant_scope` is unset → the insert
// ERRORS, breaking ingestion). See deployment/docker/clickhouse/init.sql.

func chRowPolicyDDL(table string) string {
	return "CREATE ROW POLICY IF NOT EXISTS tenant_iso_" + table + " ON netops." + table +
		" USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = '' TO ALL"
}

// ensureCHRowPolicies converges the telemetry row policies in the background.
func ensureCHRowPolicies() {
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return // no ClickHouse configured (file/dev backend)
	}
	stmts := []string{
		"DROP VIEW IF EXISTS netops.flows_hourly",
		chRowPolicyDDL("flows"),
		chRowPolicyDDL("findings"),
		chRowPolicyDDL("tunnels"),
	}
	go func() {
		for attempt := 0; attempt < 10; attempt++ {
			if chExecAll(base, stmts) {
				log.Printf("clickhouse: tenant row policies ensured (#20 Phase 2)")
				return
			}
			time.Sleep(6 * time.Second)
		}
		log.Printf("clickhouse: WARNING — could not ensure tenant row policies after retries; telemetry isolation relies on the app layer until ClickHouse is reachable")
	}()
}

func chExecAll(base string, stmts []string) bool {
	for _, s := range stmts {
		if !chExec(base, s) {
			return false
		}
	}
	return true
}

// chExec runs one DDL statement against ClickHouse over HTTP. Passes
// tenant_scope=__all__ so the statement is never itself filtered by a policy.
func chExec(base, sql string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	q := u.Query()
	q.Set("tenant_scope", "__all__")
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader([]byte(sql)))
	if err != nil {
		return false
	}
	req.SetBasicAuth(envOr("CLICKHOUSE_USER", "netops"), envOr("CLICKHOUSE_PASSWORD", ""))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
