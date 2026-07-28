package main

import (
	"log"
	"netops/backend/internal/chschema"
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

// ensureCHRowPolicies converges the telemetry row policies in the background.
func ensureCHRowPolicies() {
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return // no ClickHouse configured (file/dev backend)
	}
	stmts := chschema.ConvergeStmts(cloudCostsSchemaDDL(), pathBaselineSchemaDDL())
	// F-58: state the retention schedule before applying it. `MODIFY TTL` is a
	// deletion schedule, and a deletion schedule applied without a log line is
	// exactly the kind of silent data loss this audit found everywhere else.
	chschema.LogRetention(chschema.RetentionConfig())
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
