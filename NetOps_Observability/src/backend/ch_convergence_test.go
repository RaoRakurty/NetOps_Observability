package main

// ch_convergence_test.go — BOOT-CONVERGENCE guards.
//
// These assert the relationship between the schema statements and the boot path
// that emits them (chConvergeStmts), so they belong with the INTEGRATOR, not
// with the schema package. The pure-DDL assertions moved to
// internal/chschema alongside the statements they describe; splitting them this
// way is why the extraction did not lose any coverage.

import (
	"netops/backend/internal/chschema"
	"os"
	"regexp"
	"strings"
	"testing"

	"netops/backend/cloud"
)

func TestRetentionRunsAfterSchemaCreation(t *testing.T) {
	stmts := chschema.ConvergeStmts(cloud.CostsSchemaDDL(), pathBaselineSchemaDDL())
	createAt := map[string]int{}
	reCreate := regexp.MustCompile(`CREATE TABLE IF NOT EXISTS netops\.(\w+)`)
	reAlterTTL := regexp.MustCompile(`ALTER TABLE netops\.(\w+) MODIFY TTL`)

	for i, s := range stmts {
		if m := reCreate.FindStringSubmatch(s); m != nil {
			if _, seen := createAt[m[1]]; !seen {
				createAt[m[1]] = i
			}
		}
	}
	seenTTL := false
	for i, s := range stmts {
		m := reAlterTTL.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		seenTTL = true
		if at, ok := createAt[m[1]]; ok && at > i {
			t.Errorf("netops.%s: MODIFY TTL at index %d runs BEFORE its CREATE at index %d — "+
				"the ALTER fails on every fresh volume, silently (chExecAll continues past errors)",
				m[1], i, at)
		}
	}
	if !seenTTL {
		t.Fatal("no MODIFY TTL statement in the boot converge list — F-58 has regressed")
	}
}

func TestSvcRollupConvergeAndInitSQLInLockstep(t *testing.T) {
	converge := strings.Join(chschema.ConvergeStmts(cloud.CostsSchemaDDL(), pathBaselineSchemaDDL()), "\n")
	for _, want := range []string{"netops.svc_flow_rollup_1m", "netops.path_baselines"} {
		if !strings.Contains(converge, want) {
			t.Errorf("boot converge list missing %s", want)
		}
	}
	initSQL, err := os.ReadFile("../../deployment/docker/clickhouse/init.sql")
	if err != nil {
		t.Fatalf("read init.sql: %v", err)
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS netops.svc_flow_rollup_1m",
		"CREATE TABLE IF NOT EXISTS netops.path_baselines",
		"tenant_iso_svc_flow_rollup_1m",
		"tenant_iso_path_baselines",
		"allow_nullable_key = 1",
	} {
		if !strings.Contains(string(initSQL), want) {
			t.Errorf("init.sql missing %q (fresh-install drift)", want)
		}
	}
}

// pathBaselineSchemaDDL still lives in package main (path_health_baselines.go
// is a worker file, not pure DDL), so its pin stays with it.

func TestPathBaselineSchemaPins(t *testing.T) {
	ddl := strings.Join(pathBaselineSchemaDDL(), "\n")
	if !strings.Contains(ddl, "CREATE TABLE IF NOT EXISTS netops.path_baselines") {
		t.Fatal("baseline CREATE must be IF NOT EXISTS")
	}
	if !strings.Contains(ddl, "ReplacingMergeTree(computed_at)") {
		t.Error("baselines must be a ReplacingMergeTree keyed on computed_at (idempotent re-writes)")
	}
	if !strings.Contains(ddl, "ORDER BY (tenant_id, path_id, route_fingerprint, hour_of_week)") {
		t.Error("baseline dedup key must be (tenant, path, fingerprint, hour_of_week)")
	}
	// route_fingerprint exists from day one so tier 1 lands without migration.
	if !strings.Contains(ddl, "route_fingerprint String DEFAULT ''") {
		t.Error("route_fingerprint column must exist (tier-1 forward slot)")
	}
	// STRICT policy (the path_* family rule, TestCorrRowPoliciesStrict): the
	// lenient untagged-shared escape is forbidden on every netops.path_* table.
	if !strings.Contains(ddl, "CREATE ROW POLICY OR REPLACE tenant_iso_path_baselines") {
		t.Error("path_baselines needs the STRICT row policy")
	}
	if strings.Contains(ddl, "OR tenant_id = ''") {
		t.Error("path_baselines policy must NOT carry the lenient untagged-shared clause")
	}
}
