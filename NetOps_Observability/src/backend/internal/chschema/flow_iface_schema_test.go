// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rollup's contract (flow_iface_schema.go): tenant first in both keys, the
// raw column names kept, a re-roll replaces instead of adding, and it converges
// on boot exactly once — after the flow columns it is built from exist.
func TestFlowIfaceRollupContract(t *testing.T) {
	ddl := FlowIfaceSchemaDDL()[0]
	for _, want := range []string{
		"ENGINE = ReplacingMergeTree(version)",
		"PARTITION BY (tenant_id, toYYYYMMDD(recv_minute))",
		"ORDER BY (tenant_id, recv_minute, sampler_address, ifindex, direction, minute,",
		"sampler_address String", // same name as netops.flows: one predicate for both
		"flow_type       LowCardinality(String)",
		"platform_sig    UInt64",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("rollup DDL missing %q", want)
		}
	}
	var create, policy, cols int
	for i, s := range ConvergeStmts() {
		switch {
		case strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS netops.flow_iface_1m"):
			create = i
		case strings.Contains(s, "tenant_iso_flow_iface_1m"):
			policy = i
		case strings.Contains(s, "ADD COLUMN IF NOT EXISTS flow_end"):
			cols = i
		}
		// The flows_hourly lesson: nothing may read netops.flows from a view.
		if strings.Contains(s, "MATERIALIZED VIEW") && strings.Contains(s, "netops.flows") {
			t.Fatalf("a materialized view reads netops.flows (breaks ingestion under the row policy): %s", s)
		}
	}
	if create == 0 || policy <= create || cols == 0 || cols > create {
		t.Fatalf("converge order: columns %d, rollup create %d, policy %d", cols, create, policy)
	}
}

// Fresh installs get the same table, policy and flow columns from both copies
// of init.sql.
func TestFlowIfaceInInitSQL(t *testing.T) {
	for _, rel := range []string{
		filepath.Join("deployment", "docker", "clickhouse", "init.sql"),
		filepath.Join("deployment", "helm", "correlix", "files", "clickhouse", "init.sql"),
	} {
		raw, err := os.ReadFile(repoFile(t, rel))
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		flat := strings.Join(strings.Fields(s), " ")
		for _, d := range FlowIfaceSchemaDDL() {
			if !strings.Contains(flat, strings.Join(strings.Fields(d), " ")) {
				t.Errorf("%s does not carry the converge list's statement: %.60s…", rel, d)
			}
		}
		for _, want := range []string{
			"CREATE TABLE IF NOT EXISTS netops.flow_iface_1m",
			"CREATE ROW POLICY IF NOT EXISTS tenant_iso_flow_iface_1m ON netops.flow_iface_1m",
			"odid            UInt32 DEFAULT 0",
			"flow_start      DateTime64(3)",
			"flow_end        DateTime64(3)",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s missing %q", rel, want)
			}
		}
	}
}
