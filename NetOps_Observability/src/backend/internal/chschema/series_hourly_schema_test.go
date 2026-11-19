// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The roll-up's contract (series_hourly_schema.go): tenant first in both keys,
// no untagged default, a re-roll replaces, a STRICT policy with no untagged
// escape, nine weeks of retention, converged on boot after its table.
func TestSeriesHourlyContract(t *testing.T) {
	ddl := SeriesHourlySchemaDDL()
	for _, want := range []string{
		"ENGINE = ReplacingMergeTree(version)",
		"PARTITION BY (tenant_id, toYYYYMM(hour))",
		"ORDER BY (tenant_id, metric, entity_key, hour)",
		"TTL hour + INTERVAL 63 DAY",
	} {
		if !strings.Contains(ddl[0], want) {
			t.Errorf("series_hourly DDL missing %q", want)
		}
	}
	// No DEFAULT '' on tenant_id: an untagged row must not be writable by
	// omission (the worker never writes one).
	if strings.Contains(ddl[0], "tenant_id   LowCardinality(String) DEFAULT") {
		t.Error("series_hourly tenant_id must have no default")
	}
	pol := ddl[1]
	if !strings.Contains(pol, "CREATE ROW POLICY OR REPLACE tenant_iso_series_hourly") ||
		strings.Contains(pol, "tenant_id = ''") || !strings.Contains(pol, "getSetting('tenant_scope') = '__all__'") {
		t.Fatalf("series_hourly must carry the STRICT policy: %s", pol)
	}
	var create, policy int
	for i, s := range ConvergeStmts() {
		switch {
		case strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS netops.series_hourly"):
			create = i
		case strings.Contains(s, "tenant_iso_series_hourly"):
			policy = i
		}
	}
	if create == 0 || policy <= create {
		t.Fatalf("converge order: create %d, policy %d", create, policy)
	}
	if RetentionConfig().SeriesHourly != 63 {
		t.Fatalf("series_hourly retention = %d, want 63", RetentionConfig().SeriesHourly)
	}
}

// Fresh installs get the same table and STRICT policy from both init.sql
// copies.
func TestSeriesHourlyInInitSQL(t *testing.T) {
	for _, rel := range []string{
		filepath.Join("deployment", "docker", "clickhouse", "init.sql"),
		filepath.Join("deployment", "helm", "correlix", "files", "clickhouse", "init.sql"),
	} {
		raw, err := os.ReadFile(repoFile(t, rel))
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		for _, want := range []string{
			"CREATE TABLE IF NOT EXISTS netops.series_hourly",
			"ORDER BY (tenant_id, metric, entity_key, hour)",
			"TTL hour + INTERVAL 63 DAY",
			"CREATE ROW POLICY OR REPLACE tenant_iso_series_hourly ON netops.series_hourly",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s missing %q", rel, want)
			}
		}
		i := strings.Index(s, "tenant_iso_series_hourly")
		if i < 0 || strings.Contains(s[i:i+260], "tenant_id = ''") {
			t.Errorf("%s: series_hourly policy must be STRICT", rel)
		}
	}
}
