// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The iface_names table and its policy converge on boot, once each, and the
// policy is the LENIENT one flows carries (a platform device's names must name
// the platform flow rows every tenant already sees).
func TestIfaceNamesConvergesWithLenientPolicy(t *testing.T) {
	var creates, policies int
	for _, s := range ConvergeStmts() {
		if strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS netops.iface_names") {
			creates++
			for _, want := range []string{
				"ORDER BY (tenant_id, exporter_addr, ifindex)",
				"ENGINE = ReplacingMergeTree(updated)",
				"TTL updated + INTERVAL 8 DAY",
				"tenant_id     LowCardinality(String)",
			} {
				if !strings.Contains(s, want) {
					t.Errorf("iface_names CREATE lacks %q:\n%s", want, s)
				}
			}
		}
		if strings.Contains(s, "tenant_iso_iface_names") {
			policies++
			if s != RowPolicyDDL("iface_names") {
				t.Errorf("iface_names policy is not the lenient flows policy:\n%s", s)
			}
		}
	}
	if creates != 1 || policies != 1 {
		t.Fatalf("converge list carries iface_names CREATE %d times and policy %d times, want 1 and 1", creates, policies)
	}
}

// No table may gain the untagged-shared clause without being named here. The
// correlation, path, rollup, wireless and DEM tables are STRICT by design; a
// lenient clause on any of them leaks untagged rows into every tenant.
func TestOnlyTheSharedTelemetryTablesAreLenient(t *testing.T) {
	re := regexp.MustCompile(`ROW POLICY (?:IF NOT EXISTS |OR REPLACE )?tenant_iso_(\w+)`)
	var lenient []string
	for _, s := range ConvergeStmts() {
		m := re.FindStringSubmatch(s)
		if m != nil && strings.Contains(s, "OR tenant_id = ''") {
			lenient = append(lenient, m[1])
		}
	}
	sort.Strings(lenient)
	want := []string{"findings", "flows", "iface_names", "tunnels"}
	if strings.Join(lenient, ",") != strings.Join(want, ",") {
		t.Fatalf("lenient row policies = %v, want exactly %v", lenient, want)
	}
}

// Fresh installs get the same table and policy from init.sql (both copies).
func TestIfaceNamesInInitSQL(t *testing.T) {
	for _, rel := range []string{
		filepath.Join("deployment", "docker", "clickhouse", "init.sql"),
		filepath.Join("deployment", "helm", "correlix", "files", "clickhouse", "init.sql"),
	} {
		b, err := os.ReadFile(repoFile(t, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		src := strings.Join(strings.Fields(string(b)), " ")
		ddl := strings.Join(strings.Fields(IfaceNamesSchemaDDL()[0]), " ")
		if !strings.Contains(src, ddl) {
			t.Errorf("%s does not carry the iface_names CREATE the converge list emits", rel)
		}
		pol := strings.Join(strings.Fields(RowPolicyDDL("iface_names")), " ")
		if !strings.Contains(src, pol) {
			t.Errorf("%s does not carry the lenient iface_names row policy", rel)
		}
	}
}
