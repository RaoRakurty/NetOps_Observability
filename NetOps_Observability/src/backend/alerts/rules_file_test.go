// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

import (
	"os"
	"strings"
	"testing"
)

// TestShippedRulesFileParses loads the real src/config/rules.yaml through the
// engine's own parser and asserts every rule the parser accepts has the fields
// the engine needs (name, expr, severity). Guards against label/format mistakes
// like inline flow-maps that the hand-rolled parser silently drops.
func TestShippedRulesFileParses(t *testing.T) {
	const path = "../../config/rules.yaml"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("rules file not found at %s: %v", path, err)
	}
	rules, err := parseRulesYAML(string(b))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(rules) < 50 {
		t.Fatalf("expected >=50 rules, parsed %d", len(rules))
	}
	byName := map[string]Rule{}
	for _, r := range rules {
		byName[r.Name] = r
		if strings.TrimSpace(r.Name) == "" {
			t.Errorf("rule with empty name: %+v", r)
		}
		if strings.TrimSpace(r.Expr) == "" {
			t.Errorf("rule %q has empty expr", r.Name)
		}
		// #101: a folded scalar (`expr: >`) used to parse as the bare fold
		// marker — a rule that errors on every tick while looking loaded.
		switch r.Expr {
		case ">", "|", ">-", "|-":
			t.Errorf("rule %q kept the YAML fold marker as its expr (folded-scalar parse regression)", r.Name)
		}
		if r.Labels["severity"] == "" {
			t.Errorf("rule %q missing severity label (inline flow-map not parsed?)", r.Name)
		}
		switch r.Labels["severity"] {
		case "critical", "warning", "info":
		default:
			t.Errorf("rule %q has unexpected severity %q", r.Name, r.Labels["severity"])
		}
	}
	// The #100/#101 bounded-IO + data-contract alerts must be present and
	// carry a real query (CorrVersionChurnUndamped is the folded-scalar one
	// that was silently broken until the #101 parser fix).
	for name, mustContain := range map[string]string{
		"CHMemoryLimitExceeded":        "ClickHouseErrorMetric_MEMORY_LIMIT_EXCEEDED",
		"CorrVersionChurnUndamped":     "increase(corr_versions",
		"CorrCurrentProjectionFailing": "corr_current_projection_write_failures_total",
		"CorrTenantWriteAmpOverBudget": "corr_tenant_writes_window",
	} {
		r, ok := byName[name]
		if !ok {
			t.Errorf("required alert %q missing from rules.yaml", name)
			continue
		}
		if !strings.Contains(r.Expr, mustContain) {
			t.Errorf("alert %q expr lost its query (got %q)", name, r.Expr)
		}
	}
	t.Logf("parsed %d rules OK", len(rules))
}
