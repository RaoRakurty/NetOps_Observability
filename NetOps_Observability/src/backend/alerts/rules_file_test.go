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
	for _, r := range rules {
		if strings.TrimSpace(r.Name) == "" {
			t.Errorf("rule with empty name: %+v", r)
		}
		if strings.TrimSpace(r.Expr) == "" {
			t.Errorf("rule %q has empty expr", r.Name)
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
	t.Logf("parsed %d rules OK", len(rules))
}
