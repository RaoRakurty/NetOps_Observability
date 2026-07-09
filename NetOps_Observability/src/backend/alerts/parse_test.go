package alerts

import (
	"testing"
	"time"
)

func TestParseRulesYAML(t *testing.T) {
	yaml := `
groups:
  - name: network
    rules:
      - alert: HighCPU
        expr: cpu_usage > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU on {{ $labels.device }}"

      - alert: DeviceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: Device unreachable
`
	rules, err := parseRulesYAML(yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	r := rules[0]
	if r.Name != "HighCPU" {
		t.Errorf("name = %q, want HighCPU", r.Name)
	}
	if r.Expr != "cpu_usage > 90" {
		t.Errorf("expr = %q", r.Expr)
	}
	if r.For != 5*time.Minute {
		t.Errorf("for = %v, want 5m", r.For)
	}
	if r.Labels["severity"] != "warning" {
		t.Errorf("severity label = %q", r.Labels["severity"])
	}
	if r.Annotations["summary"] != "High CPU on {{ $labels.device }}" {
		t.Errorf("summary = %q", r.Annotations["summary"])
	}

	if rules[1].Name != "DeviceDown" || rules[1].Labels["severity"] != "critical" {
		t.Errorf("second rule wrong: %+v", rules[1])
	}
}

func TestParseRulesEmpty(t *testing.T) {
	rules, err := parseRulesYAML("")
	if err != nil || rules != nil {
		t.Fatalf("empty input: rules=%v err=%v", rules, err)
	}
}

// ---- #101: folded/literal YAML scalars in expr -------------------------------
// The first-customer alert-routing audit found `expr: >` parsed as the literal
// query ">" — the rule loaded, then errored on every evaluation tick, silently.
// Every scalar style promtool accepts must yield the same final query string.

func TestParseRulesYAMLScalarStyles(t *testing.T) {
	const want = `increase(corr_versions{outcome="persisted"}[30m]) > 60 and increase(corr_versions{outcome="damped"}[30m]) == 0`
	yaml := `
groups:
  - name: g
    rules:
      - alert: Inline
        expr: increase(corr_versions{outcome="persisted"}[30m]) > 60 and increase(corr_versions{outcome="damped"}[30m]) == 0
        labels: { severity: warning }
        annotations:
          summary: "s"
      - alert: Folded
        expr: >
          increase(corr_versions{outcome="persisted"}[30m]) > 60
          and increase(corr_versions{outcome="damped"}[30m]) == 0
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "s"
      - alert: Literal
        expr: |
          increase(corr_versions{outcome="persisted"}[30m]) > 60
          and increase(corr_versions{outcome="damped"}[30m]) == 0
        labels: { severity: critical }
      - alert: FoldedStrip
        expr: >-
          increase(corr_versions{outcome="persisted"}[30m]) > 60
          and increase(corr_versions{outcome="damped"}[30m]) == 0
        labels: { severity: warning }
      - alert: After
        expr: up == 0
        labels: { severity: critical }
`
	rules, err := parseRulesYAML(yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]Rule{}
	for _, r := range rules {
		byName[r.Name] = r
	}
	for _, name := range []string{"Inline", "Folded", "Literal", "FoldedStrip"} {
		if got := byName[name].Expr; got != want {
			t.Errorf("%s: expr = %q, want %q", name, got, want)
		}
	}
	// The continuation must END at the next key: Folded's `for:` still parses,
	// and the rule AFTER a folded block is intact.
	if byName["Folded"].For.Minutes() != 15 {
		t.Errorf("Folded: for = %v, want 15m (continuation swallowed the key?)", byName["Folded"].For)
	}
	if byName["After"].Expr != "up == 0" {
		t.Errorf("After: expr = %q (folded block leaked past its rule)", byName["After"].Expr)
	}
	if byName["After"].Labels["severity"] != "critical" {
		t.Errorf("After: severity lost")
	}
}
