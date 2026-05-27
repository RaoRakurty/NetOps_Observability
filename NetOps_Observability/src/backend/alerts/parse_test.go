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
