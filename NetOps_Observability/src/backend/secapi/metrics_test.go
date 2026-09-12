// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// metrics_test.go — the counter family's name, label vocabulary and
// zero-emission contract. A metric that only appears once it has fired is
// indistinguishable from a broken exporter, so every series is emitted.

import (
	"strings"
	"testing"
)

func TestMetricsEmitEverySeriesIncludingZeros(t *testing.T) {
	m := NewMetrics()
	m.Inc("list")
	m.Inc("list")
	m.Inc("posture")
	m.Inc("not-an-op") // dropped, never mislabelled into a real series

	var sb strings.Builder
	m.Write(&sb)
	out := sb.String()

	if !strings.Contains(out, "# TYPE netops_security_findings_queries_total counter") {
		t.Fatalf("the counter family is not declared:\n%s", out)
	}
	for _, op := range Ops {
		want := `netops_security_findings_queries_total{op="` + op + `"}`
		if !strings.Contains(out, want) {
			t.Errorf("series %s missing — an absent series and a zero series mean different things to an alert", want)
		}
	}
	if !strings.Contains(out, `{op="list"} 2`) || !strings.Contains(out, `{op="posture"} 1`) {
		t.Errorf("counts wrong:\n%s", out)
	}
	if !strings.Contains(out, `{op="get"} 0`) {
		t.Errorf("an untouched op must emit a zero series:\n%s", out)
	}
	if strings.Contains(out, "not-an-op") {
		t.Error("an unknown op must be dropped, never emitted as a label")
	}
	snap := m.Snapshot()
	if snap["list"] != 2 || len(snap) != len(Ops) {
		t.Errorf("snapshot = %v", snap)
	}
	// §3a applied to telemetry: the family carries NO tenant label, so /metrics
	// cannot leak tenant existence or cardinality to whoever can scrape it.
	if strings.Contains(out, "tenant") {
		t.Fatalf("the metric family must not carry a tenant label:\n%s", out)
	}
}

func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.Inc("list") // must not panic: a server built without metrics still serves
	if len(m.Snapshot()) != 0 {
		t.Error("a nil Metrics must snapshot empty")
	}
	var sb strings.Builder
	m.Write(&sb)
	if sb.Len() != 0 {
		t.Error("a nil Metrics must write nothing")
	}
}
