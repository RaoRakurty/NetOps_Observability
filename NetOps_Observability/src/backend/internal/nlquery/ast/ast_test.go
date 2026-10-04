// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ast

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const good = `{"v":1,"query_type":"metric_series","target":"circuit","metric":"circuit_loss_pct",
 "entities":[{"type":"site","id":"site:dfw-hq"}],"time_range":{"kind":"relative","last":"2h"}}`

func TestDecodeAcceptsAWellFormedQuery(t *testing.T) {
	a, err := Decode([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if a.Type != MetricSeries || a.Refs[0].ID != "site:dfw-hq" || a.Time.Last != "2h" {
		t.Fatalf("decoded %+v", a)
	}
}

// §3a: there is no tenant field, so every spelling of one is an unknown-field
// error — a model cannot scope a query to someone else's tenant.
func TestDecodeRejectsTenantSmuggling(t *testing.T) {
	for _, f := range []string{"tenant", "tenant_id", "as_tenant", "TenantID"} {
		raw := strings.Replace(good, `"v":1,`, `"v":1,"`+f+`":"t-b",`, 1)
		if _, err := Decode([]byte(raw)); err == nil {
			t.Errorf("a %q field must be rejected", f)
		}
	}
	nested := strings.Replace(good, `{"type":"site","id":"site:dfw-hq"}`, `{"type":"site","id":"site:dfw-hq","tenant":"t-b"}`, 1)
	if _, err := Decode([]byte(nested)); err == nil {
		t.Error("a nested tenant field must be rejected")
	}
}

func TestDecodeRejectsMalformedInput(t *testing.T) {
	for name, raw := range map[string]string{
		"trailing data":  good + ` {"v":1}`,
		"not an object":  `[1,2,3]`,
		"unknown field":  strings.Replace(good, `"v":1,`, `"v":1,"sql":"SELECT 1",`, 1),
		"wrong type":     strings.Replace(good, `"v":1`, `"v":"one"`, 1),
		"truncated":      good[:40],
		"raw promql key": strings.Replace(good, `"v":1,`, `"v":1,"promql":"up",`, 1),
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Decode([]byte(strings.Repeat(" ", MaxBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized input: %v", err)
	}
}

func TestHashIsDeterministicAndCloneIsDeep(t *testing.T) {
	a, _ := Decode([]byte(good))
	b, _ := Decode([]byte(strings.ReplaceAll(good, "\n ", "")))
	if a.Hash() == "" || a.Hash() != b.Hash() {
		t.Fatal("the same query must hash the same regardless of whitespace")
	}
	c := a.Clone()
	c.Refs[0].ID = "site:aus"
	if a.Refs[0].ID != "site:dfw-hq" {
		t.Fatal("Clone must not share slices with the original")
	}
	if a.Hash() == c.Hash() {
		t.Fatal("a changed query must hash differently")
	}
}

func TestParseDuration(t *testing.T) {
	ok := map[string]time.Duration{"15m": 15 * time.Minute, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour, "9999m": 9999 * time.Minute}
	for in, want := range ok {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0h", "1y", "10000m", "1.5h", "-1h", "h", "2 h", "1h30m"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
}

func TestQueryTypeClassification(t *testing.T) {
	if !MetricTopK.IsMetric() || ChangeList.IsMetric() || !FlowTop.Known() || QueryType("drop_table").Known() {
		t.Fatal("query type classification is wrong")
	}
}
