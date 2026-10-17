// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisgate

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The bars are the owner's (Part 2 §48/§67). Changing one is a deliberate,
// reviewed edit to this table — never a side effect.
func TestBarsArePinned(t *testing.T) {
	want := map[string]struct {
		k   Kind
		min float64
	}{
		GateEntity: {KindRate, 0.99}, GateExecutable: {KindRate, 0.98}, GateSemantic: {KindRate, 0.95},
		GateCrossTenant: {KindZero, 0}, GateUnauthorized: {KindZero, 0},
		GateCitation: {KindRate, 1.0}, GateInjection: {KindRate, 1.0}, GateAudit: {KindRate, 1.0},
	}
	if len(Bars()) != len(want) {
		t.Fatalf("%d bars, want %d", len(Bars()), len(want))
	}
	for _, b := range Bars() {
		w, ok := want[b.Gate]
		if !ok || w.k != b.Kind || w.min != b.Min {
			t.Errorf("bar %s = %s %.2f, want %s %.2f", b.Gate, b.Kind, b.Min, w.k, w.min)
		}
	}
}

func TestEvaluate(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(RecordTo(dir, "nlquery.compile",
		Measure{Gate: GateEntity, OK: 99, Total: 100}, // exactly the bar: pass
		Measure{Gate: GateExecutable, OK: 97, Total: 100},
		Measure{Gate: GateCrossTenant, Total: 500},
	))
	must(RecordTo(dir, "ai.incidents",
		Measure{Gate: GateInjection, OK: 2, Total: 3}, // an XFAIL counted as a failure
		Measure{Gate: GateCrossTenant, Total: 5, Bad: 1},
	))
	rs, err := Evaluate(dir)
	must(err)
	by := map[string]Result{}
	for _, r := range rs {
		by[r.Bar.Gate] = r
	}
	if !by[GateEntity].Pass {
		t.Error("a value exactly at the bar passes")
	}
	if by[GateExecutable].Pass {
		t.Error("0.97 < 0.98 must fail")
	}
	if by[GateCrossTenant].Pass || by[GateCrossTenant].Bad != 1 || by[GateCrossTenant].Total != 505 {
		t.Errorf("counts sum across sources and one leak fails: %+v", by[GateCrossTenant])
	}
	if by[GateInjection].Pass {
		t.Error("an expected failure is a failure")
	}
	for _, g := range []string{GateSemantic, GateUnauthorized, GateCitation, GateAudit} {
		if !by[g].Missing || by[g].Pass {
			t.Errorf("%s was never measured: it must be MISSING and fail, got %+v", g, by[g])
		}
	}
	if !errors.Is(Check(rs), ErrGatesFailed) {
		t.Fatal("Check must fail")
	}
	md := Markdown(rs, "report")
	for _, want := range []string{"| entity | ≥ 99 % | 99.0 % (99/100) | ✅ pass", "| cross_tenant | = 0 | 1 of 505 checks | ❌ fail", "| audit | ≥ 100 % | not measured | ❌ missing"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestRecordRefusesNonsense(t *testing.T) {
	dir := t.TempDir()
	for _, m := range []Measure{
		{Gate: "vibes", OK: 1, Total: 1},
		{Gate: GateEntity, OK: 2, Total: 1},
		{Gate: GateEntity, OK: -1, Total: 1},
	} {
		if RecordTo(dir, "x", m) == nil {
			t.Errorf("%+v must be refused", m)
		}
	}
	if RecordTo(dir, "../escape", Measure{Gate: GateEntity, OK: 1, Total: 1}) == nil {
		t.Error("a path in the source name must be refused")
	}
	t.Setenv(EnvReportDir, "")
	if err := Record("x", Measure{Gate: GateEntity, OK: 1, Total: 1}); err != nil {
		t.Fatal("without the env var Record is a no-op")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("a refused record must write nothing")
	}
}
