// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package osprobe

// osprobe_test.go — the LADDER ITSELF: the order, the overwrite rule, and the
// derivation that keeps the two from drifting apart.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeSource is a rung whose answer the test dictates.
type fakeSource struct {
	method Method
	value  string
	err    error
	calls  int
}

func (f *fakeSource) Method() Method { return f.method }
func (f *fakeSource) Probe(_ context.Context, _ Target) (string, error) {
	f.calls++
	return f.value, f.err
}

func mustLadder(t *testing.T, sources ...Source) *Ladder {
	t.Helper()
	l, err := NewLadder(func(string, map[string]any) {}, sources...)
	if err != nil {
		t.Fatalf("NewLadder: %v", err)
	}
	return l
}

// TestLadderOrderIsSNMPThenGNMIThenSSH pins the design decision. The order is
// not an implementation detail: it decides which source's answer a device row
// ends up carrying.
func TestLadderOrderIsSNMPThenGNMIThenSSH(t *testing.T) {
	want := []Method{MethodSNMP, MethodGNMI, MethodSSH}
	if len(LadderOrder) != len(want) {
		t.Fatalf("LadderOrder = %v, want %v", LadderOrder, want)
	}
	for i := range want {
		if LadderOrder[i] != want[i] {
			t.Fatalf("LadderOrder = %v, want %v", LadderOrder, want)
		}
	}
}

// TestLadderTakesTheFirstAnswerAndStopsThere — the whole point of a ladder.
func TestLadderTakesTheFirstAnswerAndStopsThere(t *testing.T) {
	snmp := &fakeSource{method: MethodSNMP, value: "SRLinux-v26.3.2"}
	gnmi := &fakeSource{method: MethodGNMI, value: "SRLinux-v25.0.0"}
	ssh := &fakeSource{method: MethodSSH, value: "SRLinux-v24.0.0"}
	l := mustLadder(t, ssh, gnmi, snmp) // deliberately out of order

	got, ok := l.Probe(context.Background(), Target{DeviceID: "spine1"}, Current{})
	if !ok {
		t.Fatal("ladder learned nothing from a rung that answered")
	}
	if got.Version != "SRLinux-v26.3.2" || got.Method != MethodSNMP {
		t.Fatalf("got %q via %q, want the SNMP rung's answer", got.Version, got.Method)
	}
	if gnmi.calls != 0 || ssh.calls != 0 {
		t.Errorf("lower rungs ran after a higher one answered: gnmi=%d ssh=%d", gnmi.calls, ssh.calls)
	}
}

// TestLadderFallsThroughEveryFailureMode — the lab's exact shape: SNMP is dead,
// gNMI is not wired, SSH answers.
func TestLadderFallsThroughEveryFailureMode(t *testing.T) {
	snmp := &fakeSource{method: MethodSNMP, value: ""} // answered, no version
	gnmi := &fakeSource{method: MethodGNMI, err: ErrNotConfigured}
	ssh := &fakeSource{method: MethodSSH, value: "SRLinux-v26.3.2"}
	l := mustLadder(t, snmp, gnmi, ssh)

	got, ok := l.Probe(context.Background(), Target{DeviceID: "spine1"}, Current{})
	if !ok || got.Method != MethodSSH || got.Version != "SRLinux-v26.3.2" {
		t.Fatalf("got (%q via %q, ok=%v), want the SSH rung's answer", got.Version, got.Method, ok)
	}
	if snmp.calls != 1 || gnmi.calls != 1 || ssh.calls != 1 {
		t.Errorf("each rung must be tried exactly once: %d/%d/%d", snmp.calls, gnmi.calls, ssh.calls)
	}

	var b strings.Builder
	l.WriteMetrics(&b)
	for _, want := range []string{
		`netops_device_osversion_probe_total{method="gnmi",outcome="unavailable"} 1`,
		`netops_device_osversion_probe_total{method="snmp",outcome="no_version"} 1`,
		`netops_device_osversion_probe_total{method="ssh",outcome="learned"} 1`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, b.String())
		}
	}
}

// TestLadderReportsNothingWhenNoRungAnswers — the honest non-answer. A device
// nobody can read a version off must leave the row untouched, NOT acquire an
// invented one.
func TestLadderReportsNothingWhenNoRungAnswers(t *testing.T) {
	l := mustLadder(t,
		&fakeSource{method: MethodSNMP, err: errors.New("timeout")},
		&fakeSource{method: MethodSSH, value: "   "},
	)
	if got, ok := l.Probe(context.Background(), Target{DeviceID: "d1"}, Current{}); ok {
		t.Fatalf("ladder invented %q from rungs that answered nothing", got.Version)
	}
	var b strings.Builder
	l.WriteMetrics(&b)
	if !strings.Contains(b.String(), `{method="snmp",outcome="error"} 1`) {
		t.Errorf("a failed probe must be counted as an error, not as a benign empty:\n%s", b.String())
	}
}

// TestLadderLogsEveryFailure — §10, no silent failures.
func TestLadderLogsEveryFailure(t *testing.T) {
	var logged []string
	l, err := NewLadder(func(msg string, fields map[string]any) {
		logged = append(logged, fmt.Sprintf("%s method=%v", msg, fields["method"]))
	},
		&fakeSource{method: MethodSNMP, err: errors.New("dial tcp: i/o timeout")},
		&fakeSource{method: MethodSSH, value: ""},
	)
	if err != nil {
		t.Fatal(err)
	}
	l.Probe(context.Background(), Target{DeviceID: "d1"}, Current{})
	if len(logged) != 2 {
		t.Fatalf("logged %v, want a line for the failure AND for the empty answer", logged)
	}
	if !strings.Contains(logged[0], "method=snmp") || !strings.Contains(logged[1], "method=ssh") {
		t.Errorf("log lines do not name their rung: %v", logged)
	}
}

// TestLadderRefusesADuplicateOrNonRungSource — construction is fail-closed.
func TestLadderRefusesADuplicateOrNonRungSource(t *testing.T) {
	if _, err := NewLadder(nil, &fakeSource{method: MethodSNMP}, &fakeSource{method: MethodSNMP}); err == nil {
		t.Error("two sources with the same method must be refused")
	}
	if _, err := NewLadder(nil, &fakeSource{method: MethodManual}); err == nil {
		t.Error("a non-rung method must be refused — manual is a provenance, not a transport")
	}
}

// TestLadderBoundsAReading — §9.
func TestLadderBoundsAReading(t *testing.T) {
	l := mustLadder(t, &fakeSource{method: MethodSNMP, value: strings.Repeat("x", MaxOSVersionBytes*3)})
	got, ok := l.Probe(context.Background(), Target{DeviceID: "d1"}, Current{})
	if !ok {
		t.Fatal("expected a reading")
	}
	if len(got.Version) != MaxOSVersionBytes {
		t.Errorf("reading length %d, want it capped at %d", len(got.Version), MaxOSVersionBytes)
	}
}

// TestLadderHonoursTheProbeTimeout — §9, all IO must have a timeout.
func TestLadderHonoursTheProbeTimeout(t *testing.T) {
	slow := blockingSource{method: MethodSNMP}
	l := mustLadder(t, slow)
	l.SetTimeout(20 * time.Millisecond)
	start := time.Now()
	if _, ok := l.Probe(context.Background(), Target{DeviceID: "d1"}, Current{}); ok {
		t.Fatal("a rung that never answers must not produce a reading")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("probe ran for %v — the per-rung timeout is not being applied", elapsed)
	}
}

type blockingSource struct{ method Method }

func (b blockingSource) Method() Method { return b.method }
func (b blockingSource) Probe(ctx context.Context, _ Target) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// ─── the overwrite rule ──────────────────────────────────────────────────────

func TestAcceptOverwriteRule(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		cur  Current
		in   Reading
		want bool
		why  string
	}{
		{
			name: "an empty reading never lands on an empty row",
			cur:  Current{}, in: Reading{Version: "", Method: MethodSNMP, At: at}, want: false,
			why: "rule 1 — there is nothing to write",
		},
		{
			name: "an empty reading never erases a probed value",
			cur:  Current{Version: "SRLinux-v26.3.2", Source: MethodSNMP}, in: Reading{Version: "  ", Method: MethodSNMP, At: at}, want: false,
			why: "rule 1 — a transient timeout must not blank a version",
		},
		{
			name: "an empty reading never erases an operator's value",
			cur:  Current{Version: "SRLinux-v26.3.2", Source: MethodManual}, in: Reading{Version: "", Method: MethodSSH, At: at}, want: false,
			why: "rule 1",
		},
		{
			name: "any rung fills an empty row",
			cur:  Current{}, in: Reading{Version: "JUNOS 21.4R3-S5.4", Method: MethodSSH, At: at}, want: true,
			why: "rule 3, the empty case — this is the lab spines' case",
		},
		{
			name: "an empty row with a stale source label is still empty",
			cur:  Current{Source: MethodSSH}, in: Reading{Version: "Version 17.09.04a", Method: MethodSNMP, At: at}, want: true,
			why: "rule 3 — emptiness is about the VALUE, not the label beside it",
		},
		{
			name: "the same rung refreshes its own reading",
			cur:  Current{Version: "SRLinux-v26.3.2", Source: MethodSSH}, in: Reading{Version: "SRLinux-v26.4.0", Method: MethodSSH, At: at}, want: true,
			why: "rule 2 — this is how an upgrade shows up",
		},
		{
			name: "a different rung does not displace an existing automatic value",
			cur:  Current{Version: "SRLinux-v26.3.2", Source: MethodSSH}, in: Reading{Version: "SRLinux-v26.4.0", Method: MethodSNMP, At: at}, want: false,
			why: "rule 3 — one flapping transport must not repeatedly rewrite the row",
		},
		{
			name: "a probe never displaces an operator's value",
			cur:  Current{Version: "SRLinux-v26.3.2", Source: MethodManual}, in: Reading{Version: "SRLinux-v26.4.0", Method: MethodSNMP, At: at}, want: false,
			why: "rule 3 — manual provenance is not a rung",
		},
		{
			name: "a probe never displaces a value of unknown provenance",
			cur:  Current{Version: "SRLinux-v26.3.2"}, in: Reading{Version: "SRLinux-v26.4.0", Method: MethodSNMP, At: at}, want: false,
			why: "rule 3 — a row written before the source field existed is treated as manual",
		},
		{
			name: "a manual reading cannot be written through the probe path",
			cur:  Current{}, in: Reading{Version: "SRLinux-v26.3.2", Method: MethodManual, At: at}, want: false,
			why: "only a rung writes through Accept; an operator writes through the API",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Accept(tc.cur, tc.in); got != tc.want {
				t.Errorf("Accept(%+v, %+v) = %v, want %v (%s)", tc.cur, tc.in, got, tc.want, tc.why)
			}
		})
	}
}

// TestPlanIsDerivedFromAccept is the anti-drift proof: for every reachable
// (current, method) pair, Plan lists a method IF AND ONLY IF Accept would take a
// non-empty reading from it. This is what lets the ladder skip transports it
// would only have to throw the answer away from — without the skip silently
// diverging from the rule it claims to implement.
func TestPlanIsDerivedFromAccept(t *testing.T) {
	currents := []Current{
		{},
		{Source: MethodSNMP},
		{Version: "x", Source: MethodSNMP},
		{Version: "x", Source: MethodGNMI},
		{Version: "x", Source: MethodSSH},
		{Version: "x", Source: MethodManual},
		{Version: "x"},
	}
	for _, cur := range currents {
		planned := map[Method]bool{}
		for _, m := range Plan(cur) {
			planned[m] = true
		}
		for _, m := range LadderOrder {
			accepted := Accept(cur, Reading{Version: "a-real-version", Method: m})
			if planned[m] != accepted {
				t.Errorf("current %+v: Plan lists %q = %v but Accept says %v — the plan and the rule have drifted",
					cur, m, planned[m], accepted)
			}
		}
	}
}

// TestLadderPlansNoProbeForAnOperatorsRow — the ladder must not touch a device
// whose answer it could never use. This is a device-safety property, not an
// optimization: it is why an operator-pinned row is never dialled at all.
func TestLadderPlansNoProbeForAnOperatorsRow(t *testing.T) {
	snmp := &fakeSource{method: MethodSNMP, value: "Version 17.09.04a"}
	l := mustLadder(t, snmp)
	cur := Current{Version: "Version 17.03.01", Source: MethodManual}
	if _, ok := l.Probe(context.Background(), Target{DeviceID: "d1"}, cur); ok {
		t.Fatal("a probe result was accepted onto an operator's row")
	}
	if snmp.calls != 0 {
		t.Errorf("the device was dialled %d times for an answer that could never be used", snmp.calls)
	}
}

// TestLadderRefreshesOnlyTheRungThatOwnsTheRow — the cross-rung case, at the
// ladder level: a row already carrying an SSH-learned version must not cause an
// SNMP dial, because rule 3 would refuse the answer.
func TestLadderRefreshesOnlyTheRungThatOwnsTheRow(t *testing.T) {
	snmp := &fakeSource{method: MethodSNMP, value: "Version 17.09.04a"}
	ssh := &fakeSource{method: MethodSSH, value: "Version 17.10.01"}
	l := mustLadder(t, snmp, ssh)

	got, ok := l.Probe(context.Background(), Target{DeviceID: "d1"},
		Current{Version: "Version 17.09.04a", Source: MethodSSH})
	if !ok || got.Method != MethodSSH || got.Version != "Version 17.10.01" {
		t.Fatalf("got (%q via %q, ok=%v), want the SSH rung's refreshed answer", got.Version, got.Method, ok)
	}
	if snmp.calls != 0 {
		t.Errorf("the SNMP rung ran for a row it could not have written (%d calls)", snmp.calls)
	}
}

// TestWriteMetricsIsSilentUntilSomethingHappened — an exposition of nothing is
// worse than no exposition: it would publish a zero series that reads as
// "probes ran and never learned anything".
func TestWriteMetricsIsSilentUntilSomethingHappened(t *testing.T) {
	var b strings.Builder
	mustLadder(t).WriteMetrics(&b)
	if b.Len() != 0 {
		t.Errorf("a ladder that has probed nothing emitted:\n%s", b.String())
	}
	var nilLadder *Ladder
	nilLadder.WriteMetrics(&b) // must not panic
}
