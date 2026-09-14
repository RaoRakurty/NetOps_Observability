// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// metrics_ring_test.go — the ring's REFUSALS have to be visible (review 3.3-13).
//
// The admission rule added for 3.3-13 refuses a line whose marker this process
// never minted, and counts it: Ring.Rejected()'s own doc says "a non-zero value
// means something on the wire is carrying trace markers (§10: a refusal nobody
// can see is a silent failure)". Nothing outside a test read that counter, so
// the refusal WAS the silent failure the comment forbids — the one signal that
// somebody is minting trace markers at a collector port existed only in memory,
// and the operator who would act on it (and the watchdog, whose only view is
// /metrics) could not see it.
//
// Exported like every other gauge in this file: ALWAYS, including at zero, so
// "the check could not run" can never be read as "the check passed".

import (
	"strings"
	"testing"
	"time"
)

func TestMetricsExportTheRingsRefusals(t *testing.T) {
	r := NewRing()
	mine := NewMarker(time.Unix(1757000000, 0))
	r.Admit(mine)
	r.Append(mine, RingLine{Msg: "the operator's own trace"})
	// Three lines carrying markers nobody here minted.
	for i := 0; i < 3; i++ {
		r.Append(NewMarker(time.Unix(int64(1757100000+i), 0)), RingLine{Msg: "off the wire"})
	}
	if r.Rejected() != 3 {
		t.Fatalf("the ring counted %d refusals, want 3 — the fixture is wrong", r.Rejected())
	}

	out := RenderMetrics(map[Module]LevelReader{ModuleAPI: fakeLevel{level: LevelInfo}}, nil, r)
	if !strings.Contains(out, MetricRingRejected+" 3") {
		t.Errorf("the refusal count is not exported (%s):\n%s — a stranger minting trace markers "+
			"at a collector port is invisible to the operator and to the watchdog", MetricRingRejected, out)
	}
	if !strings.Contains(out, "# TYPE "+MetricRingRejected+" counter") {
		t.Errorf("%s has no TYPE line:\n%s", MetricRingRejected, out)
	}
}

// ABSENCE MUST NOT BE CONFUSABLE WITH ZERO, here for the same reason as the four
// gauges above: an api with nothing refused and an api that predates the
// admission rule must not look identical.
func TestTheRefusalCounterIsExportedAtZeroAndWithNoRing(t *testing.T) {
	for name, ring := range map[string]RejectionReader{
		"a ring that has refused nothing": NewRing(),
		"no ring at all":                  nil,
	} {
		out := RenderMetrics(map[Module]LevelReader{ModuleAPI: fakeLevel{level: LevelInfo}}, nil, ring)
		if !strings.Contains(out, MetricRingRejected+" 0") {
			t.Errorf("%s: the refusal counter is absent rather than zero:\n%s", name, out)
		}
	}
}

// The ring itself must satisfy the reader the exporter needs, or the wiring is a
// compile-time lie waiting for a refactor.
func TestRingIsARejectionReader(t *testing.T) {
	var _ RejectionReader = NewRing()
}
