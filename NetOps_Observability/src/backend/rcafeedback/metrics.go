// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rcafeedback

// metrics.go — the Prometheus counter for operator verdicts
// (netops_rca_feedback_total{verdict}). The counter is process-wide and NOT
// tenant-labelled on purpose: a per-tenant label on a metrics endpoint that is
// not itself tenant-scoped would leak tenant existence and cardinality to
// anyone who can scrape /metrics (§3a is about data surfaces; this is the same
// principle applied to telemetry).

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics counts verdicts by value. Safe for concurrent use.
type Metrics struct {
	// One counter per entry of VerdictOrder, indexed identically, so Write
	// emits a stable series set (including zeros — an absent series and a zero
	// series mean different things to an alert).
	counts [3]atomic.Int64
}

// NewMetrics builds the counter set.
func NewMetrics() *Metrics { return &Metrics{} }

// Inc records one accepted verdict. An unknown verdict is dropped rather than
// bucketed into a wrong series — the write path validates first, so this is
// unreachable in practice and silently mislabelling would be worse than a gap.
func (m *Metrics) Inc(verdict string) {
	if m == nil {
		return
	}
	for i, v := range VerdictOrder {
		if v == verdict {
			m.counts[i].Add(1)
			return
		}
	}
}

// Snapshot returns the current per-verdict totals (test seam; no locking games).
func (m *Metrics) Snapshot() map[string]int64 {
	out := map[string]int64{}
	if m == nil {
		return out
	}
	for i, v := range VerdictOrder {
		out[v] = m.counts[i].Load()
	}
	return out
}

// Write emits the counter family in Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_rca_feedback_total Operator verdicts recorded on RCA cases, by verdict.\n")
	fmt.Fprintf(w, "# TYPE netops_rca_feedback_total counter\n")
	for i, v := range VerdictOrder {
		fmt.Fprintf(w, "netops_rca_feedback_total{verdict=%q} %d\n", v, m.counts[i].Load())
	}
}
