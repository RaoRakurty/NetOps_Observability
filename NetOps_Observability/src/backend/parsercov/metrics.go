// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// metrics.go — netops_parsercov_mining_runs_total{outcome} and
// netops_parsercov_lines_scanned_total.
//
// NOT TENANT-LABELLED, on purpose (the secapi/rcafeedback precedent): /metrics
// is not itself a tenant-scoped surface, so a tenant label on it would leak
// tenant existence and cardinality to anyone who can scrape it. §3a governs
// data surfaces; the same reasoning governs telemetry ABOUT those surfaces.
//
// The outcome vocabulary is CLOSED, and every series is emitted including its
// zeros — an absent series and a zero series mean different things to an alert,
// and "the miner stopped running" must look different from "the miner ran and
// found nothing".

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Mining-run outcomes. One of these is recorded for every call that reaches the
// mining path, exactly once.
const (
	// OutcomeOK — a run completed and scanned the whole window.
	OutcomeOK = "ok"
	// OutcomeCached — served from the cache; no OpenSearch scan was issued.
	OutcomeCached = "cached"
	// OutcomePartial — a run completed but hit the line cap or the group cap;
	// the answer is truthful about being incomplete (see the `note`).
	OutcomePartial = "partial"
	// OutcomeEmpty — a run completed with no unrecognized lines in the window.
	OutcomeEmpty = "empty"
	// OutcomeUnavailable — the lane publishes no admission verdict, so no
	// honest answer exists and the route answered 503.
	OutcomeUnavailable = "unavailable"
	// OutcomeError — the scan failed (upstream error).
	OutcomeError = "error"
)

// Outcomes is the closed label set, in emission order.
var Outcomes = []string{
	OutcomeOK, OutcomeCached, OutcomePartial, OutcomeEmpty,
	OutcomeUnavailable, OutcomeError,
}

// Metrics counts mining runs by outcome and the lines they scanned. Safe for
// concurrent use.
type Metrics struct {
	// One counter per entry of Outcomes, indexed identically, so Write emits a
	// stable series set including zeros.
	runs  []atomic.Int64
	lines atomic.Int64
}

// NewMetrics builds the counter set.
func NewMetrics() *Metrics { return &Metrics{runs: make([]atomic.Int64, len(Outcomes))} }

// IncRun records one mining run's outcome. An outcome outside Outcomes is
// DROPPED rather than bucketed into a wrong series — the call sites pass
// constants, so this is unreachable, and mislabelling would be worse than a gap.
func (m *Metrics) IncRun(outcome string) {
	if m == nil {
		return
	}
	for i, o := range Outcomes {
		if o == outcome {
			m.runs[i].Add(1)
			return
		}
	}
}

// AddLines records lines scanned by one run.
func (m *Metrics) AddLines(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.lines.Add(int64(n))
}

// Snapshot returns the current totals (test seam; no locking games).
func (m *Metrics) Snapshot() (map[string]int64, int64) {
	out := map[string]int64{}
	if m == nil {
		return out, 0
	}
	for i, o := range Outcomes {
		out[o] = m.runs[i].Load()
	}
	return out, m.lines.Load()
}

// Write emits both families in Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_parsercov_mining_runs_total Unrecognized-template mining runs, by outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_parsercov_mining_runs_total counter\n")
	for i, o := range Outcomes {
		fmt.Fprintf(w, "netops_parsercov_mining_runs_total{outcome=%q} %d\n", o, m.runs[i].Load())
	}
	fmt.Fprintf(w, "# HELP netops_parsercov_lines_scanned_total Log lines read by the template miner.\n")
	fmt.Fprintf(w, "# TYPE netops_parsercov_lines_scanned_total counter\n")
	fmt.Fprintf(w, "netops_parsercov_lines_scanned_total %d\n", m.lines.Load())
}
