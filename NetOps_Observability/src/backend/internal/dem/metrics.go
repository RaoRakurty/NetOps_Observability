// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// metrics.go — the module's own counter block (§10: every service emits
// metrics, no silent failures). Each counter answers a question an operator
// would actually ask: is anyone declaring targets, is the prober picking them
// up, and is the score query failing silently.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics is the module's counter set. Counters are atomic, so the package
// holds no mutable package-level state (§5 no globals).
type Metrics struct {
	TargetsCreated   atomic.Int64
	TargetsUpdated   atomic.Int64
	TargetsDeleted   atomic.Int64
	ScoresServed     atomic.Int64
	QueryErrors      atomic.Int64
	TargetsProjected atomic.Int64 // targets handed to the prober's work queue
	ProjectErrors    atomic.Int64
	// Per-RUN record intake (tracker 253). Reliability grading is only as good
	// as the runs behind it, so the intake's own health is a first-class
	// question: a store that is silently rejecting or dropping records reads,
	// on the coverage screen, exactly like a fleet that simply is not flaky.
	RunsRecorded    atomic.Int64
	RunsDuplicate   atomic.Int64 // re-read of a still-published batch; expected, not a fault
	RunsRejected    atomic.Int64 // failed validation — could not be attributed
	RunsDropped     atomic.Int64 // refused: the store is at its definition bound
	RunIntakeErrors atomic.Int64
	RunsTracked     atomic.Int64 // definitions currently holding a ring
}

// NewMetrics builds an empty counter set.
func NewMetrics() *Metrics { return &Metrics{} }

// Snapshot is a plain read of the counters for a status endpoint.
func (m *Metrics) Snapshot() map[string]int64 {
	if m == nil {
		return map[string]int64{}
	}
	return map[string]int64{
		"targets_created_total":   m.TargetsCreated.Load(),
		"targets_updated_total":   m.TargetsUpdated.Load(),
		"targets_deleted_total":   m.TargetsDeleted.Load(),
		"scores_served_total":     m.ScoresServed.Load(),
		"query_errors_total":      m.QueryErrors.Load(),
		"targets_projected_total": m.TargetsProjected.Load(),
		"project_errors_total":    m.ProjectErrors.Load(),
		"runs_recorded_total":     m.RunsRecorded.Load(),
		"runs_duplicate_total":    m.RunsDuplicate.Load(),
		"runs_rejected_total":     m.RunsRejected.Load(),
		"runs_dropped_total":      m.RunsDropped.Load(),
		"run_intake_errors_total": m.RunIntakeErrors.Load(),
		"runs_tracked":            m.RunsTracked.Load(),
	}
}

// metricHelp pairs each metric with its HELP line and its TYPE. Declared as
// data so a new counter cannot ship without one — and so a GAUGE (a level, not
// a total) cannot ship mislabelled as a counter, which would make every rate()
// over it wrong.
var metricHelp = [][3]string{
	{"targets_created_total", "Experience targets declared", "counter"},
	{"targets_updated_total", "Experience targets edited or paused", "counter"},
	{"targets_deleted_total", "Experience targets removed", "counter"},
	{"scores_served_total", "Experience score responses served", "counter"},
	{"query_errors_total", "Experience score computations abandoned because the metrics store did not answer", "counter"},
	{"targets_projected_total", "Targets published to the prober's work queue", "gauge"},
	{"project_errors_total", "Work-queue publications that failed (the prober keeps its previous list)", "counter"},
	{"runs_recorded_total", "Per-run synthetic records filed for reliability grading", "counter"},
	{"runs_duplicate_total", "Run records already held (a re-read of a still-published batch)", "counter"},
	{"runs_rejected_total", "Run records refused by validation and therefore ungraded", "counter"},
	{"runs_dropped_total", "Run records refused because the run store is at its definition bound", "counter"},
	{"run_intake_errors_total", "Drains of the prober's run channel that failed", "counter"},
	{"runs_tracked", "Checks currently holding a run ring", "gauge"},
}

// Write emits the exposition text at scrape time, in a fixed order so a scrape
// is byte-stable.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	snap := m.Snapshot()
	for _, row := range metricHelp {
		name := "netops_dem_" + row[0]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, row[1], name, row[2], name, snap[row[0]])
	}
}
