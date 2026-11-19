// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package routinerollup

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Metrics is the job's counter set, rendered on /metrics from cached state (a
// scrape never touches OpenSearch). A nil *Metrics is a no-op everywhere.
type Metrics struct {
	mu               sync.Mutex
	runsOK           int64
	runsFailed       int64
	nWritten         int64
	nTenantMismatch  int64
	deferrals        int64
	nMismatchHours   int64
	lastSuccess      time.Time
	newestRolledUpTo time.Time
}

// NewMetrics returns an empty counter set.
func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) success(at, rolledTo time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runsOK++
	m.lastSuccess, m.newestRolledUpTo = at, rolledTo
}

func (m *Metrics) failure() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runsFailed++
}

func (m *Metrics) written(n int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nWritten += int64(n)
}

func (m *Metrics) tenantMismatch(docs int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nTenantMismatch += docs
}

func (m *Metrics) deferral() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deferrals++
}

func (m *Metrics) mismatchHours(n int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nMismatchHours = int64(n)
}

// Snapshot is a copy of the counters, for tests and status pages.
type Snapshot struct {
	RunsOK, RunsFailed, Written, TenantMismatch, Deferrals, MismatchHours int64
	LastSuccess, RolledUpTo                                               time.Time
}

// Snapshot returns the current counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		RunsOK: m.runsOK, RunsFailed: m.runsFailed, Written: m.nWritten, TenantMismatch: m.nTenantMismatch,
		Deferrals: m.deferrals, MismatchHours: m.nMismatchHours, LastSuccess: m.lastSuccess, RolledUpTo: m.newestRolledUpTo,
	}
}

// Write renders the series in the Prometheus text format. The last-success
// gauge is absent until the first successful tick: "never rolled" must not
// read as "rolled at the epoch".
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	s := m.Snapshot()
	fmt.Fprintf(w, "# HELP netops_routine_rollup_runs_total Routine-syslog roll-up ticks, by result.\n")
	fmt.Fprintf(w, "# TYPE netops_routine_rollup_runs_total counter\n")
	fmt.Fprintf(w, "netops_routine_rollup_runs_total{result=\"ok\"} %d\n", s.RunsOK)
	fmt.Fprintf(w, "netops_routine_rollup_runs_total{result=\"error\"} %d\n", s.RunsFailed)
	fmt.Fprintf(w, "# HELP netops_routine_rollup_documents_written_total Roll-up documents upserted.\n")
	fmt.Fprintf(w, "# TYPE netops_routine_rollup_documents_written_total counter\n")
	fmt.Fprintf(w, "netops_routine_rollup_documents_written_total %d\n", s.Written)
	fmt.Fprintf(w, "# HELP netops_routine_rollup_tenant_mismatch_records_total Routine originals skipped because their tenant_id disagrees with their index.\n")
	fmt.Fprintf(w, "# TYPE netops_routine_rollup_tenant_mismatch_records_total counter\n")
	fmt.Fprintf(w, "netops_routine_rollup_tenant_mismatch_records_total %d\n", s.TenantMismatch)
	fmt.Fprintf(w, "# HELP netops_routine_rollup_deferrals_total Ticks that spent their page budget and left the rest for the next tick.\n")
	fmt.Fprintf(w, "# TYPE netops_routine_rollup_deferrals_total counter\n")
	fmt.Fprintf(w, "netops_routine_rollup_deferrals_total %d\n", s.Deferrals)
	fmt.Fprintf(w, "# HELP netops_routine_rollup_mismatch_hours Closed hours whose roll-up sum differed from the originals at the last reconcile.\n")
	fmt.Fprintf(w, "# TYPE netops_routine_rollup_mismatch_hours gauge\n")
	fmt.Fprintf(w, "netops_routine_rollup_mismatch_hours %d\n", s.MismatchHours)
	if !s.LastSuccess.IsZero() {
		fmt.Fprintf(w, "# HELP netops_routine_rollup_last_success_timestamp_seconds When the roll-up last completed a tick.\n")
		fmt.Fprintf(w, "# TYPE netops_routine_rollup_last_success_timestamp_seconds gauge\n")
		fmt.Fprintf(w, "netops_routine_rollup_last_success_timestamp_seconds %d\n", s.LastSuccess.Unix())
	}
}
