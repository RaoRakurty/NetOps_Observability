// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aidecision

// metrics.go — a ledger write is best-effort for the operator (a failed append
// never costs them the answer) but never silent for the platform: every
// outcome, and every entry the per-decision bound turned away, is counted and
// rendered on /metrics.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics counts ledger writes. All methods are nil-safe.
type Metrics struct {
	decisions atomic.Uint64
	entries   atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
}

// NewMetrics returns zeroed counters.
func NewMetrics() *Metrics { return &Metrics{} }

// Appended counts one stored decision of n entries.
func (m *Metrics) Appended(n int) {
	if m == nil {
		return
	}
	m.decisions.Add(1)
	m.entries.Add(uint64(max(n, 0)))
}

// Failed counts one decision whose append failed.
func (m *Metrics) Failed() {
	if m == nil {
		return
	}
	m.failed.Add(1)
}

// Dropped counts entries the per-decision bound refused.
func (m *Metrics) Dropped(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.dropped.Add(uint64(n))
}

// Snapshot returns (decisions, entries, failed, dropped) — tests, diagnostics.
func (m *Metrics) Snapshot() (uint64, uint64, uint64, uint64) {
	if m == nil {
		return 0, 0, 0, 0
	}
	return m.decisions.Load(), m.entries.Load(), m.failed.Load(), m.dropped.Load()
}

// Write renders the counters in Prometheus text format, zeros included: a
// vanished series must mean a scrape failure, never a state change.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_ai_decision_ledger_decisions_total Iris AI decisions offered to the decision ledger, by whether the append was stored. A failed append never fails the operator's answer.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_decision_ledger_decisions_total counter\n")
	fmt.Fprintf(w, "netops_ai_decision_ledger_decisions_total{result=\"stored\"} %d\n", m.decisions.Load())
	fmt.Fprintf(w, "netops_ai_decision_ledger_decisions_total{result=\"failed\"} %d\n", m.failed.Load())
	fmt.Fprintf(w, "# HELP netops_ai_decision_ledger_entries_total Decision-ledger entries stored.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_decision_ledger_entries_total counter\n")
	fmt.Fprintf(w, "netops_ai_decision_ledger_entries_total %d\n", m.entries.Load())
	fmt.Fprintf(w, "# HELP netops_ai_decision_ledger_dropped_entries_total Decision-ledger entries refused by the per-decision bound (the decision itself is still stored).\n")
	fmt.Fprintf(w, "# TYPE netops_ai_decision_ledger_dropped_entries_total counter\n")
	fmt.Fprintf(w, "netops_ai_decision_ledger_dropped_entries_total %d\n", m.dropped.Load())
}
