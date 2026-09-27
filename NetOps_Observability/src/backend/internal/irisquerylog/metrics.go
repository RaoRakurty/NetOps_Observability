// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisquerylog

// metrics.go — capture is best-effort for the operator (a failed write never
// fails their question) but never silent for the platform: every outcome is
// counted here and rendered on /metrics.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics counts capture and correction outcomes. The zero value is not
// usable; use NewMetrics. All methods are nil-safe.
type Metrics struct {
	recorded    atomic.Uint64
	failed      atomic.Uint64
	corrections map[string]*atomic.Uint64 // closed: one per Kind, fixed at construction
}

// NewMetrics returns zeroed counters.
func NewMetrics() *Metrics {
	m := &Metrics{corrections: map[string]*atomic.Uint64{}}
	for _, k := range Kinds {
		m.corrections[k] = &atomic.Uint64{}
	}
	return m
}

// Captured counts one capture attempt.
func (m *Metrics) Captured(ok bool) {
	if m == nil {
		return
	}
	if ok {
		m.recorded.Add(1)
		return
	}
	m.failed.Add(1)
}

// Corrected counts one stored correction of kind k.
func (m *Metrics) Corrected(k string) {
	if m == nil {
		return
	}
	if c, ok := m.corrections[k]; ok {
		c.Add(1)
	}
}

// Recorded and Failed expose the capture counters (tests, diagnostics).
func (m *Metrics) Recorded() uint64 {
	if m == nil {
		return 0
	}
	return m.recorded.Load()
}

// Failed is the count of captures that could not be stored.
func (m *Metrics) Failed() uint64 {
	if m == nil {
		return 0
	}
	return m.failed.Load()
}

// Write renders the counters in Prometheus text format. Every series is
// written on every scrape, zeros included: a vanished series must mean a
// scrape failure, never a state change.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_iris_query_capture_total Iris questions offered to the query log, by whether the record was stored. A failed capture never fails the operator's question.\n")
	fmt.Fprintf(w, "# TYPE netops_iris_query_capture_total counter\n")
	fmt.Fprintf(w, "netops_iris_query_capture_total{result=\"recorded\"} %d\n", m.recorded.Load())
	fmt.Fprintf(w, "netops_iris_query_capture_total{result=\"failed\"} %d\n", m.failed.Load())
	fmt.Fprintf(w, "# HELP netops_iris_query_corrections_total Operator corrections (\"that's not what I meant\") stored for offline evaluation, by kind.\n")
	fmt.Fprintf(w, "# TYPE netops_iris_query_corrections_total counter\n")
	for _, k := range Kinds {
		fmt.Fprintf(w, "netops_iris_query_corrections_total{kind=%q} %d\n", k, m.corrections[k].Load())
	}
}
