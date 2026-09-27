// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package changeledger

// metrics.go — the producers' Prometheus surface (§10: every outcome counted).
// Labelled by producer and outcome only, never by tenant: the question is "is
// the ledger being fed", and an unlabelled-by-tenant series cannot leak a
// tenant roster (§3a) or grow with the fleet.

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// Outcomes — the closed `outcome` label vocabulary.
const (
	OutcomeRecorded = "recorded" // written (or already present: idempotent)
	OutcomeSkipped  = "skipped"  // not a recordable change (first capture, no target, …)
	OutcomeRetried  = "retried"  // one extra attempt after a transient failure
	OutcomeFailed   = "failed"   // not recorded after every attempt
	OutcomeDropped  = "dropped"  // the audit queue was full
)

var outcomes = []string{OutcomeRecorded, OutcomeSkipped, OutcomeRetried, OutcomeFailed, OutcomeDropped}

// Metrics counts producer outcomes.
type Metrics struct {
	mu     sync.Mutex
	counts map[[2]string]int64 // (producer, outcome) → n
}

// NewMetrics builds an empty counter set.
func NewMetrics() *Metrics { return &Metrics{counts: map[[2]string]int64{}} }

// record counts one outcome and returns the new total for it.
func (m *Metrics) record(producer, outcome string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{producer, outcome}
	m.counts[k]++
	return m.counts[k]
}

// Count reads one counter (tests and the status surface).
func (m *Metrics) Count(producer, outcome string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[[2]string{producer, outcome}]
}

// Write emits netops_change_ledger_writes_total. Both producers are always
// rendered with every outcome, so a producer that has never written is a
// visible zero rather than an absent series.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprint(w, "# HELP netops_change_ledger_writes_total Change-ledger producer outcomes (Iris N-D2), by producer and outcome.\n")
	fmt.Fprint(w, "# TYPE netops_change_ledger_writes_total counter\n")
	producers := map[string]bool{ProducerConfigCapture: true, ProducerAudit: true}
	for k := range m.counts {
		producers[k[0]] = true
	}
	names := make([]string, 0, len(producers))
	for p := range producers {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		for _, o := range outcomes {
			fmt.Fprintf(w, "netops_change_ledger_writes_total{producer=%q,outcome=%q} %d\n", p, o, m.counts[[2]string{p, o}])
		}
	}
}
