// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics counts what happened to runbooks (N-F2). All counters are nil-safe (a
// store built without metrics counts nothing).
type Metrics struct {
	passed, failed, timedOut, busy atomic.Int64
	stale                          atomic.Int64

	mu  sync.Mutex
	ops map[opKey]int64
}

type opKey struct{ op, outcome string }

// harness counts one run.
func (m *Metrics) harness(res HarnessResult, err error) {
	if m == nil {
		return
	}
	switch {
	case err != nil:
		m.busy.Add(1)
	case res.TimedOut:
		m.timedOut.Add(1)
	case res.Passed:
		m.passed.Add(1)
	default:
		m.failed.Add(1)
	}
}

// staleApproval counts an approval refused because the proof no longer holds.
func (m *Metrics) staleApproval() {
	if m != nil {
		m.stale.Add(1)
	}
}

// op counts one store operation. op is a fixed verb, never request data.
func (m *Metrics) op(op string, err error) {
	if m == nil {
		return
	}
	outcome := "ok"
	if err != nil {
		outcome = "refused"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ops == nil {
		m.ops = map[opKey]int64{}
	}
	m.ops[opKey{op, outcome}]++
}

// Write renders Prometheus text.
func (m *Metrics) Write(w io.Writer) error {
	if m == nil {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP netops_iris_runbook_harness_total Case-harness runs on tenant runbooks, by outcome (N-F2).\n"+
		"# TYPE netops_iris_runbook_harness_total counter\n"+
		"netops_iris_runbook_harness_total{outcome=\"passed\"} %d\n"+
		"netops_iris_runbook_harness_total{outcome=\"failed\"} %d\n"+
		"netops_iris_runbook_harness_total{outcome=\"timeout\"} %d\n"+
		"netops_iris_runbook_harness_total{outcome=\"busy\"} %d\n"+
		"# HELP netops_iris_runbook_stale_approvals_total Approvals refused because the cases have not passed against the current platform.\n"+
		"# TYPE netops_iris_runbook_stale_approvals_total counter\n"+
		"netops_iris_runbook_stale_approvals_total %d\n"+
		"# HELP netops_iris_runbook_ops_total Tenant runbook store operations, by operation and outcome.\n"+
		"# TYPE netops_iris_runbook_ops_total counter\n",
		m.passed.Load(), m.failed.Load(), m.timedOut.Load(), m.busy.Load(), m.stale.Load())
	m.mu.Lock()
	keys := make([]opKey, 0, len(m.ops))
	for k := range m.ops {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].op != keys[j].op {
			return keys[i].op < keys[j].op
		}
		return keys[i].outcome < keys[j].outcome
	})
	for _, k := range keys {
		fmt.Fprintf(&b, "netops_iris_runbook_ops_total{op=%q,outcome=%q} %d\n", k.op, k.outcome, m.ops[k])
	}
	m.mu.Unlock()
	_, err := io.WriteString(w, b.String())
	return err
}
