// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics counts how device facts were resolved for Iris (N-F6). All
// counters are nil-safe (a server built without metrics counts nothing).
type Metrics struct {
	agreed, disagreed, single, policyErr atomic.Int64
}

// Observe counts one resolved fact: one source, several that agreed, or
// several that disagreed.
func (m *Metrics) Observe(r Resolution) {
	if m == nil {
		return
	}
	switch {
	case r.Disagreed():
		m.disagreed.Add(1)
	case len(r.Considered) <= 1:
		m.single.Add(1)
	default:
		m.agreed.Add(1)
	}
}

// PolicyError counts a policy read that failed or held an invalid order (the
// answer used the platform default and said so).
func (m *Metrics) PolicyError() {
	if m != nil {
		m.policyErr.Add(1)
	}
}

// Write renders Prometheus text.
func (m *Metrics) Write(w io.Writer) error {
	if m == nil {
		return nil
	}
	_, err := fmt.Fprintf(w, "# HELP netops_iris_source_authority_total Device facts Iris resolved across sources, by outcome; policy_error = the workspace's source order could not be read and the platform default was used (N-F6).\n"+
		"# TYPE netops_iris_source_authority_total counter\n"+
		"netops_iris_source_authority_total{outcome=\"agreed\"} %d\n"+
		"netops_iris_source_authority_total{outcome=\"disagreed\"} %d\n"+
		"netops_iris_source_authority_total{outcome=\"single_source\"} %d\n"+
		"netops_iris_source_authority_total{outcome=\"policy_error\"} %d\n",
		m.agreed.Load(), m.disagreed.Load(), m.single.Load(), m.policyErr.Load())
	return err
}
