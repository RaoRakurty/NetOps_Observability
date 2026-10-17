// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package orgcontext

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics counts how Network context reached (or failed to reach) prompts.
type Metrics struct {
	rendered, empty, failed, skipped atomic.Int64
}

// Rendered counts a prompt that carried a context block. All counters are
// nil-safe (a server built without metrics counts nothing).
func (m *Metrics) Rendered() {
	if m != nil {
		m.rendered.Add(1)
	}
}

// Empty counts a prompt for a workspace with no active facts.
func (m *Metrics) Empty() {
	if m != nil {
		m.empty.Add(1)
	}
}

// Failed counts a store read that failed (the answer runs without context).
func (m *Metrics) Failed() {
	if m != nil {
		m.failed.Add(1)
	}
}

// Skipped counts a stored active fact that no longer passed validation.
func (m *Metrics) Skipped() {
	if m != nil {
		m.skipped.Add(1)
	}
}

// Write renders Prometheus text.
func (m *Metrics) Write(w io.Writer) error {
	if m == nil {
		return nil
	}
	_, err := fmt.Fprintf(w, "# HELP netops_iris_org_context_render_total Network context reads for an Iris prompt, by outcome (N-F1).\n"+
		"# TYPE netops_iris_org_context_render_total counter\n"+
		"netops_iris_org_context_render_total{outcome=\"rendered\"} %d\n"+
		"netops_iris_org_context_render_total{outcome=\"empty\"} %d\n"+
		"netops_iris_org_context_render_total{outcome=\"error\"} %d\n"+
		"# HELP netops_iris_org_context_skipped_facts_total Stored facts skipped at render because they no longer pass validation.\n"+
		"# TYPE netops_iris_org_context_skipped_facts_total counter\n"+
		"netops_iris_org_context_skipped_facts_total %d\n",
		m.rendered.Load(), m.empty.Load(), m.failed.Load(), m.skipped.Load())
	return err
}
